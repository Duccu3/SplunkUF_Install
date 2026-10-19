
# Script to install Splunk Universal Forwarder and configure logging on Windows

$ErrorActionPreference = "Stop"

# Set variables
$SplunkInstallPath = "C:\Program Files\SplunkUniversalForwarder"
$SplunkDeploymentServer = "192.168.1.135:8089"
$SplunkDeploymentServerIP = "192.168.1.135"
$SysmonConfigPath = "C:\install_agent_windows\sysmonconfig.xml"
$StopExistingWinCollectServices = ([Environment]::GetEnvironmentVariable("SPLUNK_UF_STOP_WINCOLLECT", "Process") -eq "1")
$TempDirectory = "C:\install_agent_windows"
$TempDirectory1 = "C:\install_agent_windows.zip"
$PSLogDirectory = "C:\PSLogs"
$SplunkBackupRoot = "C:\SplunkUF_Backup"
$MsiLogPath = Join-Path $TempDirectory "splunkinstall.log"
$ExpectedSplunkServiceAccount = "NT SERVICE\SplunkForwarder"
$AllowedSplunkSignerThumbprints = @("FCE56795CF0E22F596A47C20EC3D1AF624EBD361")

# Installation, UF backup, MSI maintenance, Sysmon and audit-policy changes must
# run in an elevated process. Least privilege applies to the SplunkForwarder service.
$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal($CurrentIdentity)
if (-not $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must run as Administrator or LocalSystem. SplunkForwarder itself will run as '$ExpectedSplunkServiceAccount'."
}

# Use the Windows LSA API so privilege checks and changes are independent of OS language.
if (-not ("VNCS.LsaUserRights" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace VNCS
{
    public static class LsaUserRights
    {
        private const uint POLICY_CREATE_ACCOUNT = 0x00000010;
        private const uint POLICY_LOOKUP_NAMES = 0x00000800;

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_OBJECT_ATTRIBUTES
        {
            public uint Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint LsaOpenPolicy(
            IntPtr SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            uint DesiredAccess,
            out IntPtr PolicyHandle);

        [DllImport("advapi32.dll")]
        private static extern uint LsaEnumerateAccountRights(
            IntPtr PolicyHandle,
            IntPtr AccountSid,
            out IntPtr UserRights,
            out uint CountOfRights);

        [DllImport("advapi32.dll")]
        private static extern uint LsaAddAccountRights(
            IntPtr PolicyHandle,
            IntPtr AccountSid,
            LSA_UNICODE_STRING[] UserRights,
            uint CountOfRights);

        [DllImport("advapi32.dll")]
        private static extern uint LsaRemoveAccountRights(
            IntPtr PolicyHandle,
            IntPtr AccountSid,
            [MarshalAs(UnmanagedType.Bool)] bool AllRights,
            LSA_UNICODE_STRING[] UserRights,
            uint CountOfRights);

        [DllImport("advapi32.dll")]
        private static extern uint LsaNtStatusToWinError(uint Status);

        [DllImport("advapi32.dll")]
        private static extern uint LsaFreeMemory(IntPtr Buffer);

        [DllImport("advapi32.dll")]
        private static extern uint LsaClose(IntPtr PolicyHandle);

        private static IntPtr OpenPolicy()
        {
            LSA_OBJECT_ATTRIBUTES attributes = new LSA_OBJECT_ATTRIBUTES();
            attributes.Length = (uint)Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));

            IntPtr policyHandle;
            uint status = LsaOpenPolicy(
                IntPtr.Zero,
                ref attributes,
                POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES,
                out policyHandle);
            ThrowOnError(status, "LsaOpenPolicy");
            return policyHandle;
        }

        private static IntPtr AllocateSid(string sidValue)
        {
            SecurityIdentifier sid = new SecurityIdentifier(sidValue);
            byte[] sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);

            IntPtr sidPointer = Marshal.AllocHGlobal(sidBytes.Length);
            Marshal.Copy(sidBytes, 0, sidPointer, sidBytes.Length);
            return sidPointer;
        }

        private static LSA_UNICODE_STRING CreateLsaString(string value)
        {
            LSA_UNICODE_STRING result = new LSA_UNICODE_STRING();
            result.Buffer = Marshal.StringToHGlobalUni(value);
            result.Length = checked((ushort)(value.Length * 2));
            result.MaximumLength = checked((ushort)(result.Length + 2));
            return result;
        }

        private static void ThrowOnError(uint status, string operation)
        {
            if (status == 0)
            {
                return;
            }

            uint error = LsaNtStatusToWinError(status);
            throw new Win32Exception((int)error, operation + " failed");
        }

        public static string[] GetRights(string sidValue)
        {
            IntPtr policyHandle = IntPtr.Zero;
            IntPtr sidPointer = IntPtr.Zero;
            IntPtr rightsBuffer = IntPtr.Zero;
            try
            {
                policyHandle = OpenPolicy();
                sidPointer = AllocateSid(sidValue);

                uint count;
                uint status = LsaEnumerateAccountRights(
                    policyHandle,
                    sidPointer,
                    out rightsBuffer,
                    out count);

                if (status != 0)
                {
                    uint error = LsaNtStatusToWinError(status);
                    if (error == 2)
                    {
                        return new string[0];
                    }
                    throw new Win32Exception((int)error, "LsaEnumerateAccountRights failed");
                }

                List<string> rights = new List<string>();
                int itemSize = Marshal.SizeOf(typeof(LSA_UNICODE_STRING));
                for (int index = 0; index < count; index++)
                {
                    IntPtr itemPointer = new IntPtr(rightsBuffer.ToInt64() + (index * itemSize));
                    LSA_UNICODE_STRING item = (LSA_UNICODE_STRING)Marshal.PtrToStructure(
                        itemPointer,
                        typeof(LSA_UNICODE_STRING));
                    rights.Add(Marshal.PtrToStringUni(item.Buffer, item.Length / 2));
                }
                return rights.ToArray();
            }
            finally
            {
                if (rightsBuffer != IntPtr.Zero) LsaFreeMemory(rightsBuffer);
                if (sidPointer != IntPtr.Zero) Marshal.FreeHGlobal(sidPointer);
                if (policyHandle != IntPtr.Zero) LsaClose(policyHandle);
            }
        }

        public static void AddRight(string sidValue, string right)
        {
            ChangeRight(sidValue, right, true);
        }

        public static void RemoveRight(string sidValue, string right)
        {
            ChangeRight(sidValue, right, false);
        }

        private static void ChangeRight(string sidValue, string right, bool add)
        {
            IntPtr policyHandle = IntPtr.Zero;
            IntPtr sidPointer = IntPtr.Zero;
            LSA_UNICODE_STRING lsaRight = new LSA_UNICODE_STRING();
            try
            {
                policyHandle = OpenPolicy();
                sidPointer = AllocateSid(sidValue);
                lsaRight = CreateLsaString(right);
                LSA_UNICODE_STRING[] rights = new LSA_UNICODE_STRING[] { lsaRight };

                uint status = add
                    ? LsaAddAccountRights(policyHandle, sidPointer, rights, 1)
                    : LsaRemoveAccountRights(policyHandle, sidPointer, false, rights, 1);
                ThrowOnError(status, add ? "LsaAddAccountRights" : "LsaRemoveAccountRights");
            }
            finally
            {
                if (lsaRight.Buffer != IntPtr.Zero) Marshal.FreeHGlobal(lsaRight.Buffer);
                if (sidPointer != IntPtr.Zero) Marshal.FreeHGlobal(sidPointer);
                if (policyHandle != IntPtr.Zero) LsaClose(policyHandle);
            }
        }
    }
}
'@
}

function Invoke-CheckedNativeCommand {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [string[]]$ArgumentList = @(),

        [int[]]$SuccessExitCodes = @(0),

        [Parameter(Mandatory = $true)]
        [string]$Operation,

        [switch]$PassThru
    )

    $commandOutput = & $FilePath @ArgumentList 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -notin $SuccessExitCodes) {
        throw "$Operation failed with exit code $exitCode. Output: $($commandOutput -join ' ')"
    }

    if ($PassThru) {
        return $commandOutput
    }
}

function Test-TcpPort {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [int]$Port,

        [int]$TimeoutMilliseconds = 5000
    )

    $client = New-Object System.Net.Sockets.TcpClient
    $asyncResult = $null
    try {
        $asyncResult = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)) {
            return $false
        }
        $client.EndConnect($asyncResult)
        return $client.Connected
    }
    catch {
        return $false
    }
    finally {
        if (($null -ne $asyncResult) -and ($null -ne $asyncResult.AsyncWaitHandle)) {
            $asyncResult.AsyncWaitHandle.Close()
        }
        $client.Close()
    }
}

# auditpol category/subcategory names are localized. Use Microsoft's stable GUIDs
# so the same policy works on English, Vietnamese and other Windows languages.
$AuditSubcategoryGuids = @{
    "Security State Change"                   = "{0CCE9210-69AE-11D9-BED3-505054503030}"
    "Security System Extension"               = "{0CCE9211-69AE-11D9-BED3-505054503030}"
    "System Integrity"                        = "{0CCE9212-69AE-11D9-BED3-505054503030}"
    "IPsec Driver"                            = "{0CCE9213-69AE-11D9-BED3-505054503030}"
    "Other System Events"                     = "{0CCE9214-69AE-11D9-BED3-505054503030}"
    "Logon"                                   = "{0CCE9215-69AE-11D9-BED3-505054503030}"
    "Logoff"                                  = "{0CCE9216-69AE-11D9-BED3-505054503030}"
    "Account Lockout"                         = "{0CCE9217-69AE-11D9-BED3-505054503030}"
    "IPsec Main Mode"                         = "{0CCE9218-69AE-11D9-BED3-505054503030}"
    "IPsec Quick Mode"                        = "{0CCE9219-69AE-11D9-BED3-505054503030}"
    "IPsec Extended Mode"                     = "{0CCE921A-69AE-11D9-BED3-505054503030}"
    "Special Logon"                           = "{0CCE921B-69AE-11D9-BED3-505054503030}"
    "Other Logon/Logoff Events"               = "{0CCE921C-69AE-11D9-BED3-505054503030}"
    "File System"                             = "{0CCE921D-69AE-11D9-BED3-505054503030}"
    "Registry"                                = "{0CCE921E-69AE-11D9-BED3-505054503030}"
    "Kernel Object"                           = "{0CCE921F-69AE-11D9-BED3-505054503030}"
    "SAM"                                     = "{0CCE9220-69AE-11D9-BED3-505054503030}"
    "Certification Services"                  = "{0CCE9221-69AE-11D9-BED3-505054503030}"
    "Application Generated"                   = "{0CCE9222-69AE-11D9-BED3-505054503030}"
    "Handle Manipulation"                     = "{0CCE9223-69AE-11D9-BED3-505054503030}"
    "File Share"                              = "{0CCE9224-69AE-11D9-BED3-505054503030}"
    "Filtering Platform Packet Drop"          = "{0CCE9225-69AE-11D9-BED3-505054503030}"
    "Filtering Platform Connection"           = "{0CCE9226-69AE-11D9-BED3-505054503030}"
    "Other Object Access Events"              = "{0CCE9227-69AE-11D9-BED3-505054503030}"
    "Sensitive Privilege Use"                 = "{0CCE9228-69AE-11D9-BED3-505054503030}"
    "Non Sensitive Privilege Use"             = "{0CCE9229-69AE-11D9-BED3-505054503030}"
    "Other Privilege Use Events"              = "{0CCE922A-69AE-11D9-BED3-505054503030}"
    "Process Creation"                        = "{0CCE922B-69AE-11D9-BED3-505054503030}"
    "Process Termination"                     = "{0CCE922C-69AE-11D9-BED3-505054503030}"
    "DPAPI Activity"                          = "{0CCE922D-69AE-11D9-BED3-505054503030}"
    "RPC Events"                              = "{0CCE922E-69AE-11D9-BED3-505054503030}"
    "Audit Policy Change"                     = "{0CCE922F-69AE-11D9-BED3-505054503030}"
    "Authentication Policy Change"            = "{0CCE9230-69AE-11D9-BED3-505054503030}"
    "Authorization Policy Change"             = "{0CCE9231-69AE-11D9-BED3-505054503030}"
    "MPSSVC Rule-Level Policy Change"         = "{0CCE9232-69AE-11D9-BED3-505054503030}"
    "Filtering Platform Policy Change"        = "{0CCE9233-69AE-11D9-BED3-505054503030}"
    "Other Policy Change Events"              = "{0CCE9234-69AE-11D9-BED3-505054503030}"
    "User Account Management"                 = "{0CCE9235-69AE-11D9-BED3-505054503030}"
    "Computer Account Management"             = "{0CCE9236-69AE-11D9-BED3-505054503030}"
    "Security Group Management"               = "{0CCE9237-69AE-11D9-BED3-505054503030}"
    "Distribution Group Management"           = "{0CCE9238-69AE-11D9-BED3-505054503030}"
    "Application Group Management"            = "{0CCE9239-69AE-11D9-BED3-505054503030}"
    "Other Account Management Events"         = "{0CCE923A-69AE-11D9-BED3-505054503030}"
    "Directory Service Access"                = "{0CCE923B-69AE-11D9-BED3-505054503030}"
    "Directory Service Changes"               = "{0CCE923C-69AE-11D9-BED3-505054503030}"
    "Directory Service Replication"           = "{0CCE923D-69AE-11D9-BED3-505054503030}"
    "Detailed Directory Service Replication"  = "{0CCE923E-69AE-11D9-BED3-505054503030}"
    "Credential Validation"                   = "{0CCE923F-69AE-11D9-BED3-505054503030}"
    "Kerberos Service Ticket Operations"      = "{0CCE9240-69AE-11D9-BED3-505054503030}"
    "Other Account Logon Events"              = "{0CCE9241-69AE-11D9-BED3-505054503030}"
    "Kerberos Authentication Service"         = "{0CCE9242-69AE-11D9-BED3-505054503030}"
    "Network Policy Server"                   = "{0CCE9243-69AE-11D9-BED3-505054503030}"
    "Detailed File Share"                     = "{0CCE9244-69AE-11D9-BED3-505054503030}"
    "Removable Storage"                       = "{0CCE9245-69AE-11D9-BED3-505054503030}"
}

function Set-WindowsAuditSubcategory {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Subcategory,

        [Parameter(Mandatory = $true)]
        [ValidateSet("enable", "disable")]
        [string]$Success,

        [Parameter(Mandatory = $true)]
        [ValidateSet("enable", "disable")]
        [string]$Failure
    )

    $subcategoryGuid = $AuditSubcategoryGuids[$Subcategory]
    if ([string]::IsNullOrWhiteSpace($subcategoryGuid)) {
        throw "No language-independent audit GUID is defined for subcategory '$Subcategory'."
    }

    Invoke-CheckedNativeCommand `
        -FilePath "auditpol.exe" `
        -ArgumentList @(
            "/set",
            "/subcategory:$subcategoryGuid",
            "/success:$Success",
            "/failure:$Failure"
        ) `
        -Operation "Configure audit subcategory '$Subcategory'"
}

function Set-EventLogMaximumSize {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Channel,

        [Parameter(Mandatory = $true)]
        [long]$MaximumSize
    )

    Invoke-CheckedNativeCommand `
        -FilePath "wevtutil.exe" `
        -ArgumentList @("sl", $Channel, "/ms:$MaximumSize") `
        -Operation "Set maximum size for event channel '$Channel'"
}

function Set-RegistryValue {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet("REG_DWORD", "REG_SZ")]
        [string]$Type,

        [Parameter(Mandatory = $true)]
        [object]$Data
    )

    Invoke-CheckedNativeCommand `
        -FilePath "reg.exe" `
        -ArgumentList @("add", $Path, "/v", $Name, "/t", $Type, "/d", [string]$Data, "/f") `
        -Operation "Set registry value '$Path\$Name'"
}

function Protect-InstallerWorkingDirectory {
    if (-not (Test-Path -LiteralPath $TempDirectory -PathType Container)) {
        throw "Installer working directory was not found: '$TempDirectory'."
    }

    # MSI properties can include credentials and verbose installation logs. Keep
    # the staging directory accessible only to LocalSystem and Administrators.
    Invoke-CheckedNativeCommand `
        -FilePath "icacls.exe" `
        -ArgumentList @(
            $TempDirectory,
            "/grant:r",
            "*S-1-5-18:(OI)(CI)(F)",
            "*S-1-5-32-544:(OI)(CI)(F)"
        ) `
        -Operation "Protect installer working directory"

    Invoke-CheckedNativeCommand `
        -FilePath "icacls.exe" `
        -ArgumentList @($TempDirectory, "/inheritance:r") `
        -Operation "Remove inherited installer-directory permissions"
}

# Do not interrupt another telemetry pipeline unless migration tooling opts in.
$services = Get-Service *WinCollect* -ErrorAction SilentlyContinue

if ($services) {
    if ($StopExistingWinCollectServices) {
        Write-Warning "SPLUNK_UF_STOP_WINCOLLECT=1: stopping existing WinCollect services to prevent duplicate collection."
        $services | Where-Object Status -eq "Running" | Stop-Service -Force
    } else {
        Write-Warning "WinCollect service(s) detected and left unchanged. Set SPLUNK_UF_STOP_WINCOLLECT=1 only during an approved collector migration."
    }
}

Get-Service *WinCollect* -ErrorAction SilentlyContinue |
    Select-Object Status, Name, DisplayName


# Splunk UF least-privilege configuration (Splunk UF 9.1+)
# The installer script itself still requires Administrator/SYSTEM because it installs software,
# Sysmon and changes Windows audit policy. Only the SplunkForwarder SERVICE is de-privileged.
$ComputerSystem = Get-WmiObject Win32_ComputerSystem
$IsDomainController = ($ComputerSystem.DomainRole -eq 4 -or $ComputerSystem.DomainRole -eq 5)

if ($IsDomainController) {
    Write-Output "Domain Controller detected. UF will still use the least-privileged virtual account."
    Write-Output "SeSecurityPrivilege will be granted on the DC so WinEventLog can collect the Security log."
    Write-Output "Event Log Readers is not used on the DC because local groups are not available by Windows design."
} else {
    Write-Output "Member server/workstation detected. UF will use a virtual account and Event Log Readers for read-only Security Event Log access."
}
if ($ComputerSystem.PartOfDomain) {
    Write-Warning "This computer is domain-joined. Domain/OU Advanced Audit Policy GPO can overwrite local auditpol settings at the next policy refresh; deploy the same audit baseline through the authoritative GPO."
}

function Get-SplunkForwarderServiceAccount {
    $service = Get-WmiObject Win32_Service -Filter "Name='SplunkForwarder'" -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return ""
    }
    return $service.StartName
}

function Get-SplunkForwarderServiceSid {
    $serviceAccount = Get-SplunkForwarderServiceAccount
    if ([string]::IsNullOrWhiteSpace($serviceAccount)) {
        throw "Unable to determine the SplunkForwarder service account."
    }
    if ($serviceAccount -ine $ExpectedSplunkServiceAccount) {
        throw "Unexpected SplunkForwarder service account '$serviceAccount'. Expected '$ExpectedSplunkServiceAccount'."
    }

    try {
        $ntAccount = New-Object System.Security.Principal.NTAccount($serviceAccount)
        return $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        throw "Unable to resolve the SID for '$serviceAccount'. Error: $($_.Exception.Message)"
    }
}

function Set-SplunkForwarderUserRight {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ServiceSid,

        [Parameter(Mandatory = $true)]
        [string]$Right,

        [Parameter(Mandatory = $true)]
        [bool]$Enabled
    )

    $currentRights = @([VNCS.LsaUserRights]::GetRights($ServiceSid))
    $hasRight = ($currentRights -contains $Right)
    if ($Enabled -and -not $hasRight) {
        Write-Output "Granting $Right to '$ExpectedSplunkServiceAccount'..."
        [VNCS.LsaUserRights]::AddRight($ServiceSid, $Right)
    }
    elseif (-not $Enabled -and $hasRight) {
        Write-Output "Removing $Right from '$ExpectedSplunkServiceAccount'..."
        [VNCS.LsaUserRights]::RemoveRight($ServiceSid, $Right)
    }

    $verifiedRights = @([VNCS.LsaUserRights]::GetRights($ServiceSid))
    $verifiedHasRight = ($verifiedRights -contains $Right)
    if ($verifiedHasRight -ne $Enabled) {
        throw "User-right validation failed for '$Right'. Expected enabled=$Enabled; actual enabled=$verifiedHasRight."
    }
}

function Enforce-SplunkForwarderUserRights {
    $serviceSid = Get-SplunkForwarderServiceSid

    # Source-specific ACLs are used instead of unrestricted filesystem read access.
    Set-SplunkForwarderUserRight -ServiceSid $serviceSid -Right "SeBackupPrivilege" -Enabled $false

    # Security Event Log access is read-only through Event Log Readers on member systems.
    # A DC has no local Event Log Readers group, so Splunk documents SeSecurityPrivilege
    # as the available option despite its Windows READ/WRITE semantics.
    Set-SplunkForwarderUserRight -ServiceSid $serviceSid -Right "SeSecurityPrivilege" -Enabled $IsDomainController

    # Retain Splunk's documented group-based collection capability.
    Set-SplunkForwarderUserRight -ServiceSid $serviceSid -Right "SeImpersonatePrivilege" -Enabled $true

    $rights = @([VNCS.LsaUserRights]::GetRights($serviceSid))
    Write-Output "Validated SplunkForwarder user rights: $($rights -join ', ')"
}

function Get-InstalledSfVersion {
    $splunkExe = Join-Path $SplunkInstallPath "bin\splunk.exe"
    if (Test-Path $splunkExe) {
        return (Get-Item $splunkExe).VersionInfo.ProductVersion
    }
    return ""
}

function ConvertTo-SfBaseVersion {
    param (
        [Parameter(Mandatory = $true)]
        [string]$VersionText
    )

    # Accept ProductVersion values such as:
    # 10.2.5, 10.2.5.0, 10.2.5 (build abc123), and 10.2.5-build-abc123.
    # Compare the supported Splunk major.minor.patch components only.
    $versionMatch = [regex]::Match(
        $VersionText,
        '^\s*(?<Version>\d+\.\d+\.\d+)(?:\.\d+)?'
    )
    if (-not $versionMatch.Success) {
        throw "Unable to parse Splunk Universal Forwarder version '$VersionText'."
    }

    return [version]$versionMatch.Groups["Version"].Value
}

function Get-SplunkInstallerSelection {
    param (
        [Parameter(Mandatory = $true)]
        [object]$OperatingSystem,

        [Parameter(Mandatory = $true)]
        [int]$ProcessorArchitecture,

        [Parameter(Mandatory = $true)]
        [string]$PackageDirectory
    )

    # All UF MSI files delivered with this script have an x64 template. Win32_Processor
    # Architecture 9 is x64; reject x86/ARM64 instead of attempting an incompatible MSI.
    if ($ProcessorArchitecture -ne 9) {
        throw "Unsupported processor architecture code '$ProcessorArchitecture'. The bundled Splunk UF installers are x64 only."
    }

    $osVersion = [version]$OperatingSystem.Version
    $buildNumber = [int]$OperatingSystem.BuildNumber
    $productType = [int]$OperatingSystem.ProductType
    $osName = $null
    $targetVersion = $null
    $installerFileName = $null

    if ($productType -eq 1) {
        # Workstation: Windows 10 and Windows 11 both report NT version 10.0;
        # Windows 11 starts at build 22000.
        if (($osVersion.Major -eq 10) -and ($osVersion.Minor -eq 0) -and ($buildNumber -ge 10240)) {
            $osName = if ($buildNumber -ge 22000) { "Windows 11" } else { "Windows 10" }
            $targetVersion = "10.2.5"
            $installerFileName = "splunkforwarder_10.2.5.msi"
        }
    }
    elseif ($productType -in @(2, 3)) {
        # Server/DC: identify the LTSC release by its NT version/build rather than a
        # localized Caption. ProductType 2 is a DC and ProductType 3 is a member server.
        if (($osVersion.Major -eq 6) -and ($osVersion.Minor -eq 2) -and ($buildNumber -eq 9200)) {
            $osName = "Windows Server 2012"
            $targetVersion = "9.1.10"
            $installerFileName = "splunkforwarder_9.1.10.msi"
        }
        elseif (($osVersion.Major -eq 6) -and ($osVersion.Minor -eq 3) -and ($buildNumber -eq 9600)) {
            $osName = "Windows Server 2012 R2"
            $targetVersion = "9.1.10"
            $installerFileName = "splunkforwarder_9.1.10.msi"
        }
        elseif (($osVersion.Major -eq 10) -and ($osVersion.Minor -eq 0)) {
            switch ($buildNumber) {
                14393 {
                    $osName = "Windows Server 2016"
                    $targetVersion = "9.2.8"
                    $installerFileName = "splunkforwarder_9.2.8.msi"
                }
                17763 { $osName = "Windows Server 2019" }
                20348 { $osName = "Windows Server 2022" }
                26100 { $osName = "Windows Server 2025" }
            }

            if (($null -ne $osName) -and ($null -eq $targetVersion)) {
                $targetVersion = "10.2.5"
                $installerFileName = "splunkforwarder_10.2.5.msi"
            }
        }
    }

    if ($null -eq $targetVersion) {
        throw "Unsupported Windows release. Caption='$($OperatingSystem.Caption)', Version='$($OperatingSystem.Version)', Build='$buildNumber', ProductType='$productType'."
    }

    # In the 9.2 matrix, Server 2016 x64 remains marked X in the Universal
    # Forwarder column. The 9.2.9+ note names Splunk Enterprise, while the 9.2
    # removal table removes Server 2012/R2 (not Server 2016) from UF support.
    return [pscustomobject]@{
        OperatingSystem = $osName
        ExpectedVersion = $targetVersion
        InstallerPath   = Join-Path $PackageDirectory $installerFileName
    }
}

function Get-MsiPackageMetadata {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Installer not found at '$Path'."
    }

    $installer = $null
    $database = $null
    $view = $null
    $record = $null
    $summary = $null

    try {
        $resolvedPath = (Resolve-Path -LiteralPath $Path).Path
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = $installer.GetType().InvokeMember(
            "OpenDatabase", "InvokeMethod", $null, $installer, @($resolvedPath, 0)
        )

        $query = "SELECT ``Property``, ``Value`` FROM ``Property`` WHERE ``Property``='ProductVersion' OR ``Property``='ProductName'"
        $view = $database.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $database, @($query))
        $view.GetType().InvokeMember("Execute", "InvokeMethod", $null, $view, $null) | Out-Null
        $productProperties = @{}
        while ($null -ne ($record = $view.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $view, $null))) {
            $propertyName = $record.GetType().InvokeMember("StringData", "GetProperty", $null, $record, @(1))
            $propertyValue = $record.GetType().InvokeMember("StringData", "GetProperty", $null, $record, @(2))
            $productProperties[[string]$propertyName] = [string]$propertyValue
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)
            $record = $null
        }

        if ([string]::IsNullOrWhiteSpace($productProperties["ProductVersion"])) {
            throw "MSI '$Path' does not contain a ProductVersion property."
        }
        if ([string]::IsNullOrWhiteSpace($productProperties["ProductName"])) {
            throw "MSI '$Path' does not contain a ProductName property."
        }

        $summary = $database.GetType().InvokeMember("SummaryInformation", "GetProperty", $null, $database, @(0))
        $template = $summary.GetType().InvokeMember("Property", "GetProperty", $null, $summary, @(7))

        return [pscustomobject]@{
            ProductName    = [string]$productProperties["ProductName"]
            ProductVersion = [string]$productProperties["ProductVersion"]
            Template       = [string]$template
        }
    }
    finally {
        if ($null -ne $view) {
            $view.GetType().InvokeMember("Close", "InvokeMethod", $null, $view, $null) | Out-Null
        }
        foreach ($comObject in @($record, $summary, $view, $database, $installer)) {
            if (($null -ne $comObject) -and [Runtime.InteropServices.Marshal]::IsComObject($comObject)) {
                [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($comObject)
            }
        }
    }
}

function Assert-SplunkInstallerPackage {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedVersion
    )

    $metadata = Get-MsiPackageMetadata -Path $Path
    if ($metadata.ProductName -ne "UniversalForwarder") {
        throw "Wrong MSI product selected. Expected 'UniversalForwarder', but '$Path' contains ProductName '$($metadata.ProductName)'."
    }
    $packageVersion = ConvertTo-SfBaseVersion -VersionText $metadata.ProductVersion
    $targetVersion = ConvertTo-SfBaseVersion -VersionText $ExpectedVersion

    if ($packageVersion -ne $targetVersion) {
        throw "Wrong UF package selected. Expected '$targetVersion', but MSI '$Path' contains '$($metadata.ProductVersion)'."
    }
    if ($metadata.Template -notmatch '^x64(?:;|$)') {
        throw "Unsupported MSI architecture '$($metadata.Template)' in '$Path'. Expected an x64 package."
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if (($null -eq $signature.SignerCertificate) -or
        ($signature.Status -in @("NotSigned", "HashMismatch"))) {
        throw "UF MSI signature validation failed for '$Path'. Status: $($signature.Status); $($signature.StatusMessage)"
    }
    if ($signature.SignerCertificate.Thumbprint -notin $AllowedSplunkSignerThumbprints) {
        throw "UF MSI '$Path' is not signed by an approved Splunk signing certificate. Signer: '$($signature.SignerCertificate.Subject)'; thumbprint: '$($signature.SignerCertificate.Thumbprint)'."
    }
    if ($signature.Status -ne "Valid") {
        # Older/offline Windows hosts might not be able to build the full chain.
        # The pinned signer and Authenticode file hash have still been checked.
        Write-Warning "UF MSI signer is pinned, but Windows reported signature status '$($signature.Status)': $($signature.StatusMessage)"
    }

    Write-Output "Validated UF MSI: version=$($metadata.ProductVersion), template=$($metadata.Template), signer='$($signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false))', path='$Path'."
}

function Assert-SupportedSfUpgradePath {
    param (
        [Parameter(Mandatory = $true)]
        [version]$InstalledVersion,

        [Parameter(Mandatory = $true)]
        [version]$TargetVersion
    )

    # Splunk documents direct UF upgrades to 10.2 only from UF 10.0.x or higher.
    # This package set has no supported intermediate 10.0.x installer, so fail
    # before stopping the service or creating a backup instead of taking an
    # unsupported direct 9.x -> 10.2 path.
    if (($TargetVersion.Major -eq 10) -and ($TargetVersion.Minor -eq 2) -and
        ($InstalledVersion -lt [version]"10.0.0")) {
        throw "Unsupported direct UF upgrade path: '$InstalledVersion' -> '$TargetVersion'. Splunk supports a direct upgrade to UF 10.2 only from UF 10.0.x or higher. Use a documented staged upgrade with the required intermediate MSI packages; the current folder is insufficient for this upgrade."
    }
}

function Assert-SplunkForwarderTargetVersion {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ExpectedVersion
    )

    $installedVersionText = Get-InstalledSfVersion
    if ([string]::IsNullOrWhiteSpace($installedVersionText)) {
        throw "Unable to determine the installed Splunk Universal Forwarder version."
    }

    $installedVersion = ConvertTo-SfBaseVersion -VersionText $installedVersionText
    $targetVersion = ConvertTo-SfBaseVersion -VersionText $ExpectedVersion
    if ($installedVersion -ne $targetVersion) {
        throw "UF version validation failed. Expected '$targetVersion', found '$installedVersionText'."
    }

    Write-Output "UF version validation passed: $installedVersionText"
}

function Backup-SplunkUniversalForwarder {
    param (
        [Parameter(Mandatory = $true)]
        [string]$InstalledVersion
    )

    $service = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        throw "SplunkForwarder service was not found before backup."
    }

    $serviceWasRunning = ($service.Status -ne "Stopped")
    if ($serviceWasRunning) {
        Write-Host "Stopping SplunkForwarder to create a consistent backup..."
        Stop-Service -Name "SplunkForwarder" -Force
        $service.WaitForStatus("Stopped", [timespan]::FromSeconds(60))
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $safeVersion = $InstalledVersion -replace '[^0-9A-Za-z._-]', '_'
    $backupDirectory = Join-Path $SplunkBackupRoot ("{0}_UF_{1}_{2}" -f $env:COMPUTERNAME, $safeVersion, $timestamp)

    try {
        Write-Host "Backing up Splunk Universal Forwarder to '$backupDirectory'..."
        New-Item -Path $backupDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null

        # UF configuration can contain credentials and private keys. Restrict the backup
        # to LocalSystem and the built-in Administrators group, using SIDs for localized Windows.
        $aclOutput = & icacls.exe $backupDirectory /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to grant secure ACLs on '$backupDirectory'. Output: $($aclOutput -join ' ')"
        }
        $aclOutput = & icacls.exe $backupDirectory /inheritance:r 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to remove inherited ACLs from '$backupDirectory'. Output: $($aclOutput -join ' ')"
        }

        $backupItems = @(
            @{ RelativePath = "etc"; Required = $true; Description = "configurations, apps and add-ons" },
            @{ RelativePath = "var\lib\splunk\modinputs"; Required = $false; Description = "modular-input checkpoints" },
            @{ RelativePath = "var\lib\splunk\fishbucket"; Required = $false; Description = "file-monitor checkpoints" }
        )
        $backedUpContents = @()

        foreach ($item in $backupItems) {
            $source = Join-Path $SplunkInstallPath $item.RelativePath
            if (-not (Test-Path -LiteralPath $source -PathType Container)) {
                if ($item.Required) {
                    throw "Required Splunk backup source was not found: '$source'."
                }
                Write-Warning "Optional Splunk backup source was not found and was skipped: '$source'."
                continue
            }

            $destination = Join-Path $backupDirectory $item.RelativePath
            $destinationParent = Split-Path $destination -Parent
            New-Item -Path $destinationParent -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Copy-Item -LiteralPath $source -Destination $destination -Recurse -Force -ErrorAction Stop

            if (-not (Test-Path -LiteralPath $destination -PathType Container)) {
                throw "Splunk backup verification failed for '$source'."
            }
            $backedUpContents += $item.RelativePath
        }

        $backupManifest = [PSCustomObject]@{
            ComputerName     = $env:COMPUTERNAME
            InstalledVersion = $InstalledVersion
            BackupTime       = (Get-Date).ToString("o")
            SplunkHome       = $SplunkInstallPath
            ServiceAccount   = Get-SplunkForwarderServiceAccount
            Contents         = $backedUpContents
        }
        $backupManifest |
            ConvertTo-Json |
            Set-Content -LiteralPath (Join-Path $backupDirectory "backup_manifest.json") -Encoding UTF8 -ErrorAction Stop

        Write-Host "Splunk Universal Forwarder backup completed and verified: '$backupDirectory'."
        return $backupDirectory
    }
    catch {
        # If backup fails, leave the existing installation usable and abort before the MSI upgrade.
        if ($serviceWasRunning) {
            $currentService = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
            if ($null -ne $currentService -and $currentService.Status -ne "Running") {
                try {
                    Start-Service -Name "SplunkForwarder"
                }
                catch {
                    Write-Warning "Backup failed and SplunkForwarder could not be restarted."
                }
            }
        }
        throw
    }
}

function ConvertFrom-SecureStringForSplunkMsi {
    param (
        [Parameter(Mandatory = $true)]
        [Security.SecureString]$SecureString
    )

    $bstr = [IntPtr]::Zero
    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

function Read-SplunkAdministratorCredential {
    # Fresh installation requires SPLUNKUSERNAME/SPLUNKPASSWORD when
    # GENRANDOMPASSWORD=0. Read them only at runtime and never echo them.
    if (-not [Environment]::UserInteractive) {
        throw "Fresh UF installation requires an interactive PowerShell session so the Splunk administrator username and password can be entered securely."
    }

    Write-Host "Splunk username rules: required; no spaces, colons (:), forward slashes (/), double quotes, or control characters."
    Write-Host "Splunk password rules: at least 8 printable ASCII characters; double quotes are not accepted. Password input is hidden."

    $maximumAttempts = 3
    for ($attempt = 1; $attempt -le $maximumAttempts; $attempt++) {
        $username = $null
        $securePassword = $null
        $secureConfirmation = $null
        $plainPassword = $null
        $plainConfirmation = $null

        try {
            $username = Read-Host "Enter the Splunk UF administrator username"
            if ($null -ne $username) {
                $username = $username.Trim()
            }

            if ([string]::IsNullOrWhiteSpace($username)) {
                Write-Warning "The Splunk administrator username cannot be empty."
                continue
            }
            if ($username -match '[\x00-\x1F"]') {
                Write-Warning "The Splunk administrator username cannot contain a double quote or control character."
                continue
            }
            if ($username -match '[ :/]') {
                Write-Warning "The Splunk administrator username cannot contain spaces, colons (:), or forward slashes (/)."
                continue
            }

            $securePassword = Read-Host "Enter the Splunk UF administrator password" -AsSecureString
            $secureConfirmation = Read-Host "Re-enter the Splunk UF administrator password" -AsSecureString

            if ($null -eq $securePassword -or $securePassword.Length -eq 0 -or
                $null -eq $secureConfirmation -or $secureConfirmation.Length -eq 0) {
                Write-Warning "The Splunk administrator password cannot be empty."
                continue
            }

            if ($securePassword.Length -lt 8) {
                Write-Warning "The Splunk administrator password must contain at least 8 printable ASCII characters."
                continue
            }

            $plainPassword = ConvertFrom-SecureStringForSplunkMsi -SecureString $securePassword
            $plainConfirmation = ConvertFrom-SecureStringForSplunkMsi -SecureString $secureConfirmation

            if (-not [string]::Equals($plainPassword, $plainConfirmation, [StringComparison]::Ordinal)) {
                Write-Warning "The two password entries do not match."
                continue
            }
            if ($plainPassword -match '[^\x20-\x7E]' -or $plainPassword -match '"') {
                Write-Warning "The Splunk administrator password must use printable ASCII characters and cannot contain a double quote because it cannot be passed safely to msiexec.exe."
                continue
            }

            return [PSCustomObject]@{
                Username = $username
                Password = $plainPassword
            }
        }
        finally {
            if ($null -ne $securePassword) {
                $securePassword.Dispose()
            }
            if ($null -ne $secureConfirmation) {
                $secureConfirmation.Dispose()
            }
            $plainConfirmation = $null
            $plainPassword = $null
        }
    }

    throw "Splunk administrator credentials were not accepted after $maximumAttempts attempts. Fresh UF installation was cancelled."
}

function Install-SplunkUniversalForwarderLeastPrivilege {
    param ([string]$InstallerPath)

    $splunkCredential = $null
    $splunkUsername = $null
    $splunkPassword = $null
    $credentialArguments = $null
    $arguments = $null
    $install = $null

    # Splunk-documented least-privilege MSI flags:
    # - PRIVILEGEBACKUP=0 avoids unrestricted file access. Grant source-specific ACLs instead.
    # - PRIVILEGEIMPERSONATE=1 allows group-based access to additional data sources.
    # - Member server/workstation: do NOT grant SeSecurityPrivilege; use Event Log Readers for read-only Security log access.
    # - Domain Controller: Event Log Readers/local groups are unavailable, so grant SeSecurityPrivilege.
    #   NOTE: SeSecurityPrivilege is READ/WRITE by Windows design, but the UF service still runs as NT SERVICE\SplunkForwarder,
    #   not LocalSystem.
    # - GROUPPERFORMANCEMONITORUSERS=0 because this profile collects logs, not WMI/perfmon metrics.
    $PrivilegeBackup = "0"
    $PrivilegeSecurity = if ($IsDomainController) { "1" } else { "0" }
    $PrivilegeImpersonate = "1"
    $GroupPerformanceMonitorUsers = "0"

    try {
        $splunkCredential = Read-SplunkAdministratorCredential
        $splunkUsername = $splunkCredential.Username
        $splunkPassword = $splunkCredential.Password
        $credentialArguments = @(
            "SPLUNKUSERNAME=`"$splunkUsername`"",
            "GENRANDOMPASSWORD=0",
            "SPLUNKPASSWORD=`"$splunkPassword`""
        )

        $arguments = @(
            "/i `"$InstallerPath`"",
            "DEPLOYMENT_SERVER=`"$SplunkDeploymentServer`"",
            "USE_VIRTUAL_ACCOUNT=1",
            "USE_LOCAL_SYSTEM=0",
            "PRIVILEGEBACKUP=$PrivilegeBackup",
            "PRIVILEGESECURITY=$PrivilegeSecurity",
            "PRIVILEGEIMPERSONATE=$PrivilegeImpersonate",
            "GROUPPERFORMANCEMONITORUSERS=$GroupPerformanceMonitorUsers",
            "LAUNCHSPLUNK=1",
            "AGREETOLICENSE=yes",
            "/quiet",
            "/norestart",
            "/l*v `"$MsiLogPath`""
        )
        $arguments = @($arguments[0..1]) + $credentialArguments + @($arguments[2..($arguments.Count - 1)])

        Write-Output "Installing Splunk Universal Forwarder with the interactively supplied administrator credential and least-privileged virtual account..."
        $install = Start-Process msiexec.exe -ArgumentList $arguments -Wait -PassThru
    }
    finally {
        # Minimize additional in-memory copies created for the MSI command line.
        if ($null -ne $splunkCredential) {
            $splunkCredential.Password = $null
        }
        $splunkPassword = $null
        $splunkUsername = $null
        $splunkCredential = $null
        $credentialArguments = $null
        $arguments = $null
    }
    if ($install.ExitCode -notin @(0, 1641, 3010)) {
        throw "Splunk Universal Forwarder installation failed with exit code $($install.ExitCode). Check '$MsiLogPath'."
    }

    if ($install.ExitCode -in @(1641, 3010)) {
        Write-Output "UF installation succeeded; Windows reports that a restart is required."
    }
}

function Upgrade-SplunkUniversalForwarder {
    param ([string]$InstallerPath)

    # Splunk documents that an in-place Windows UF upgrade retains configuration
    # and ignores installation properties other than AGREETOLICENSE.
    $arguments = @(
        "/i `"$InstallerPath`"",
        "AGREETOLICENSE=yes",
        "/quiet",
        "/norestart",
        "/l*v `"$MsiLogPath`""
    )

    Write-Output "Upgrading Splunk Universal Forwarder in place..."
    $upgrade = Start-Process -FilePath msiexec.exe -ArgumentList $arguments -Wait -PassThru
    if ($upgrade.ExitCode -notin @(0, 1641, 3010)) {
        $service = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
        if ($null -ne $service -and $service.Status -ne "Running") {
            try {
                Start-Service -Name "SplunkForwarder"
            }
            catch {
                Write-Warning "The UF upgrade failed and SplunkForwarder could not be restarted."
            }
        }
        throw "Splunk Universal Forwarder upgrade failed with exit code $($upgrade.ExitCode). Check '$MsiLogPath'."
    }

    if ($upgrade.ExitCode -in @(1641, 3010)) {
        Write-Output "UF upgrade succeeded; Windows reports that a restart is required."
    }
}

function Test-SplunkForwarderLocalGroupMembership {
    param (
        [string]$GroupName,
        [string]$ServiceAccount
    )

    $memberName = ($ServiceAccount -split '\\')[-1]

    # Prefer Get-LocalGroupMember when available (Windows 10 / Server 2016+).
    if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
        try {
            $members = Get-LocalGroupMember -Group $GroupName -ErrorAction Stop
            foreach ($member in $members) {
                if ($member.Name -ieq $ServiceAccount -or $member.Name -match "\\$([regex]::Escape($memberName))$") {
                    return $true
                }
            }
        } catch {
            Write-Verbose "Get-LocalGroupMember check failed: $($_.Exception.Message)"
        }
    }

    # Fallback for older Windows versions such as Server 2012.
    try {
        $group = [ADSI]"WinNT://./$GroupName,group"
        $members = @($group.psbase.Invoke("Members"))
        foreach ($member in $members) {
            $name = $member.GetType().InvokeMember("Name", "GetProperty", $null, $member, $null)
            if ($name -ieq $memberName) {
                return $true
            }
        }
    } catch {
        Write-Verbose "ADSI membership check failed: $($_.Exception.Message)"
    }

    return $false
}

function Grant-SplunkForwarderEventLogReadAccess {
    if ($IsDomainController) {
        Write-Output "Domain Controller detected: skipping Event Log Readers membership. Security Event Log access is provided by SeSecurityPrivilege."
        return
    }

    $serviceAccount = Get-SplunkForwarderServiceAccount
    if ([string]::IsNullOrWhiteSpace($serviceAccount)) {
        throw "Unable to determine SplunkForwarder service account."
    }

    if ($serviceAccount -ine $ExpectedSplunkServiceAccount) {
        throw "Unexpected SplunkForwarder service account '$serviceAccount'. Expected '$ExpectedSplunkServiceAccount'."
    }

    # Resolve the built-in Event Log Readers group by SID so this works on localized Windows.
    $eventLogReadersSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-573")
    $eventLogReadersNtAccount = $eventLogReadersSid.Translate([System.Security.Principal.NTAccount]).Value
    $eventLogReadersGroup = ($eventLogReadersNtAccount -split '\\')[-1]

    if (Test-SplunkForwarderLocalGroupMembership -GroupName $eventLogReadersGroup -ServiceAccount $serviceAccount) {
        Write-Output "'$serviceAccount' is already a member of '$eventLogReadersGroup'."
        return
    }

    Write-Output "Adding '$serviceAccount' to '$eventLogReadersGroup' for read-only Windows Event Log access..."
    $netOutput = & net.exe localgroup "$eventLogReadersGroup" "$serviceAccount" /add 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to add '$serviceAccount' to '$eventLogReadersGroup'. net.exe exit code $LASTEXITCODE. Output: $($netOutput -join ' ')"
    }

    if (-not (Test-SplunkForwarderLocalGroupMembership -GroupName $eventLogReadersGroup -ServiceAccount $serviceAccount)) {
        throw "Event Log Readers membership validation failed for '$serviceAccount'."
    }
}

function Remove-SplunkForwarderPerformanceMonitorMembership {
    if ($IsDomainController) {
        return
    }

    $performanceMonitorSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-558")
    $performanceMonitorAccount = $performanceMonitorSid.Translate([System.Security.Principal.NTAccount]).Value
    $performanceMonitorGroup = ($performanceMonitorAccount -split '\\')[-1]

    if (-not (Test-SplunkForwarderLocalGroupMembership -GroupName $performanceMonitorGroup -ServiceAccount $ExpectedSplunkServiceAccount)) {
        return
    }

    Write-Output "Removing '$ExpectedSplunkServiceAccount' from '$performanceMonitorGroup' because WMI/perfmon inputs are not enabled..."
    $netOutput = & net.exe localgroup "$performanceMonitorGroup" "$ExpectedSplunkServiceAccount" /delete 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to remove '$ExpectedSplunkServiceAccount' from '$performanceMonitorGroup'. Output: $($netOutput -join ' ')"
    }

    if (Test-SplunkForwarderLocalGroupMembership -GroupName $performanceMonitorGroup -ServiceAccount $ExpectedSplunkServiceAccount) {
        throw "Performance Monitor Users membership validation failed for '$ExpectedSplunkServiceAccount'."
    }
}

function Set-PowerShellTranscriptDirectoryAcl {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    # Preserve maintenance access before removing inherited permissions.
    Invoke-CheckedNativeCommand `
        -FilePath "icacls.exe" `
        -ArgumentList @(
            $Path,
            "/grant:r",
            "*S-1-5-18:(OI)(CI)(F)",
            "*S-1-5-32-544:(OI)(CI)(F)",
            "${ExpectedSplunkServiceAccount}:(OI)(CI)(RX)",
            "*S-1-3-0:(OI)(CI)(IO)(F)"
        ) `
        -Operation "Grant protected PowerShell transcript ACLs"

    Invoke-CheckedNativeCommand `
        -FilePath "icacls.exe" `
        -ArgumentList @($Path, "/inheritance:r") `
        -Operation "Remove inherited PowerShell transcript ACLs"

    # Remove broad read permissions, then allow authenticated users to create their
    # own transcript files/directories without granting access to other users' transcripts.
    Invoke-CheckedNativeCommand `
        -FilePath "icacls.exe" `
        -ArgumentList @($Path, "/remove:g", "*S-1-5-32-545", "*S-1-5-11", "*S-1-1-0") `
        -Operation "Remove broad PowerShell transcript read ACLs"

    Invoke-CheckedNativeCommand `
        -FilePath "icacls.exe" `
        -ArgumentList @($Path, "/grant:r", "*S-1-5-11:(WD,AD,X)") `
        -Operation "Grant transcript creation access to authenticated users"
}

function Finalize-SplunkForwarderLeastPrivilege {
    Enforce-SplunkForwarderUserRights
    Grant-SplunkForwarderEventLogReadAccess
    Remove-SplunkForwarderPerformanceMonitorMembership

    # Restart after group membership change so the service token receives the new group membership.
    $service = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        Restart-Service -Name "SplunkForwarder" -Force
        $service.WaitForStatus("Running", [timespan]::FromSeconds(60))
    }

    $service = Get-WmiObject Win32_Service -Filter "Name='SplunkForwarder'" -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        throw "SplunkForwarder service not found after installation."
    }

    Write-Output "SplunkForwarder final logon account: $($service.StartName)"
    if ($service.StartName -ine $ExpectedSplunkServiceAccount) {
        throw "Security validation failed: SplunkForwarder is running as '$($service.StartName)' instead of '$ExpectedSplunkServiceAccount'."
    }
    if ($service.State -ine "Running") {
        throw "SplunkForwarder service-account validation passed, but the service state is '$($service.State)' instead of 'Running'."
    }

    if ($IsDomainController) {
        Write-Output "Least-privilege service-account validation passed for Domain Controller (virtual account + SeSecurityPrivilege profile)."
    } else {
        Write-Output "Least-privilege service-account validation passed for member server/workstation (virtual account + Event Log Readers profile)."
    }
}


function Ensure-Sysmon {
    $SysmonExe = Join-Path $TempDirectory "Sysmon\Sysmon.exe"

    Write-Output "`n==== Checking Sysmon installation/configuration ===="

    if (-not (Test-Path $SysmonExe)) {
        throw "Sysmon executable not found at '$SysmonExe'."
    }

    $sysmonSignature = Get-AuthenticodeSignature -LiteralPath $SysmonExe
    if (($sysmonSignature.Status -ne "Valid") -or
        ($null -eq $sysmonSignature.SignerCertificate) -or
        ($sysmonSignature.SignerCertificate.Subject -notmatch '^CN=Microsoft Corporation(?:,|$)')) {
        throw "Sysmon signature validation failed. Status='$($sysmonSignature.Status)', signer='$($sysmonSignature.SignerCertificate.Subject)'."
    }

    if (-not (Test-Path $SysmonConfigPath)) {
        throw "Sysmon configuration file not found at '$SysmonConfigPath'."
    }

    $ExistingSysmonService = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($ExistingSysmonService) {
        Write-Output "Sysmon is already installed. Updating configuration..."
        & $SysmonExe -accepteula -c $SysmonConfigPath
    } else {
        Write-Output "Sysmon is not installed. Installing Sysmon with the supplied configuration..."
        & $SysmonExe -accepteula -i $SysmonConfigPath
    }

    $SysmonExitCode = $LASTEXITCODE
    if ($SysmonExitCode -ne 0) {
        throw "Sysmon installation/configuration failed with exit code $SysmonExitCode."
    }

    $SysmonService = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $SysmonService) {
        throw "Sysmon service was not found after installation/configuration."
    }

    if ($SysmonService.Status -ne "Running") {
        Write-Output "Sysmon service is not running. Starting service '$($SysmonService.Name)'..."
        Start-Service -Name $SysmonService.Name
        $SysmonService = Get-Service -Name $SysmonService.Name
    }

    if ($SysmonService.Status -ne "Running") {
        throw "Sysmon service '$($SysmonService.Name)' is not running."
    }

    $SysmonChannel = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
    if (-not $SysmonChannel) {
        throw "Sysmon Operational Event Log channel was not found after installation."
    }

    Write-Output "Sysmon validation passed. Service '$($SysmonService.Name)' is running and the Sysmon Operational channel exists."
}

function Grant-SplunkForwarderSysmonAccess {
    $serviceAccount = "NT SERVICE\SplunkForwarder"
    $sysmonChannel = "Microsoft-Windows-Sysmon/Operational"

    Write-Output "`n==== Granting SplunkForwarder read access to Sysmon event channel ===="

    # Verify Sysmon channel exists before attempting to modify permissions
    $channelExists = Get-WinEvent -ListLog $sysmonChannel -ErrorAction SilentlyContinue
    if (-not $channelExists) {
        throw "Sysmon Operational channel not found. Ensure Sysmon is installed first."
    }

    # Retrieve current channel SDDL
    $sddlOutput = wevtutil gl $sysmonChannel 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to retrieve event channel information for '$sysmonChannel'. wevtutil exit code: $LASTEXITCODE"
    }

    $sddlLine = $sddlOutput | Where-Object { $_ -match "^\s*channelAccess:\s*(.+)" }
    if (-not $sddlLine) {
        throw "Unable to parse channelAccess SDDL from wevtutil output."
    }

    $currentSddl = $sddlLine -replace "^\s*channelAccess:\s*", ""
    $currentSddl = $currentSddl.Trim()

    if ([string]::IsNullOrWhiteSpace($currentSddl)) {
        throw "Retrieved SDDL for Sysmon channel is empty."
    }

    Write-Output "Current Sysmon channel SDDL retrieved successfully."

    # Translate service account to SID
    try {
        $ntAccount = New-Object System.Security.Principal.NTAccount($serviceAccount)
        $splunkForwarderSid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        throw "Failed to resolve SID for account '$serviceAccount'. Error: $($_.Exception.Message)"
    }

    Write-Output "SplunkForwarder SID: $splunkForwarderSid"

    # Check if SplunkForwarder already has access
    if ($currentSddl -match [regex]::Escape($splunkForwarderSid)) {
        Write-Output "'$serviceAccount' already has explicit permissions on Sysmon channel. No modification needed."
        return
    }

    # Grant read-only access (0x1 = GENERIC_READ)
    $readAce = "(A;;0x1;;;$splunkForwarderSid)"

    # Insert ACE before the SACL (S:) portion if it exists, otherwise append to DACL
    if ($currentSddl -match "(S:.*)$") {
        $newSddl = $currentSddl -replace "(S:.*)$", "$readAce`$1"
    } else {
        $newSddl = $currentSddl + $readAce
    }

    Write-Output "Applying new SDDL to grant read access..."

    # Apply the new SDDL
    wevtutil sl $sysmonChannel "/ca:$newSddl" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to apply new SDDL to Sysmon channel. wevtutil exit code: $LASTEXITCODE"
    }

    # Verify the permission was applied
    $verifyOutput = wevtutil gl $sysmonChannel 2>&1
    $verifySddlLine = $verifyOutput | Where-Object { $_ -match "^\s*channelAccess:\s*(.+)" }
    $verifySddl = $verifySddlLine -replace "^\s*channelAccess:\s*", ""
    $verifySddl = $verifySddl.Trim()

    if ($verifySddl -notmatch [regex]::Escape($splunkForwarderSid)) {
        throw "Verification failed: SplunkForwarder SID not found in updated SDDL."
    }

    Write-Output "Successfully granted read-only access to '$serviceAccount' on Sysmon Operational channel."
    Write-Output "Least-privilege principle maintained: SplunkForwarder can READ Sysmon events but cannot modify or clear the log."
}

Protect-InstallerWorkingDirectory

Write-Output "==== Checking Deployment Server Connectivity ===="
$DeploymentServerReachable = Test-TcpPort -ComputerName $SplunkDeploymentServerIP -Port 8089

if ($DeploymentServerReachable) { 
    Write-Output "Connection to $SplunkDeploymentServerIP on port 8089 succeeded. Proceeding with installation..."

    # Detect by ProductType/version/build so localized OS captions do not break selection.
    $OperatingSystem = Get-WmiObject Win32_OperatingSystem
    $Processor = Get-WmiObject Win32_Processor | Select-Object -First 1
    $InstallerSelection = Get-SplunkInstallerSelection `
        -OperatingSystem $OperatingSystem `
        -ProcessorArchitecture ([int]$Processor.Architecture) `
        -PackageDirectory $TempDirectory

    $ExpectedSfVersion = $InstallerSelection.ExpectedVersion
    $SplunkInstallerPath = $InstallerSelection.InstallerPath
    Write-Output "Detected OS: $($OperatingSystem.Caption) (version $($OperatingSystem.Version), build $($OperatingSystem.BuildNumber), ProductType $($OperatingSystem.ProductType), architecture $($OperatingSystem.OSArchitecture))."
    Write-Output "Selected UF $ExpectedSfVersion for $($InstallerSelection.OperatingSystem): '$SplunkInstallerPath'."
    
    $WasFreshInstall = -not (Test-Path $SplunkInstallPath)

    if (-not $WasFreshInstall) {
        Write-Output "Splunk Universal Forwarder is already installed at '$SplunkInstallPath'."

        $InstalledSfVersion = Get-InstalledSfVersion
        $CurrentServiceAccount = Get-SplunkForwarderServiceAccount
        Write-Output "Installed version: $InstalledSfVersion; Expected version: $ExpectedSfVersion"
        Write-Output "Current SplunkForwarder logon account: $CurrentServiceAccount"

        # An in-place upgrade retains the existing service account and ignores MSI account
        # properties. This script intentionally performs install/upgrade only; it never uninstalls UF.
        if ([string]::IsNullOrWhiteSpace($InstalledSfVersion)) {
            throw "Splunk installation directory exists, but the installed UF version could not be determined."
        }

        $ParsedInstalledVersion = ConvertTo-SfBaseVersion -VersionText $InstalledSfVersion
        $ParsedTargetVersion = ConvertTo-SfBaseVersion -VersionText $ExpectedSfVersion
        if ($ParsedInstalledVersion -gt $ParsedTargetVersion) {
            throw "Installed UF version '$InstalledSfVersion' is newer than target '$ExpectedSfVersion'. Downgrade is not permitted."
        }

        $VersionMismatch = ($ParsedInstalledVersion -ne $ParsedTargetVersion)
        if ($VersionMismatch) {
            Assert-SupportedSfUpgradePath `
                -InstalledVersion $ParsedInstalledVersion `
                -TargetVersion $ParsedTargetVersion
        }
        $NeedsPrivilegeMigration = ($CurrentServiceAccount -ine $ExpectedSplunkServiceAccount)

        if ($NeedsPrivilegeMigration) {
            throw "SplunkForwarder is running as '$CurrentServiceAccount', not '$ExpectedSplunkServiceAccount'. Splunk requires uninstall/reinstall to change the service account after UF has started. This install/upgrade-only script will not uninstall the existing UF."
        }

        if ($VersionMismatch) {
            Write-Output "Version mismatch detected. Preparing a documented in-place UF upgrade..."
            Assert-SplunkInstallerPackage -Path $SplunkInstallerPath -ExpectedVersion $ExpectedSfVersion

            # Stop and back up configurations/apps and input checkpoints before the MSI upgrade.
            # fishbucket is included to preserve file-monitor checkpoints and reduce duplicate ingestion risk.
            $BackupDirectory = Backup-SplunkUniversalForwarder -InstalledVersion $InstalledSfVersion
            Write-Output "Verified pre-upgrade UF backup: '$BackupDirectory'."

            Upgrade-SplunkUniversalForwarder -InstallerPath $SplunkInstallerPath
            Assert-SplunkForwarderTargetVersion -ExpectedVersion $ExpectedSfVersion
            Finalize-SplunkForwarderLeastPrivilege
        }
        else {
            Write-Output "Installed UF version and virtual service account are correct. Verifying read-only Event Log access..."
            Finalize-SplunkForwarderLeastPrivilege
        }
    }
    else {
        Write-Output "Splunk Universal Forwarder is not installed. Proceeding with least-privilege installation..."

        Assert-SplunkInstallerPackage -Path $SplunkInstallerPath -ExpectedVersion $ExpectedSfVersion

        Install-SplunkUniversalForwarderLeastPrivilege -InstallerPath $SplunkInstallerPath
        Assert-SplunkForwarderTargetVersion -ExpectedVersion $ExpectedSfVersion
        Finalize-SplunkForwarderLeastPrivilege


    }
}
else {
    Write-Output "Connection to $SplunkDeploymentServerIP on port 8089 failed. Installation aborted."
    Write-Output "Please check the network connection or ensure the deployment server is reachable."
    exit 1
}

# Ensure Sysmon is installed/configured regardless of whether UF was fresh-installed,
# migrated, upgraded, or already compliant.
Ensure-Sysmon

# Grant SplunkForwarder read access to Sysmon event channel
# This is required because Event Log Readers membership does not automatically
# grant access to custom event channels like Sysmon Operational.
Grant-SplunkForwarderSysmonAccess

# Set log size
Set-EventLogMaximumSize -Channel "Security" -MaximumSize 540100100
Set-EventLogMaximumSize -Channel "Application" -MaximumSize 256000100
Set-EventLogMaximumSize -Channel "Setup" -MaximumSize 256000100
Set-EventLogMaximumSize -Channel "System" -MaximumSize 256000100
Set-EventLogMaximumSize -Channel "Windows PowerShell" -MaximumSize 256000100
Set-EventLogMaximumSize -Channel "Microsoft-Windows-PowerShell/Operational" -MaximumSize 256000100
Set-EventLogMaximumSize -Channel "Microsoft-Windows-Sysmon/Operational" -MaximumSize 540100100

Write-Output "`nAdding registry keys for logging and policy configuration..."
# Enable command line audit logging
Set-RegistryValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Type "REG_DWORD" -Data 1

# Apply advanced audit policy
Set-RegistryValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Type "REG_DWORD" -Data 1

# Configure PowerShell policy
$policies = @(
    @{ Path = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"; Name = "EnableModuleLogging"; Type = "REG_DWORD"; Data = 1 },
    @{ Path = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Name = "EnableScriptBlockLogging"; Type = "REG_DWORD"; Data = 1 },
    @{ Path = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Name = "EnableInvocationHeader"; Type = "REG_DWORD"; Data = 1 },
    @{ Path = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Name = "EnableTranscripting"; Type = "REG_DWORD"; Data = 1 }
)
# Logging does not require changing the machine execution policy. Preserve any
# stricter enterprise setting instead of forcing RemoteSigned.
foreach ($policy in $policies) {
    # Always enforce the requested value. Checking only for value existence would
    # leave a policy disabled when it already exists with data 0.
    Set-RegistryValue -Path $policy.Path -Name $policy.Name -Type $policy.Type -Data $policy.Data
}

# Module logging records only explicitly selected modules. Use '*' to capture all
# Windows PowerShell module pipeline execution events (for example Event ID 4103).
Set-RegistryValue `
    -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" `
    -Name "*" `
    -Type "REG_SZ" `
    -Data "*"

# Create logging directory if it does not exist
if (-not (Test-Path $PSLogDirectory)) {
    New-Item -Path $PSLogDirectory -ItemType Directory -Force | Out-Null
}
Set-RegistryValue `
    -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -Name "OutputDirectory" `
    -Type "REG_SZ" `
    -Data $PSLogDirectory

# Allow users to create their own protected transcripts while granting the UF read-only access.
Set-PowerShellTranscriptDirectoryAcl -Path $PSLogDirectory

Write-Output "`nGroup Policy configuration..."
#Account Logon
Set-WindowsAuditSubcategory -Subcategory "Credential Validation" -Success enable -Failure enable
Set-WindowsAuditSubcategory -Subcategory "Other Account Logon Events" -Success enable -Failure enable

# The KDC runs on domain controllers. These subcategories generate the expected
# Kerberos authentication/service-ticket events only on a DC.
if ($IsDomainController) {
    Set-WindowsAuditSubcategory -Subcategory "Kerberos Authentication Service" -Success enable -Failure enable
    Set-WindowsAuditSubcategory -Subcategory "Kerberos Service Ticket Operations" -Success enable -Failure enable
} else {
    Set-WindowsAuditSubcategory -Subcategory "Kerberos Authentication Service" -Success disable -Failure disable
    Set-WindowsAuditSubcategory -Subcategory "Kerberos Service Ticket Operations" -Success disable -Failure disable
}

#Account management
Set-WindowsAuditSubcategory -Subcategory "Application Group Management" -Success disable -Failure disable
Set-WindowsAuditSubcategory -Subcategory "Computer Account Management" -Success enable -Failure enable
Set-WindowsAuditSubcategory -Subcategory "Distribution Group Management" -Success enable -Failure enable
Set-WindowsAuditSubcategory -Subcategory "Security Group Management" -Success enable -Failure enable
Set-WindowsAuditSubcategory -Subcategory "Other Account Management Events" -Success enable -Failure enable
Set-WindowsAuditSubcategory -Subcategory "User Account Management" -Success enable -Failure enable

# Detailed Tracking
Set-WindowsAuditSubcategory -Subcategory "Process Termination" -Success enable -Failure enable
Set-WindowsAuditSubcategory -Subcategory "DPAPI Activity" -Success disable -Failure disable
Set-WindowsAuditSubcategory -Subcategory "RPC Events" -Success enable -Failure enable
Set-WindowsAuditSubcategory -Subcategory "Process Creation" -Success enable -Failure enable

# DS Access
# Active Directory Domain Services auditing is applicable only to domain controllers.
if ($IsDomainController) {
    Set-WindowsAuditSubcategory -Subcategory "Detailed Directory Service Replication" -Success enable -Failure enable
    Set-WindowsAuditSubcategory -Subcategory "Directory Service Access" -Success enable -Failure enable
    Set-WindowsAuditSubcategory -Subcategory "Directory Service Changes" -Success enable -Failure enable
    Set-WindowsAuditSubcategory -Subcategory "Directory Service Replication" -Success enable -Failure enable
} else {
    Set-WindowsAuditSubcategory -Subcategory "Detailed Directory Service Replication" -Success disable -Failure disable
    Set-WindowsAuditSubcategory -Subcategory "Directory Service Access" -Success disable -Failure disable
    Set-WindowsAuditSubcategory -Subcategory "Directory Service Changes" -Success disable -Failure disable
    Set-WindowsAuditSubcategory -Subcategory "Directory Service Replication" -Success disable -Failure disable
}

# Logon/Logoff
Set-WindowsAuditSubcategory -Subcategory "Account Lockout" -Success enable -Failure disable
Set-WindowsAuditSubcategory -Subcategory "IPsec Extended Mode" -Success disable -Failure disable
Set-WindowsAuditSubcategory -Subcategory "IPsec Main Mode" -Success disable -Failure disable
Set-WindowsAuditSubcategory -Subcategory "IPsec Quick Mode" -Success disable -Failure disable
Set-WindowsAuditSubcategory -Subcategory "Logoff" -Success enable -Failure disable
Set-WindowsAuditSubcategory -Subcategory "Logon" -Success enable -Failure enable
Set-WindowsAuditSubcategory -Subcategory "Network Policy Server" -Success disable -Failure disable
Set-WindowsAuditSubcategory -Subcategory "Other Logon/Logoff Events" -Success enable -Failure enable
Set-WindowsAuditSubcategory -Subcategory "Special Logon" -Success enable -Failure disable

#Object Access
Set-WindowsAuditSubcategory -Subcategory "Application Generated" -Success enable -Failure enable
Set-WindowsAuditSubcategory -Subcategory "Certification Services" -Success enable -Failure enable
Set-WindowsAuditSubcategory -Subcategory "Detailed File Share" -Success enable -Failure disable

#Will generate a lot of events if Files and Reg keys are audited so only audit locations that are not noisy
Set-WindowsAuditSubcategory -Subcategory "File Share" -Success enable -Failure enable
Set-WindowsAuditSubcategory -Subcategory "File System" -Success enable -Failure enable

#This next item is a VERY noisy items and requires the Windows Firewall to be in at least an ALLOW  configuration in Group Policy
Set-WindowsAuditSubcategory -Subcategory "Filtering Platform Connection" -Success disable -Failure disable
Set-WindowsAuditSubcategory -Subcategory "Filtering Platform Packet Drop" -Success disable -Failure disable
Set-WindowsAuditSubcategory -Subcategory "Handle Manipulation" -Success disable -Failure disable
Set-WindowsAuditSubcategory -Subcategory "Kernel Object" -Success enable -Failure enable
Set-WindowsAuditSubcategory -Subcategory "Other Object Access Events" -Success disable -Failure disable
Set-WindowsAuditSubcategory -Subcategory "Registry" -Success enable -Failure disable
Set-WindowsAuditSubcategory -Subcategory "Removable Storage" -Success enable -Failure enable
Set-WindowsAuditSubcategory -Subcategory "SAM" -Success disable -Failure disable

#Policy Change
Set-WindowsAuditSubcategory -Subcategory "Audit Policy Change" -Success enable -Failure enable
Set-WindowsAuditSubcategory -Subcategory "Authentication Policy Change" -Success enable -Failure disable
Set-WindowsAuditSubcategory -Subcategory "Authorization Policy Change" -Success enable -Failure enable

#Enable if you use Windows Firewall to monitor changes
Set-WindowsAuditSubcategory -Subcategory "Filtering Platform Policy Change" -Success disable -Failure disable
Set-WindowsAuditSubcategory -Subcategory "MPSSVC Rule-Level Policy Change" -Success disable -Failure disable
Set-WindowsAuditSubcategory -Subcategory "Other Policy Change Events" -Success disable -Failure disable

# Privilege Use
Set-WindowsAuditSubcategory -Subcategory "Other Privilege Use Events" -Success disable -Failure disable
Set-WindowsAuditSubcategory -Subcategory "Non Sensitive Privilege Use" -Success disable -Failure disable
Set-WindowsAuditSubcategory -Subcategory "Sensitive Privilege Use" -Success enable -Failure enable

# SYSTEM
Set-WindowsAuditSubcategory -Subcategory "IPsec Driver" -Success enable -Failure enable
Set-WindowsAuditSubcategory -Subcategory "Other System Events" -Success enable -Failure enable
Set-WindowsAuditSubcategory -Subcategory "Security State Change" -Success enable -Failure enable
Set-WindowsAuditSubcategory -Subcategory "Security System Extension" -Success enable -Failure enable
Set-WindowsAuditSubcategory -Subcategory "System Integrity" -Success enable -Failure enable

Write-Output "`nChecking the status and service account of Splunk Universal Forwarder..."
# Finish
Invoke-CheckedNativeCommand `
    -FilePath "$SplunkInstallPath\bin\splunk.exe" `
    -ArgumentList @("status") `
    -Operation "Check Splunk Universal Forwarder status"
$FinalSplunkService = Get-WmiObject Win32_Service | Where-Object { $_.Name -eq "SplunkForwarder" }
$FinalSplunkService | Select-Object Name, StartName, State
if ($null -eq $FinalSplunkService) {
    throw "SplunkForwarder service was not found. Least-privilege requirement is NOT met."
} elseif ($FinalSplunkService.StartName -ine $ExpectedSplunkServiceAccount) {
    throw "SplunkForwarder is running as '$($FinalSplunkService.StartName)' instead of '$ExpectedSplunkServiceAccount'. Least-privilege requirement is NOT met."
} else {
    Write-Output "Least-privilege validation passed. SplunkForwarder is running as '$ExpectedSplunkServiceAccount'."
    if ($IsDomainController) {
        Write-Output "Security log access profile: Domain Controller -> SeSecurityPrivilege enabled; Event Log Readers not used."
    } else {
        Write-Output "Security log access profile: Member server/workstation -> SeSecurityPrivilege disabled; Event Log Readers used for read-only access."
    }
}

#Clean forder
Write-Output "`nCleaning up temporary installation files..."
if (Test-Path $TempDirectory) {
    try {
        Remove-Item -Path $TempDirectory -Recurse -Force
        Write-Output "Temporary directory '$TempDirectory' has been successfully removed."
    } catch {
        Write-Output "Failed to remove temporary directory '$TempDirectory'. Error: $_"
    }
} else {
    Write-Output "Temporary directory '$TempDirectory' does not exist."
}
if (Test-Path $TempDirectory1) {
    try {
        Remove-Item -Path $TempDirectory1 -Recurse -Force
        Write-Output "Temporary directory '$TempDirectory1' has been successfully removed."
    } catch {
        Write-Output "Failed to remove temporary directory '$TempDirectory1'. Error: $_"
    }
} else {
    Write-Output "Temporary directory '$TempDirectory1' does not exist."
}
