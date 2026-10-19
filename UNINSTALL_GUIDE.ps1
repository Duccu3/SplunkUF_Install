<#
.SYNOPSIS
    Uninstalls Splunk Universal Forwarder and, unless requested otherwise, Sysmon.

.DESCRIPTION
    Uses the registered Windows Installer product code and REMOVE_FROM_GROUPS=1,
    then removes only known residuals created by this deployment package.

    The default operation removes Splunk UF, Sysmon, the SplunkForwarder service
    account's local-group membership, LSA rights and explicit Sysmon-channel ACE.

    -FullReset additionally removes the Windows logging policy values, PowerShell
    transcript files, installer staging files, and disables only the advanced
    audit subcategories managed by script_install_windows_new(Services).ps1.

    Event-log contents and configured maximum sizes are deliberately preserved:
    the old script could not know their pre-installation values, so assigning
    arbitrary "defaults" would not be a valid rollback.

.EXAMPLE
    .\UNINSTALL_GUIDE.ps1 -Force

    Remove UF and Sysmon, preserving logging policy, PSLogs and UF backups.

.EXAMPLE
    .\UNINSTALL_GUIDE.ps1 -FullReset -Force

    Recommended clean LAB reset before repeatedly testing a fresh installation.
    C:\SplunkUF_Backup is still preserved.

.EXAMPLE
    .\UNINSTALL_GUIDE.ps1 -FullReset -RemoveBackups -Force

    Strongest reset. This also permanently removes all UF backups.

.EXAMPLE
    .\UNINSTALL_GUIDE.ps1 -KeepSysmon -Force

    Remove UF but keep the existing Sysmon installation and event history.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
param (
    [switch]$FullReset,
    [switch]$KeepSysmon,
    [switch]$RemoveBackups,
    [switch]$Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# Keep compatibility with the Windows PowerShell versions commonly present on
# Server 2012 while still failing before any mutation if the console is not elevated.
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "UNINSTALL_GUIDE.ps1 must be run from an elevated PowerShell window (Run as Administrator)."
}

$script:UninstallCmdlet = $PSCmdlet
$script:Failures = New-Object System.Collections.Generic.List[string]
$script:Warnings = New-Object System.Collections.Generic.List[string]
$script:DeferredCleanupPaths = New-Object System.Collections.Generic.List[string]
$script:RebootRequired = $false

$SplunkServiceName = "SplunkForwarder"
$SplunkServiceAccount = "NT SERVICE\SplunkForwarder"
$SplunkInstallPath = "C:\Program Files\SplunkUniversalForwarder"
$SysmonChannel = "Microsoft-Windows-Sysmon/Operational"
$TranscriptDirectory = "C:\PSLogs"
$InstallerDirectory = "C:\install_agent_windows"
$InstallerArchive = "C:\install_agent_windows.zip"
$BackupRoot = "C:\SplunkUF_Backup"

$UninstallLog = Join-Path $env:TEMP ("SplunkUF_uninstall_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
$TranscriptStarted = $false

function Write-Section {
    param ([Parameter(Mandatory = $true)][string]$Text)

    Write-Output ""
    Write-Output ("=" * 72)
    Write-Output $Text
    Write-Output ("=" * 72)
}

function Add-UninstallFailure {
    param ([Parameter(Mandatory = $true)][string]$Message)

    $script:Failures.Add($Message)
    Write-Warning $Message
}

function Add-UninstallWarning {
    param ([Parameter(Mandatory = $true)][string]$Message)

    $script:Warnings.Add($Message)
    Write-Warning $Message
}

function Test-ChangeApproved {
    param (
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$Action
    )

    return $script:UninstallCmdlet.ShouldProcess($Target, $Action)
}

function Invoke-NativeCommandCapture {
    param (
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @()
    )

    # Windows PowerShell 5.1 converts native stderr into ErrorRecord objects.
    # With the script-wide ErrorActionPreference=Stop, expected idempotent native
    # errors (for example NET HELPMSG 1377: member already absent) would otherwise
    # terminate the entire uninstall before its exit code can be evaluated.
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $commandOutput = & $FilePath @ArgumentList 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }

    return New-Object PSObject -Property @{
        ExitCode = $exitCode
        Output   = @($commandOutput)
    }
}

function Invoke-NativeCommand {
    param (
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [int[]]$SuccessExitCodes = @(0),
        [Parameter(Mandatory = $true)][string]$Operation,
        [switch]$IgnoreFailure
    )

    $result = Invoke-NativeCommandCapture -FilePath $FilePath -ArgumentList $ArgumentList
    $commandOutput = $result.Output
    $exitCode = $result.ExitCode
    if ($exitCode -notin $SuccessExitCodes) {
        $message = "$Operation failed with exit code $exitCode. Output: $($commandOutput -join ' ')"
        if ($IgnoreFailure) {
            Add-UninstallWarning $message
            return $false
        }
        throw $message
    }

    return $true
}

function Get-SplunkForwarderSid {
    try {
        $account = New-Object System.Security.Principal.NTAccount($SplunkServiceAccount)
        return $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        # sc.exe calculates a service SID from its name, including when the
        # virtual account can no longer be resolved normally.
        $result = Invoke-NativeCommandCapture -FilePath "sc.exe" -ArgumentList @("showsid", $SplunkServiceName)
        $sidMatch = [regex]::Match(($result.Output -join "`n"), "S-1-5-80-(?:\d+-){4}\d+")
        if ($sidMatch.Success) {
            return $sidMatch.Value
        }
    }

    return ""
}

function Get-SplunkForwarderLogonAccount {
    $service = Get-WmiObject Win32_Service -Filter "Name='$SplunkServiceName'" -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return ""
    }
    return [string]$service.StartName
}

function Test-LocalSystemAccount {
    param ([string]$Account)

    return $Account -in @(
        "LocalSystem",
        "Local System",
        "NT AUTHORITY\SYSTEM",
        ".\LocalSystem"
    )
}

function Get-SplunkUninstallEntries {
    $registryRoots = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    $seenProductCodes = @{}
    $results = @()

    foreach ($root in $registryRoots) {
        if (-not (Test-Path -LiteralPath $root)) {
            continue
        }

        foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            $item = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
            if ($null -eq $item) {
                continue
            }

            $displayNameProperty = $item.PSObject.Properties["DisplayName"]
            $publisherProperty = $item.PSObject.Properties["Publisher"]
            $displayName = if ($null -ne $displayNameProperty) { [string]$displayNameProperty.Value } else { "" }
            $publisher = if ($null -ne $publisherProperty) { [string]$publisherProperty.Value } else { "" }
            $isUniversalForwarder = (
                ($displayName -match "^(Splunk\s+)?Universal\s*Forwarder(?:\s|$)") -or
                (($publisher -match "Splunk") -and ($displayName -match "Universal\s*Forwarder"))
            )
            if (-not $isUniversalForwarder) {
                continue
            }

            $productCode = [string]$key.PSChildName
            if ($productCode -notmatch "^\{[0-9A-Fa-f-]{36}\}$") {
                $uninstallStringProperty = $item.PSObject.Properties["UninstallString"]
                $uninstallString = if ($null -ne $uninstallStringProperty) { [string]$uninstallStringProperty.Value } else { "" }
                $productCodeMatch = [regex]::Match($uninstallString, "\{[0-9A-Fa-f-]{36}\}")
                if ($productCodeMatch.Success) {
                    $productCode = $productCodeMatch.Value
                }
            }

            if (($productCode -match "^\{[0-9A-Fa-f-]{36}\}$") -and (-not $seenProductCodes.ContainsKey($productCode))) {
                $seenProductCodes[$productCode] = $true
                $displayVersionProperty = $item.PSObject.Properties["DisplayVersion"]
                $displayVersion = if ($null -ne $displayVersionProperty) { [string]$displayVersionProperty.Value } else { "" }
                $results += New-Object PSObject -Property @{
                    DisplayName    = $displayName
                    DisplayVersion = $displayVersion
                    ProductCode    = $productCode
                    RegistryPath   = $key.PSPath
                }
            }
        }
    }

    # Recovery path for a damaged/missing Add/Remove Programs entry. These are
    # the ProductCodes of the three MSI packages shipped beside this script.
    # Calling msiexec for a code that is not installed returns 1605, which the
    # uninstall flow treats as an idempotent success.
    if (($results.Count -eq 0) -and
        (($null -ne (Get-Service -Name $SplunkServiceName -ErrorAction SilentlyContinue)) -or
         (Test-Path -LiteralPath $SplunkInstallPath))) {
        $knownProducts = @(
            @{ Version = "10.2.5"; ProductCode = "{19C3777D-2D60-477F-9E9A-99A8080CE83C}" },
            @{ Version = "9.2.8"; ProductCode = "{C99D7A64-F228-49E1-A77D-F1FF5F8D384C}" },
            @{ Version = "9.1.10"; ProductCode = "{0EE41023-752F-4BA4-9BFF-B305165BBC32}" }
        )
        foreach ($knownProduct in $knownProducts) {
            $results += New-Object PSObject -Property @{
                DisplayName    = "UniversalForwarder (recovery candidate)"
                DisplayVersion = $knownProduct.Version
                ProductCode    = $knownProduct.ProductCode
                RegistryPath   = ""
            }
        }
    }

    return @($results)
}

function Stop-SplunkForwarder {
    $splunkExe = Join-Path $SplunkInstallPath "bin\splunk.exe"
    if (Test-Path -LiteralPath $splunkExe -PathType Leaf) {
        if (Test-ChangeApproved -Target $splunkExe -Action "Stop Splunk Universal Forwarder") {
            try {
                & $splunkExe stop 2>&1 | Out-Null
            }
            catch {
                Add-UninstallWarning "splunk.exe stop did not complete cleanly: $($_.Exception.Message)"
            }
        }
    }

    $service = Get-Service -Name $SplunkServiceName -ErrorAction SilentlyContinue
    if (($null -ne $service) -and ($service.Status -ne "Stopped")) {
        if (Test-ChangeApproved -Target $SplunkServiceName -Action "Stop Windows service") {
            try {
                Stop-Service -Name $SplunkServiceName -Force -ErrorAction Stop
                $service.WaitForStatus("Stopped", (New-TimeSpan -Seconds 30))
            }
            catch {
                Add-UninstallWarning "Could not stop service '$SplunkServiceName': $($_.Exception.Message)"
            }
        }
    }
}

function Stop-SplunkProcessesFromInstallPath {
    $escapedRoot = [regex]::Escape($SplunkInstallPath.TrimEnd("\") + "\")
    $processes = @(Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        ([string]$_.ExecutablePath) -match ("^" + $escapedRoot)
    })

    foreach ($process in $processes) {
        if (Test-ChangeApproved -Target ("PID {0}: {1}" -f $process.ProcessId, $process.ExecutablePath) -Action "Terminate residual Splunk process") {
            try {
                Stop-Process -Id ([int]$process.ProcessId) -Force -ErrorAction Stop
            }
            catch {
                Add-UninstallWarning "Could not terminate Splunk PID $($process.ProcessId): $($_.Exception.Message)"
            }
        }
    }
}

function Remove-SplunkLocalGroupMembership {
    param ([string]$InstalledServiceAccount)

    $computerSystem = Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue
    if (($null -ne $computerSystem) -and ($computerSystem.DomainRole -in @(4, 5))) {
        Write-Output "Domain Controller detected: no local Event Log Readers group cleanup is required."
        return
    }

    try {
        $groupSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-573")
        $groupAccount = $groupSid.Translate([System.Security.Principal.NTAccount]).Value
        $groupName = ($groupAccount -split "\\")[-1]
    }
    catch {
        Add-UninstallWarning "Could not resolve the localized Event Log Readers group: $($_.Exception.Message)"
        return
    }

    $isLocalSystemProfile = Test-LocalSystemAccount -Account $InstalledServiceAccount
    if ($isLocalSystemProfile) {
        Write-Output "Legacy LocalSystem UF profile detected. Event Log Readers membership for '$SplunkServiceAccount' is not expected; checking only for a stale membership."
    }
    elseif ($InstalledServiceAccount -ieq $SplunkServiceAccount) {
        Write-Output "Virtual-account UF profile detected. Removing its Event Log Readers membership."
    }
    elseif (-not [string]::IsNullOrWhiteSpace($InstalledServiceAccount)) {
        Write-Warning "UF uses nonstandard service account '$InstalledServiceAccount'. Only the known SplunkForwarder service-SID residuals will be removed manually; MSI REMOVE_FROM_GROUPS=1 will handle installer-managed rights for the actual account."
    }

    if (Test-ChangeApproved -Target "$groupName -> $SplunkServiceAccount" -Action "Remove local-group membership") {
        $result = Invoke-NativeCommandCapture -FilePath "net.exe" -ArgumentList @("localgroup", $groupName, $SplunkServiceAccount, "/delete")
        $outputText = $result.Output -join " "
        if ($result.ExitCode -eq 0) {
            Write-Output "Removed '$SplunkServiceAccount' from '$groupName'."
        }
        elseif ($outputText -match "\b1377\b") {
            Write-Output "'$SplunkServiceAccount' is already absent from '$groupName'; no group cleanup is required."
        }
        else {
            # MSI REMOVE_FROM_GROUPS=1 will make the same cleanup. A missing
            # membership is also an idempotent success, so this is a warning.
            Add-UninstallWarning "Local-group removal returned exit code $($result.ExitCode); MSI REMOVE_FROM_GROUPS=1 will retry it. Output: $outputText"
        }
    }
}

function Initialize-LsaCleanupType {
    if ("VNCS.UninstallLsaUserRights" -as [type]) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace VNCS
{
    public static class UninstallLsaUserRights
    {
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

        [DllImport("advapi32.dll")]
        private static extern uint LsaOpenPolicy(IntPtr SystemName, ref LSA_OBJECT_ATTRIBUTES ObjectAttributes, uint DesiredAccess, out IntPtr PolicyHandle);

        [DllImport("advapi32.dll")]
        private static extern uint LsaRemoveAccountRights(IntPtr PolicyHandle, IntPtr AccountSid, [MarshalAs(UnmanagedType.Bool)] bool AllRights, IntPtr UserRights, uint CountOfRights);

        [DllImport("advapi32.dll")]
        private static extern uint LsaEnumerateAccountRights(IntPtr PolicyHandle, IntPtr AccountSid, out IntPtr UserRights, out uint CountOfRights);

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
            IntPtr handle;
            uint status = LsaOpenPolicy(IntPtr.Zero, ref attributes, POLICY_LOOKUP_NAMES, out handle);
            ThrowOnError(status, "LsaOpenPolicy");
            return handle;
        }

        private static IntPtr AllocateSid(string sidValue)
        {
            SecurityIdentifier sid = new SecurityIdentifier(sidValue);
            byte[] bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            IntPtr pointer = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, pointer, bytes.Length);
            return pointer;
        }

        private static void ThrowOnError(uint status, string operation)
        {
            if (status == 0) return;
            uint error = LsaNtStatusToWinError(status);
            throw new Win32Exception((int)error, operation + " failed");
        }

        public static void RemoveAllRights(string sidValue)
        {
            IntPtr handle = IntPtr.Zero;
            IntPtr sid = IntPtr.Zero;
            try
            {
                handle = OpenPolicy();
                sid = AllocateSid(sidValue);
                uint status = LsaRemoveAccountRights(handle, sid, true, IntPtr.Zero, 0);
                uint error = status == 0 ? 0 : LsaNtStatusToWinError(status);
                if (error == 2 || error == 1332) return;
                ThrowOnError(status, "LsaRemoveAccountRights");
            }
            finally
            {
                if (sid != IntPtr.Zero) Marshal.FreeHGlobal(sid);
                if (handle != IntPtr.Zero) LsaClose(handle);
            }
        }

        public static uint GetRightCount(string sidValue)
        {
            IntPtr handle = IntPtr.Zero;
            IntPtr sid = IntPtr.Zero;
            IntPtr rights = IntPtr.Zero;
            try
            {
                handle = OpenPolicy();
                sid = AllocateSid(sidValue);
                uint count;
                uint status = LsaEnumerateAccountRights(handle, sid, out rights, out count);
                uint error = status == 0 ? 0 : LsaNtStatusToWinError(status);
                if (error == 2 || error == 1332) return 0;
                ThrowOnError(status, "LsaEnumerateAccountRights");
                return count;
            }
            finally
            {
                if (rights != IntPtr.Zero) LsaFreeMemory(rights);
                if (sid != IntPtr.Zero) Marshal.FreeHGlobal(sid);
                if (handle != IntPtr.Zero) LsaClose(handle);
            }
        }
    }
}
'@
}

function Remove-SplunkLsaRights {
    param ([string]$ServiceSid)

    if ([string]::IsNullOrWhiteSpace($ServiceSid)) {
        Add-UninstallWarning "The SplunkForwarder service SID could not be resolved; MSI REMOVE_FROM_GROUPS=1 will be relied upon for user-right cleanup."
        return
    }

    # This function must never alter LocalSystem (S-1-5-18), a user account or
    # another service. Only the deterministic SplunkForwarder service SID is in scope.
    if ($ServiceSid -notmatch '^S-1-5-80-(?:\d+-){4}\d+$') {
        Add-UninstallFailure "Refusing LSA cleanup for unexpected SID '$ServiceSid'. Expected a Windows service SID under S-1-5-80."
        return
    }

    if (Test-ChangeApproved -Target $ServiceSid -Action "Remove every LSA user right assigned to SplunkForwarder service SID") {
        try {
            Initialize-LsaCleanupType
            [VNCS.UninstallLsaUserRights]::RemoveAllRights($ServiceSid)
            Write-Output "Removed LSA user rights assigned to SplunkForwarder SID '$ServiceSid'."
        }
        catch {
            Add-UninstallWarning "Could not remove LSA rights for SID '$ServiceSid': $($_.Exception.Message)"
        }
    }
}

function Remove-SplunkAceFromSysmonChannel {
    param ([string]$ServiceSid)

    if ([string]::IsNullOrWhiteSpace($ServiceSid)) {
        return
    }
    if ($null -eq (Get-WinEvent -ListLog $SysmonChannel -ErrorAction SilentlyContinue)) {
        return
    }

    $result = Invoke-NativeCommandCapture -FilePath "wevtutil.exe" -ArgumentList @("gl", $SysmonChannel)
    if ($result.ExitCode -ne 0) {
        Add-UninstallWarning "Could not read Sysmon channel access descriptor."
        return
    }

    $line = $result.Output | Where-Object { $_ -match "^\s*channelAccess:\s*(.+)" } | Select-Object -First 1
    if ($null -eq $line) {
        Add-UninstallWarning "Could not parse Sysmon channel access descriptor."
        return
    }

    $currentSddl = ([string]$line -replace "^\s*channelAccess:\s*", "").Trim()
    if ($currentSddl -notmatch [regex]::Escape($ServiceSid)) {
        return
    }

    # Remove only ACEs belonging to this one service SID.
    $acePattern = "\([^\)]*;;;" + [regex]::Escape($ServiceSid) + "\)"
    $newSddl = [regex]::Replace($currentSddl, $acePattern, "")
    if ($newSddl -eq $currentSddl) {
        Add-UninstallWarning "SplunkForwarder SID was present in Sysmon SDDL, but its ACE could not be safely isolated."
        return
    }

    if (Test-ChangeApproved -Target $SysmonChannel -Action "Remove explicit SplunkForwarder read ACE") {
        try {
            Invoke-NativeCommand -FilePath "wevtutil.exe" -ArgumentList @("sl", $SysmonChannel, "/ca:$newSddl") -Operation "Remove SplunkForwarder ACE from Sysmon channel" | Out-Null
        }
        catch {
            Add-UninstallWarning $_.Exception.Message
        }
    }
}

function Uninstall-SplunkMsiProducts {
    $entries = @(Get-SplunkUninstallEntries)
    if ($entries.Count -eq 0) {
        Write-Output "No registered Splunk Universal Forwarder MSI product was found."
        return
    }

    foreach ($entry in $entries) {
        Write-Output ("Found {0} {1}, ProductCode {2}." -f $entry.DisplayName, $entry.DisplayVersion, $entry.ProductCode)
        if (-not (Test-ChangeApproved -Target $entry.ProductCode -Action "Uninstall Splunk Universal Forwarder with REMOVE_FROM_GROUPS=1")) {
            continue
        }

        $msiLog = Join-Path $env:TEMP ("SplunkUF_msi_uninstall_{0}_{1}.log" -f ($entry.ProductCode -replace "[{}-]", ""), (Get-Date -Format "yyyyMMdd_HHmmss"))
        $arguments = "/x $($entry.ProductCode) REMOVE_FROM_GROUPS=1 /qn /norestart /L*v `"$msiLog`""
        try {
            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru -ErrorAction Stop
            if ($process.ExitCode -in @(0, 1605, 1614)) {
                Write-Output "MSI uninstall completed. Log: $msiLog"
            }
            elseif ($process.ExitCode -in @(1641, 3010)) {
                $script:RebootRequired = $true
                Write-Output "MSI uninstall completed and requested a restart. Log: $msiLog"
            }
            else {
                Add-UninstallFailure "MSI uninstall failed with exit code $($process.ExitCode). Log: $msiLog"
            }
        }
        catch {
            Add-UninstallFailure "Could not launch MSI uninstall for $($entry.ProductCode): $($_.Exception.Message)"
        }
    }
}

function Remove-ResidualService {
    param ([Parameter(Mandatory = $true)][string]$Name)

    if ($null -eq (Get-Service -Name $Name -ErrorAction SilentlyContinue)) {
        return
    }

    if (Test-ChangeApproved -Target $Name -Action "Delete residual Windows service") {
        Invoke-NativeCommandCapture -FilePath "sc.exe" -ArgumentList @("stop", $Name) | Out-Null
        $result = Invoke-NativeCommandCapture -FilePath "sc.exe" -ArgumentList @("delete", $Name)
        $outputText = $result.Output -join " "
        if (($result.ExitCode -ne 0) -and ($outputText -notmatch "\b1060\b")) {
            Add-UninstallFailure "Could not delete residual service '$Name'. Output: $outputText"
        }
        else {
            if ($result.ExitCode -eq 0) {
                $script:RebootRequired = $true
                Write-Output "Deleted residual service '$Name'."
            }
        }
    }
}

function Remove-ExactFileSystemPath {
    param (
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$AllowedPaths,
        [Parameter(Mandatory = $true)][string]$Description,
        [switch]$DeferIfLocked
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd("\")
    $allowed = $false
    foreach ($candidate in $AllowedPaths) {
        if ($fullPath -ieq ([System.IO.Path]::GetFullPath($candidate).TrimEnd("\"))) {
            $allowed = $true
            break
        }
    }
    if (-not $allowed) {
        throw "Refusing to remove non-allowlisted path '$fullPath'."
    }
    if (-not (Test-Path -LiteralPath $fullPath)) {
        return
    }
    if (-not (Test-ChangeApproved -Target $fullPath -Action "Remove $Description")) {
        return
    }

    $lastError = $null
    foreach ($attempt in 1..3) {
        try {
            Remove-Item -LiteralPath $fullPath -Recurse -Force -ErrorAction Stop
            Write-Output "Removed $Description '$fullPath'."
            return
        }
        catch {
            $lastError = $_
            Start-Sleep -Seconds 1
        }
    }

    if ($DeferIfLocked) {
        if (-not $script:DeferredCleanupPaths.Contains($fullPath)) {
            $script:DeferredCleanupPaths.Add($fullPath)
        }
        Add-UninstallWarning "Could not remove $Description '$fullPath' while this PowerShell host is using it. Cleanup is deferred until this PowerShell window closes."
        return
    }

    Add-UninstallFailure "Could not remove $Description '$fullPath': $($lastError.Exception.Message)"
    $script:RebootRequired = $true
}

function Move-LocationOutsideInstallerStaging {
    $currentLocation = Get-Location
    if ($currentLocation.Provider.Name -ne "FileSystem") {
        return
    }

    $currentPath = [System.IO.Path]::GetFullPath($currentLocation.Path).TrimEnd("\")
    $stagingPath = [System.IO.Path]::GetFullPath($InstallerDirectory).TrimEnd("\")
    if (($currentPath -ieq $stagingPath) -or $currentPath.StartsWith($stagingPath + "\", [System.StringComparison]::OrdinalIgnoreCase)) {
        Set-Location -LiteralPath $env:SystemRoot
        Write-Output "Moved the PowerShell working directory to '$env:SystemRoot' so installer staging can be removed."
    }
}

function Test-DeferredCleanupPath {
    param ([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd("\")
    return $script:DeferredCleanupPaths.Contains($fullPath)
}

function Start-DeferredCleanup {
    if ($WhatIfPreference -or ($script:DeferredCleanupPaths.Count -eq 0)) {
        return
    }

    $allowedDeferredPaths = @(
        [System.IO.Path]::GetFullPath($TranscriptDirectory).TrimEnd("\"),
        [System.IO.Path]::GetFullPath($InstallerDirectory).TrimEnd("\"),
        [System.IO.Path]::GetFullPath($InstallerArchive).TrimEnd("\")
    )
    foreach ($path in $script:DeferredCleanupPaths) {
        if ($path -notin $allowedDeferredPaths) {
            Add-UninstallFailure "Refusing to schedule non-allowlisted deferred cleanup path '$path'."
            return
        }
    }

    $pathLiterals = @($script:DeferredCleanupPaths | ForEach-Object {
        "'" + ($_ -replace "'", "''") + "'"
    }) -join ", "
    $cleanupTemplate = @'
$paths = @(__PATHS__)
Wait-Process -Id __PARENT_PID__ -ErrorAction SilentlyContinue
foreach ($path in $paths) {
    foreach ($attempt in 1..30) {
        if (-not (Test-Path -LiteralPath $path)) { break }
        try {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
            break
        }
        catch {
            Start-Sleep -Seconds 1
        }
    }
}
'@
    $cleanupCommand = $cleanupTemplate.Replace("__PATHS__", $pathLiterals).Replace("__PARENT_PID__", [string]$PID)
    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cleanupCommand))
    $powerShellExe = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $helperWorkingDirectory = Join-Path $env:SystemRoot "Temp"
    if (-not (Test-Path -LiteralPath $helperWorkingDirectory -PathType Container)) {
        $helperWorkingDirectory = $env:SystemRoot
    }

    try {
        Start-Process `
            -FilePath $powerShellExe `
            -ArgumentList "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encodedCommand" `
            -WorkingDirectory $helperWorkingDirectory `
            -WindowStyle Hidden `
            -ErrorAction Stop | Out-Null
        Write-Output "Scheduled deferred cleanup for: $($script:DeferredCleanupPaths -join ', ')"
    }
    catch {
        Add-UninstallFailure "Could not schedule deferred cleanup: $($_.Exception.Message)"
    }
}

function Get-SysmonServiceExecutable {
    foreach ($serviceName in @("Sysmon64", "Sysmon")) {
        $service = Get-WmiObject Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
        if (($null -eq $service) -or [string]::IsNullOrWhiteSpace([string]$service.PathName)) {
            continue
        }

        $match = [regex]::Match([string]$service.PathName, '^\s*"([^"]+)"|^\s*([^\s]+)')
        if ($match.Success) {
            $path = if ($match.Groups[1].Success) { $match.Groups[1].Value } else { $match.Groups[2].Value }
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                return $path
            }
        }
    }
    return ""
}

function Test-MicrosoftSignedSysmon {
    param ([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }
    if ([System.IO.Path]::GetFileName($Path) -notin @("Sysmon.exe", "Sysmon64.exe")) {
        return $false
    }

    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        return (
            ($null -ne $signature.SignerCertificate) -and
            ($signature.Status -notin @("NotSigned", "HashMismatch")) -and
            ($signature.SignerCertificate.Subject -match '^CN=Microsoft Corporation(?:,|$)')
        )
    }
    catch {
        return $false
    }
}

function Uninstall-Sysmon {
    $candidatePaths = New-Object System.Collections.Generic.List[string]
    $serviceExecutable = Get-SysmonServiceExecutable
    foreach ($path in @(
        $serviceExecutable,
        "C:\Windows\Sysmon64.exe",
        "C:\Windows\Sysmon.exe",
        (Join-Path $InstallerDirectory "Sysmon\Sysmon.exe")
    )) {
        if ((-not [string]::IsNullOrWhiteSpace($path)) -and (-not $candidatePaths.Contains($path))) {
            $candidatePaths.Add($path)
        }
    }

    $sysmonServices = @(Get-Service -Name "Sysmon", "Sysmon64" -ErrorAction SilentlyContinue)
    if (($sysmonServices.Count -eq 0) -and ($null -eq (Get-Service -Name "SysmonDrv" -ErrorAction SilentlyContinue))) {
        Write-Output "Sysmon services are not installed."
        return
    }

    $uninstallAttempted = $false
    foreach ($candidate in $candidatePaths) {
        if (-not (Test-MicrosoftSignedSysmon -Path $candidate)) {
            continue
        }
        if (-not (Test-ChangeApproved -Target $candidate -Action "Uninstall Microsoft Sysmon")) {
            continue
        }

        $uninstallAttempted = $true
        try {
            $result = Invoke-NativeCommandCapture -FilePath $candidate -ArgumentList @("-accepteula", "-u", "force")
        }
        catch {
            Add-UninstallWarning "Could not launch Sysmon uninstaller '$candidate': $($_.Exception.Message). Exact service cleanup will be attempted."
            continue
        }
        if ($result.ExitCode -eq 0) {
            Write-Output "Sysmon uninstall completed using '$candidate'."
            break
        }
        Add-UninstallWarning "Sysmon '$candidate -u force' returned exit code $($result.ExitCode); exact service cleanup will be attempted. Output: $($result.Output -join ' ')"
    }

    if (-not $uninstallAttempted) {
        Add-UninstallWarning "No Microsoft-signed Sysmon executable was available; exact service cleanup will be attempted."
    }

    foreach ($serviceName in @("Sysmon", "Sysmon64", "SysmonDrv")) {
        Remove-ResidualService -Name $serviceName
    }

    foreach ($candidate in $candidatePaths) {
        $normalized = [System.IO.Path]::GetFullPath($candidate)
        if ($normalized -in @("C:\Windows\Sysmon.exe", "C:\Windows\Sysmon64.exe")) {
            Remove-ExactFileSystemPath -Path $normalized -AllowedPaths @("C:\Windows\Sysmon.exe", "C:\Windows\Sysmon64.exe") -Description "residual Sysmon binary"
        }
    }
}

function Remove-RegistryValueSafely {
    param (
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (($null -eq $key) -or ($key.GetValueNames() -notcontains $Name)) {
        return
    }

    if (Test-ChangeApproved -Target "$Path\$Name" -Action "Remove installer-managed registry value") {
        try {
            Remove-ItemProperty -LiteralPath $Path -Name $Name -Force -ErrorAction Stop
            Write-Output "Removed registry value '$Path\$Name'."
        }
        catch {
            Add-UninstallFailure "Could not remove registry value '$Path\$Name': $($_.Exception.Message)"
        }
    }
}

function Remove-EmptyRegistryKey {
    param ([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $key) {
        return
    }
    $children = @(Get-ChildItem -LiteralPath $Path -ErrorAction SilentlyContinue)
    if (($key.GetValueNames().Count -eq 0) -and ($children.Count -eq 0)) {
        if (Test-ChangeApproved -Target $Path -Action "Remove empty installer-created registry key") {
            Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        }
    }
}

function Remove-LoggingPolicyCreatedByInstaller {
    $moduleLogging = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    $moduleNames = Join-Path $moduleLogging "ModuleNames"
    $scriptBlockLogging = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $transcription = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    $processAudit = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

    Remove-RegistryValueSafely -Path $moduleNames -Name "*"
    Remove-RegistryValueSafely -Path $moduleLogging -Name "EnableModuleLogging"
    Remove-RegistryValueSafely -Path $scriptBlockLogging -Name "EnableScriptBlockLogging"
    foreach ($name in @("EnableInvocationHeader", "EnableTranscripting", "OutputDirectory")) {
        Remove-RegistryValueSafely -Path $transcription -Name $name
    }
    Remove-RegistryValueSafely -Path $processAudit -Name "ProcessCreationIncludeCmdLine_Enabled"
    Remove-RegistryValueSafely -Path $lsa -Name "SCENoApplyLegacyAuditPolicy"

    foreach ($path in @($moduleNames, $moduleLogging, $scriptBlockLogging, $transcription)) {
        Remove-EmptyRegistryKey -Path $path
    }
}

function Disable-InstallerManagedAuditSubcategories {
    # Stable GUIDs used by the install script; auditpol /clear is never used.
    $auditGuids = @(
        "{0CCE9210-69AE-11D9-BED3-505054503030}", "{0CCE9211-69AE-11D9-BED3-505054503030}",
        "{0CCE9212-69AE-11D9-BED3-505054503030}", "{0CCE9213-69AE-11D9-BED3-505054503030}",
        "{0CCE9214-69AE-11D9-BED3-505054503030}", "{0CCE9215-69AE-11D9-BED3-505054503030}",
        "{0CCE9216-69AE-11D9-BED3-505054503030}", "{0CCE9217-69AE-11D9-BED3-505054503030}",
        "{0CCE9218-69AE-11D9-BED3-505054503030}", "{0CCE9219-69AE-11D9-BED3-505054503030}",
        "{0CCE921A-69AE-11D9-BED3-505054503030}", "{0CCE921B-69AE-11D9-BED3-505054503030}",
        "{0CCE921C-69AE-11D9-BED3-505054503030}", "{0CCE921D-69AE-11D9-BED3-505054503030}",
        "{0CCE921E-69AE-11D9-BED3-505054503030}", "{0CCE921F-69AE-11D9-BED3-505054503030}",
        "{0CCE9220-69AE-11D9-BED3-505054503030}", "{0CCE9221-69AE-11D9-BED3-505054503030}",
        "{0CCE9222-69AE-11D9-BED3-505054503030}", "{0CCE9223-69AE-11D9-BED3-505054503030}",
        "{0CCE9224-69AE-11D9-BED3-505054503030}", "{0CCE9225-69AE-11D9-BED3-505054503030}",
        "{0CCE9226-69AE-11D9-BED3-505054503030}", "{0CCE9227-69AE-11D9-BED3-505054503030}",
        "{0CCE9228-69AE-11D9-BED3-505054503030}", "{0CCE9229-69AE-11D9-BED3-505054503030}",
        "{0CCE922A-69AE-11D9-BED3-505054503030}", "{0CCE922B-69AE-11D9-BED3-505054503030}",
        "{0CCE922C-69AE-11D9-BED3-505054503030}", "{0CCE922D-69AE-11D9-BED3-505054503030}",
        "{0CCE922E-69AE-11D9-BED3-505054503030}", "{0CCE922F-69AE-11D9-BED3-505054503030}",
        "{0CCE9230-69AE-11D9-BED3-505054503030}", "{0CCE9231-69AE-11D9-BED3-505054503030}",
        "{0CCE9232-69AE-11D9-BED3-505054503030}", "{0CCE9233-69AE-11D9-BED3-505054503030}",
        "{0CCE9234-69AE-11D9-BED3-505054503030}", "{0CCE9235-69AE-11D9-BED3-505054503030}",
        "{0CCE9236-69AE-11D9-BED3-505054503030}", "{0CCE9237-69AE-11D9-BED3-505054503030}",
        "{0CCE9238-69AE-11D9-BED3-505054503030}", "{0CCE9239-69AE-11D9-BED3-505054503030}",
        "{0CCE923A-69AE-11D9-BED3-505054503030}", "{0CCE923B-69AE-11D9-BED3-505054503030}",
        "{0CCE923C-69AE-11D9-BED3-505054503030}", "{0CCE923D-69AE-11D9-BED3-505054503030}",
        "{0CCE923E-69AE-11D9-BED3-505054503030}", "{0CCE923F-69AE-11D9-BED3-505054503030}",
        "{0CCE9240-69AE-11D9-BED3-505054503030}", "{0CCE9241-69AE-11D9-BED3-505054503030}",
        "{0CCE9242-69AE-11D9-BED3-505054503030}", "{0CCE9243-69AE-11D9-BED3-505054503030}",
        "{0CCE9244-69AE-11D9-BED3-505054503030}", "{0CCE9245-69AE-11D9-BED3-505054503030}"
    )

    foreach ($guid in $auditGuids) {
        if (-not (Test-ChangeApproved -Target $guid -Action "Disable installer-managed advanced audit subcategory")) {
            continue
        }
        $result = Invoke-NativeCommandCapture -FilePath "auditpol.exe" -ArgumentList @("/set", "/subcategory:$guid", "/success:disable", "/failure:disable")
        if ($result.ExitCode -ne 0) {
            Add-UninstallFailure "Could not disable audit subcategory $guid. Output: $($result.Output -join ' ')"
        }
    }
}

function Test-RegistryValueExists {
    param (
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    $key = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    return (($null -ne $key) -and ($key.GetValueNames() -contains $Name))
}

function Confirm-RequestedScope {
    if ($WhatIfPreference -or $Force) {
        return
    }

    Write-Output ""
    Write-Warning "This operation permanently uninstalls Splunk UF and removes Sysmon unless -KeepSysmon is used."
    if ($FullReset) {
        Write-Warning "FullReset also removes PSLogs and disables the exact audit subcategories managed by the installer. Domain GPO can reapply them."
    }
    if ($RemoveBackups) {
        Write-Warning "RemoveBackups permanently deletes '$BackupRoot'."
    }
    $confirmation = Read-Host "Type UNINSTALL to continue"
    if ($confirmation -cne "UNINSTALL") {
        throw "Cancelled by user. No uninstall action was started."
    }
}

function Test-FinalState {
    param ([string]$ServiceSid)

    Write-Section "FINAL VALIDATION"
    $clean = $true

    if ($null -ne (Get-Service -Name $SplunkServiceName -ErrorAction SilentlyContinue)) {
        Add-UninstallFailure "SplunkForwarder service still exists. A restart may be required."
        $clean = $false
    }
    if (Test-Path -LiteralPath $SplunkInstallPath) {
        Add-UninstallFailure "Splunk install directory still exists: '$SplunkInstallPath'."
        $clean = $false
    }
    if (@(Get-SplunkUninstallEntries).Count -gt 0) {
        Add-UninstallFailure "Splunk Universal Forwarder is still registered with Windows Installer."
        $clean = $false
    }
    if (@(Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        ([string]$_.ExecutablePath) -like "$SplunkInstallPath\*"
    }).Count -gt 0) {
        Add-UninstallFailure "A process is still running from '$SplunkInstallPath'."
        $clean = $false
    }

    if ((-not $KeepSysmon) -and (@(Get-Service -Name "Sysmon", "Sysmon64", "SysmonDrv" -ErrorAction SilentlyContinue).Count -gt 0)) {
        Add-UninstallFailure "One or more Sysmon services still exist. A restart may be required."
        $clean = $false
    }

    if (-not [string]::IsNullOrWhiteSpace($ServiceSid)) {
        try {
            Initialize-LsaCleanupType
            if ([VNCS.UninstallLsaUserRights]::GetRightCount($ServiceSid) -ne 0) {
                Add-UninstallFailure "SplunkForwarder SID '$ServiceSid' still has LSA user rights."
                $clean = $false
            }
        }
        catch {
            Add-UninstallWarning "Could not validate residual LSA rights: $($_.Exception.Message)"
        }

        if ($null -ne (Get-WinEvent -ListLog $SysmonChannel -ErrorAction SilentlyContinue)) {
            $channelResult = Invoke-NativeCommandCapture -FilePath "wevtutil.exe" -ArgumentList @("gl", $SysmonChannel)
            if (($channelResult.ExitCode -eq 0) -and (($channelResult.Output -join "`n") -match [regex]::Escape($ServiceSid))) {
                Add-UninstallFailure "Sysmon channel still contains an ACE for SplunkForwarder SID '$ServiceSid'."
                $clean = $false
            }
        }
    }

    if ($FullReset) {
        foreach ($path in @($TranscriptDirectory, $InstallerDirectory, $InstallerArchive)) {
            if (Test-Path -LiteralPath $path) {
                if (Test-DeferredCleanupPath -Path $path) {
                    Write-Output "FullReset path is pending deferred cleanup after this PowerShell window closes: '$path'."
                }
                else {
                    Add-UninstallFailure "FullReset residual path still exists: '$path'."
                    $clean = $false
                }
            }
        }
        $policyValues = @(
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"; Name = "EnableModuleLogging" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"; Name = "*" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Name = "EnableScriptBlockLogging" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Name = "EnableInvocationHeader" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Name = "EnableTranscripting" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Name = "OutputDirectory" },
            @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"; Name = "ProcessCreationIncludeCmdLine_Enabled" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "SCENoApplyLegacyAuditPolicy" }
        )
        foreach ($policy in $policyValues) {
            if (Test-RegistryValueExists -Path $policy.Path -Name $policy.Name) {
                Add-UninstallFailure "FullReset registry value still exists: '$($policy.Path)\$($policy.Name)'."
                $clean = $false
            }
        }
    }

    if ($RemoveBackups -and (Test-Path -LiteralPath $BackupRoot)) {
        Add-UninstallFailure "Backup directory still exists: '$BackupRoot'."
        $clean = $false
    }

    if ($clean -and ($script:Failures.Count -eq 0)) {
        Write-Output "Validation passed: the requested uninstall scope is clean."
        return $true
    }
    return $false
}

$finalStateClean = $false
$serviceSid = ""
$installedServiceAccount = ""

try {
    try {
        Start-Transcript -Path $UninstallLog -Force | Out-Null
        $TranscriptStarted = $true
    }
    catch {
        Write-Warning "Could not start transcript log: $($_.Exception.Message)"
    }

    Write-Section "SPLUNK UF / SYSMON UNINSTALL"
    Write-Output "Mode: $(if ($FullReset) { 'Full LAB reset' } else { 'Application uninstall' })"
    Write-Output "Sysmon: $(if ($KeepSysmon) { 'preserve' } else { 'remove' })"
    Write-Output "UF backups: $(if ($RemoveBackups) { 'remove' } else { 'preserve' })"
    Write-Output "Log: $UninstallLog"
    Write-Warning "Event-log records and maximum-size settings are preserved because the installer did not capture their original state."

    Confirm-RequestedScope
    $installedServiceAccount = Get-SplunkForwarderLogonAccount
    if (-not [string]::IsNullOrWhiteSpace($installedServiceAccount)) {
        Write-Output "Detected SplunkForwarder logon account: $installedServiceAccount"
        if (Test-LocalSystemAccount -Account $installedServiceAccount) {
            Write-Warning "Legacy LocalSystem installation detected. Uninstall is supported; this script will never remove or modify LocalSystem's own LSA rights."
        }
    }

    $serviceSid = Get-SplunkForwarderSid
    if (-not [string]::IsNullOrWhiteSpace($serviceSid)) {
        Write-Output "Resolved SplunkForwarder SID: $serviceSid"
    }

    Write-Section "1. REMOVE SPLUNK UNIVERSAL FORWARDER"
    Stop-SplunkForwarder
    Remove-SplunkLocalGroupMembership -InstalledServiceAccount $installedServiceAccount
    Remove-SplunkAceFromSysmonChannel -ServiceSid $serviceSid
    Remove-SplunkLsaRights -ServiceSid $serviceSid
    Uninstall-SplunkMsiProducts
    Stop-SplunkProcessesFromInstallPath
    Remove-ResidualService -Name $SplunkServiceName
    Remove-ExactFileSystemPath -Path $SplunkInstallPath -AllowedPaths @($SplunkInstallPath) -Description "Splunk UF residual directory"

    if (-not $KeepSysmon) {
        Write-Section "2. REMOVE SYSMON"
        Uninstall-Sysmon
    }
    else {
        Write-Section "2. PRESERVE SYSMON"
        Write-Output "Sysmon was kept; only the explicit SplunkForwarder channel ACE was removed."
    }

    if ($FullReset) {
        Write-Section "3. FULL LAB RESET"
        Write-Warning "Disabling only audit subcategories managed by this installer; auditpol /clear is never used."
        Disable-InstallerManagedAuditSubcategories
        Remove-LoggingPolicyCreatedByInstaller
        Move-LocationOutsideInstallerStaging
        Remove-ExactFileSystemPath -Path $TranscriptDirectory -AllowedPaths @($TranscriptDirectory) -Description "PowerShell transcript directory" -DeferIfLocked
        Remove-ExactFileSystemPath -Path $InstallerDirectory -AllowedPaths @($InstallerDirectory) -Description "installer staging directory" -DeferIfLocked
        Remove-ExactFileSystemPath -Path $InstallerArchive -AllowedPaths @($InstallerArchive) -Description "installer staging archive" -DeferIfLocked
    }

    if ($RemoveBackups) {
        Write-Section "4. REMOVE UF BACKUPS"
        Remove-ExactFileSystemPath -Path $BackupRoot -AllowedPaths @($BackupRoot) -Description "Splunk UF backup root"
    }
    elseif (Test-Path -LiteralPath $BackupRoot) {
        Write-Output "Preserved UF backups at '$BackupRoot'."
    }

    if ($WhatIfPreference) {
        Write-Output "WhatIf simulation completed; final-state validation was skipped because no changes were made."
        $finalStateClean = $true
    }
    else {
        $finalStateClean = Test-FinalState -ServiceSid $serviceSid
    }
}
catch {
    Add-UninstallFailure $_.Exception.Message
}
finally {
    if ($TranscriptStarted) {
        try { Stop-Transcript | Out-Null } catch { }
    }
}

Start-DeferredCleanup

Write-Output ""
Write-Output ("Warnings: {0}; failures: {1}; reboot required: {2}" -f $script:Warnings.Count, $script:Failures.Count, $script:RebootRequired)
Write-Output "Detailed log: $UninstallLog"
if ($script:DeferredCleanupPaths.Count -gt 0) {
    Write-Output "Close this PowerShell window to release transcript/file locks and finish deleting: $($script:DeferredCleanupPaths -join ', ')"
}

if ($script:Failures.Count -gt 0 -or -not $finalStateClean) {
    Write-Output "UNINSTALL INCOMPLETE. Review the failures above, restart Windows if requested, then run this script again."
    exit 2
}

if ($script:RebootRequired) {
    Write-Output "UNINSTALL COMPLETE. Restart Windows before reinstalling Splunk UF."
    exit 3010
}

Write-Output "UNINSTALL COMPLETE. You can run script_install_windows_new(Services).ps1 again."
exit 0
