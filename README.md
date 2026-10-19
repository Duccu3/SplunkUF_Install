Splunk Universal Forwarder & Windows Logging Configuration

Các chức năng chính
- Kiểm tra hệ điều hành Windows, kiến trúc và phiên bản Splunk Universal Forwarder; lựa chọn gói MSI tương ứng.
- Kiểm tra cài đặt UF hiện tại và hỗ trợ nâng cấp có kiểm tra phiên bản, chữ ký số và sao lưu cấu hình.
- Cấu hình UF chạy với tài khoản dịch vụ NT SERVICE\SplunkForwarder, kiểm soát đặc quyền và quyền đọc Event Log.
- Cài đặt hoặc cập nhật Sysmon qua file cấu hình được chuẩn bị trước.
- Thiết lập PowerShell Module Logging, Script Block Logging, Transcription và Windows Advanced Audit Policy.
- Điều chỉnh kích thước Event Log, kiểm tra kết quả và dọn thư mục cài đặt tạm.
Điều kiện sử dụng
1. Máy Windows thử nghiệm, PowerShell chạy với quyền Administrator/LocalSystem. Chỉ chạy trên môi trường được phép thay đổi audit policy và cài agent.
2. Chuẩn bị trước thư mục C:\install_agent_windows gồm các gói UF MSI tương ứng với các bản Windows hỗ trợ, Sysmon\Sysmon.exe và sysmonconfig.xml. Script không tải các gói cài đặt này từ Internet.
3. Splunk Deployment Server đã sẵn sàng và có thể truy cập cổng TCP 8089.
4. Người quản trị cung cấp địa chỉ Deployment Server qua biến môi trường SPLUNK_DEPLOYMENT_SERVER_IP; bản GitHub không chứa IP nội bộ.
5. Tác vụ cài đặt UF mới sẽ hỏi tên và mật khẩu quản trị UF trong phiên PowerShell tương tác. Không đính kèm credential, MSI logs, backup hay cấu hình sản xuất vào repository.
Ví dụ chạy trên máy lab đã chuẩn bị đầy đủ file cài đặt (thay địa chỉ minh họa bằng IP thực tế thuộc hệ thống được phép quản trị):
$env:SPLUNK_DEPLOYMENT_SERVER_IP = "192.0.2.10"  # Ví dụ minh họa, cần thay bằng máy chủ thực tế
.\script_install_windows_new.ps1
Cảnh báo vận hành: Script có thể thay đổi ACL, đặc quyền dịch vụ, audit policy và kích thước Event Log. Có tùy chọn dừng dịch vụ WinCollect nếu người vận hành chủ động đặt SPLUNK_UF_STOP_WINCOLLECT=1; mặc định không dừng. Kiểm tra chính sách domain GPO trước khi chạy vì GPO có thể ghi đè cấu hình audit cục bộ. Thông tin xác thực khi cài UF được truyền qua tham số MSI, vì vậy chỉ chạy trên thiết bị tin cậy, kiểm soát khả năng xem dòng lệnh tiến trình và bảo vệ splunkinstall.log.
Kiểm tra cơ bản sau cài đặt
Get-Service SplunkForwarder
Get-Service Sysmon* -ErrorAction SilentlyContinue
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational'
auditpol /get /category:*
Đối với Splunk, tiếp tục xác minh dữ liệu từ các nguồn WinEventLog:Security, Microsoft-Windows-Sysmon/Operational, Microsoft-Windows-PowerShell/Operational theo cấu hình triển khai thực tế.

Các file input/output.conf sử dụng để cấu hình trên endpoint nhằm đẩy log tập trung về SIEM
