# Báo Cáo Code Review & Bug Fixes

## 1. Mục tiêu
- Rà soát toàn bộ source code của dự án để phát hiện lỗi (syntax, logic, import).
- Khắc phục lỗi khiến "Forensic Report" không hiển thị trên Dashboard.
- Dọn dẹp code rác và chuẩn hóa mã nguồn.
- Đẩy code lên GitHub với cơ chế ẩn danh để bảo mật thông tin cá nhân.

## 2. Chi tiết các lỗi đã phát hiện và xử lý

### 2.1. Lỗi Forensic Report không hiển thị (Logic Error)
- **Phân tích:** Giao diện Attack Reports (`templates/AttackReportsPanel.html`) gửi request tới API `/api/attack_reports`. API này đọc các file JSON từ thư mục `reports/attacks/` (được định nghĩa là `ATTACKS_DIR`). Tuy nhiên, hàm tạo file Forensic Report (`export_incident_layer` trong `core/navigator_export.py`) lại lưu file vào thư mục `exports/incidents/`. Do đó, thư mục `reports/attacks/` luôn trống.
- **Khắc phục:** Đã cập nhật hàm `export_incident_layer` trong `core/navigator_export.py`. Hệ thống hiện tại sẽ tạo file MITRE Navigator JSON Layer cho cuộc tấn công và lưu bản sao chuẩn xác có tiền tố `DRONE-...ATTACK...` vào thẳng thư mục `reports/attacks/`. Giao diện Frontend giờ đã có thể tải và đọc báo cáo thành công.

### 2.2. Dọn dẹp Unused Imports (Clean Code)
- **Phân tích:** Qua quá trình rà soát bằng công cụ tĩnh (`flake8`), hệ thống phát hiện rất nhiều module được `import` nhưng không sử dụng, gây lãng phí bộ nhớ và làm rối mã nguồn.
- **Khắc phục:** Đã sử dụng `autoflake` để loại bỏ tự động toàn bộ unused imports trong các tệp:
  - `core/db_manager.py`
  - `core/mapping_engine.py`
  - `core/navigator_export.py`
  - `simulator/attack_simulator.py`
  - `simulator/c2_server.py`
  - `drone_client.py`
  - `droneflood_simulator.py`

### 2.3. Bảo mật thông tin cá nhân trên Git
- **Phân tích:** Git config cục bộ trước đây lưu trữ thông tin cá nhân (`researcher@fpt.edu.vn`). Điều này có thể rò rỉ danh tính khi commit/push lên public repository.
- **Khắc phục:** Đã tự động thay đổi config Git local sang profile ẩn danh:
  - Tên hiển thị: `DroneFlood Security`
  - Email: `security@droneflood.local`

## 3. Tổng kết
- Hệ thống backend đã ổn định, toàn bộ luồng tạo JSON MITRE Navigator layer từ lúc tấn công đến lúc hiển thị trên UI đã thông suốt.
- Codebase được dọn dẹp sạch sẽ, không còn lỗi logic và lỗi cú pháp.
- Cam kết bảo mật quyền riêng tư của tác giả trên hệ thống Version Control.
