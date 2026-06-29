# Hướng dẫn Reproduce (Chạy lại hệ thống MITRE ATT&CK Mapping cho Drone)

## Yêu cầu hệ thống (Requirements)
- **Python:** Phiên bản 3.10 trở lên.
- **Hệ điều hành:** Khuyên dùng Windows/Ubuntu cho máy SOC, Kali Linux cho máy Attacker (hoặc có thể chạy tất cả trên cùng 1 máy để test cục bộ).
- **Thư viện phụ thuộc:** Không yêu cầu (Zero-dependency), dự án chỉ sử dụng các thư viện chuẩn của Python.

## Cài đặt (Installation)
1. Clone hoặc tải mã nguồn về máy:
```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/Xay_dung_MITRE_ATTACK_Mapping.git
cd Xay_dung_MITRE_ATTACK_Mapping
```
*(Nếu bạn đã có sẵn thư mục, chỉ cần mở Terminal/Command Prompt tại thư mục này).*

## Cách chạy (Usage)

### Bước 1: Khởi động Máy chủ Phân tích (C2/SOC Server)
Chạy script lõi để khởi tạo DB và mở Web Dashboard:
```bash
python drone.py
```
*Lưu ý: Script này sẽ lắng nghe trên cổng 5555 để nhận dữ liệu từ drone và cổng 9000 cho giao diện Web.*

### Bước 2: Truy cập Dashboard
Mở trình duyệt và truy cập vào:
- **URL:** [http://localhost:9000](http://localhost:9000)

### Bước 3: Chạy mô phỏng tấn công (Attacker Simulation)
Mở một cửa sổ Terminal/Command Prompt **mới** (giữ cửa sổ của `drone.py` đang chạy) và chọn 1 trong 2 cách sau:

**Cách 3.1: Chạy mô phỏng một bầy drone bị tấn công (Khuyên dùng)**
```bash
python droneflood_simulator.py 127.0.0.1 5555
```
*(Thay 127.0.0.1 bằng IP của máy chạy drone.py nếu bạn chạy trên 2 máy khác nhau).*

**Cách 3.2: Chạy mô phỏng một drone đơn lẻ (Single Node)**
```bash
python drone_client.py 127.0.0.1 5555
```

### Bước 4: Quan sát kết quả
Quay lại trình duyệt ([http://localhost:9000](http://localhost:9000)), bạn sẽ thấy đồ thị tấn công bắt đầu vẽ theo thời gian thực và các bằng chứng RE được Engine tự động bắt (trigger) và map với MITRE ATT&CK.
