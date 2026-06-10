# 📖 Hướng Dẫn Sử Dụng Toàn Tập: Drone Fleet Malware Mapping Engine

Tài liệu này cung cấp hướng dẫn chi tiết nhất về cách vận hành hệ thống, các lệnh Python, cách tương tác với giao diện Web (Dashboard) và cách xuất/xem các báo cáo an toàn thông tin.

---

## 1. 🚀 Tất Cả Các Lệnh Chạy Code Python

Hệ thống bao gồm 3 thành phần script chính. Để có trải nghiệm đầy đủ, bạn cần mở **ít nhất 2 cửa sổ Terminal (Command Prompt / PowerShell)**.

### 1.1 Khởi động Mapping Engine & Web Server (Bắt buộc)
Lệnh này là trái tim của hệ thống. Nó sẽ khởi động Rule Engine phân tích, cơ sở dữ liệu In-Memory/SQLite, và Web UI ở port `8080`, đồng thời mở port C2 (thường là `5555`) để lắng nghe drone.

**🖥️ Chạy trên: Máy ảo Kali Linux**

```bash
python drone.py
```
> [!NOTE]
> Màn hình terminal chạy lệnh này sẽ bị chiếm dụng bởi **Terminal Dashboard**. Cứ mỗi 2 giây, nó sẽ tự động cập nhật và hiển thị danh sách Drone đang bay:
> - **DRONE ACTIVE**: Danh sách drone sạch (Pin, Tọa độ GPS, Độ cao, Tốc độ).
> - **DRONE BOT**: Danh sách drone đã bị lây nhiễm (Kèm theo tên mã độc, số lượng Artifacts sinh ra, và giai đoạn của chiến dịch tấn công).

### 1.2 Chạy Trình Giả Lập Chiến Dịch Tấn Công (Fleet Simulator)
Mở một cửa sổ Terminal **mới**, dùng lệnh này để tạo ra hàng loạt drone bay giả lập, tự động thực hiện các hành vi mã độc để đưa dữ liệu về Engine phía trên.

**🖥️ Chạy trên: Máy ảo Kali Linux (Cùng máy với `drone.py`)**

```bash
python droneflood_simulator.py 127.0.0.1 5555 [các-tùy-chọn]
```
**Các tham số quan trọng:**
- `<c2_ip>`: Sử dụng `127.0.0.1` vì bạn đang chạy simulator trên cùng máy Kali với server.
- `[c2_port]`: Cổng C2 (Mặc định là `5555`, bạn có thể bỏ trống).
- `--scenario`: Kịch bản tấn công. Có thể chọn: `clean`, `persistence`, `custom_c2`, `fleet_takeover`, `gps_drift`, `mission_failure`, hoặc `full_campaign` (Mặc định).
- `--speed`: Tốc độ chạy giả lập: `fast` (Nhanh), `demo` (Vừa phải để xem), `slow` (Chậm). Mặc định là `demo`.
- `--repeat`: Số vòng lặp của chiến dịch.
- `--pause-after`: Tạm dừng sau một giai đoạn nhất định (VD: `--pause-after Persistence`).
- `--verbose`: In ra chi tiết toàn bộ telemetry log trong Terminal.

**Ví dụ thực tế khuyên dùng:**
```bash
python droneflood_simulator.py 127.0.0.1 5555 --scenario full_campaign --repeat 5 --speed demo
```

### 1.3 Chạy Drone Client Đơn Lẻ (Nâng cao/Tùy chọn)
Nếu bạn muốn thử nghiệm độc lập một bot dựa trên dữ liệu JSON định sẵn (thay vì tự sinh ngẫu nhiên):

**🖥️ Chạy trên: Máy ảo Ubuntu**

```bash
python drone_client.py 192.168.136.141 5555 --playback datasets/clean_case.json
```
*(Trong đó `192.168.136.141` chính là IP của máy Kali).*

---

## 2. 📊 Cách Xem Báo Cáo Trên Giao Diện (Dashboard)

Sau khi Server (`drone.py`) đã chạy, hãy mở trình duyệt Web (Chrome/Edge/Firefox) và truy cập:
👉 **[http://localhost:8080](http://localhost:8080)**

Giao diện Web được thiết kế theo dạng lưới (Bento-Grid), bạn có thể xem các báo cáo như sau:

### 2.1 Báo Cáo Sự Cố Chi Tiết (Incident Report HTML)
- Hệ thống tự động tạo báo cáo cho từng Drone khi phát hiện có mã độc.
- Trên giao diện sẽ có các nút/liên kết liên quan đến Drone ID (hoặc thông qua tính năng Generate Report của bảng điều khiển).
- Khi hệ thống phân tích xong, một file báo cáo HTML sẽ được sinh ra (Ví dụ: `reports/incident_report_DRONE-1234.html`). Bạn có thể click trực tiếp trên UI để xem.
- **Nội dung Báo cáo:** Phán quyết cuối cùng (Severity), Tác động đến môi trường Công nghiệp (ICS Impact), Các IOCs (IP, Mutex, Registry), Bằng chứng dịch ngược (RE Findings), và Khuyến nghị cách ly/phục hồi.

### 2.2 Xuất Báo Cáo Ra MITRE ATT&CK Navigator
- Tìm tính năng **Navigator Export** trên giao diện Web.
- Khi Click vào, hệ thống sẽ tự động tải xuống một file JSON (VD: `navigator_2026xxxx_xxxxxx.json`).
- **Cách xem:** Truy cập trang web [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/), chọn **"Open Existing Layer" -> "Upload from local"** và tải file vừa nhận được lên. Bạn sẽ thấy một ma trận nhiệt hiển thị chính xác các kỹ thuật (Techniques) mà mã độc đã sử dụng (T0885, T0832...).

### 2.3 Xuất Báo Cáo Mối Đe Dọa (STIX Bundle)
- Tìm tính năng **STIX Export** trên giao diện.
- File tải về (`stix_bundle_xxxx.json`) chứa các mẫu IOCs theo chuẩn STIX 2.1, dùng để import vào các nền tảng chia sẻ thông tin đe dọa như MISP hoặc OpenCTI.

---

## 3. 🕹️ Mọi Thứ Có Thể Tương Tác Được

Hệ thống cung cấp tính tương tác thời gian thực cao. Bạn hãy chú ý đến các Panel sau:

1. **Bảng Điều Khiển Tổng Quan (Fleet Health / Campaign Intelligence):**
   - **Tương tác:** Theo dõi số liệu thay đổi liên tục. Xem danh sách "Top Dangerous Nodes" để biết drone nào đang bị chiếm quyền nghiêm trọng nhất (Điểm Risk Score càng cao, hiển thị màu Đỏ/Cam).

2. **Dòng Thời Gian Tấn Công (Evidence Chain / Timeline):**
   - **Tương tác:** Cuộn chuột để xem các dòng log chạy liên tục. Bạn có thể quan sát quá trình hệ thống từ lúc phát hiện Registry Key đến việc map nó vào MITRE T-Code.

3. **Bảng Bằng Chứng Dịch Ngược (RE Findings / Evidence Correlation):**
   - **Tương tác:** Theo dõi các dòng dữ liệu với thuộc tính *Confidence* (Độ tin cậy). Bạn sẽ thấy hệ thống giải thích rõ ràng "Tại sao lại map Technique này?" (Ví dụ: Tìm thấy Mutex -> Suy ra Persistence -> Map vào T0866).

4. **Bảng Đánh Giá Độ Chính Xác (Evaluation Metrics / Validation Panel):**
   - **Tương tác:** Bảng này sẽ tự động chạy thuật toán so sánh với dữ liệu Ground Truth. Bạn có thể quan sát các chỉ số **Accuracy**, **Precision**, **Recall** và **F1-Score** tự động điều chỉnh khi có mẫu mới được phát hiện, qua đó thể hiện độ chính xác của hệ thống.

5. **Luật Đề Xuất & Khuyến Nghị (Recommendations Panel):**
   - **Tương tác:** Bạn có thể copy trực tiếp các **Snort Rule** hoặc **YARA Rule** được hệ thống tự động sinh ra dựa trên IOCs bắt được (VD: Rule chặn kết nối đến C2 IP), dùng để áp dụng ngay cho Firewall.

6. **Tính Năng Reset (Xóa Lịch Sử):**
   - **Tương tác:** Sử dụng nút Reset trên giao diện (nếu có). Hành động này sẽ gửi API `/reset` để làm sạch toàn bộ CSDL tấn công, cho phép bạn bắt đầu giả lập một chiến dịch mới mà không cần tắt mở lại Python Server.
