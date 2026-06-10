# 🧪 Hướng Dẫn Chạy Thử Nghiệm Từng Kịch Bản (Scenario Testing Guide)

Phần này hướng dẫn bạn cách chạy thử nghiệm **từng kịch bản tấn công độc lập**, cách quan sát sự thay đổi trên màn hình Terminal và sự phản hồi trực tiếp trên Giao diện Web HTML.

---

## 🛠️ Chuẩn Bị Môi Trường Cố Định (Triển khai trên Máy Ảo)
Hệ thống được thiết kế để mô phỏng môi trường mạng thực tế (Mô hình Client - Server). Theo cấu hình của bạn, bạn sử dụng 2 máy ảo:

**1. Máy Ảo Kali Linux (Chạy C2 Server & Dashboard):**
- Đây là "Trung tâm điều khiển".
- Mở Terminal 1 trên Kali và chạy lệnh để khởi động Server:
   ```bash
   python drone.py
   ```
- Mở trình duyệt trên máy Kali và truy cập: **[http://localhost:8080](http://localhost:8080)** để xem giao diện Dashboard.
- Mở Terminal 2 trên Kali để chạy Trình Giả lập Bầy đàn (Simulator) khi cần test nhiều Drone. Trong lệnh, bạn điền IP là `192.168.136.141` (IP của máy Kali) để kết nối.

**2. Máy Ảo Ubuntu (Chạy Client Đơn Lẻ):**
- Mở Terminal trên máy Ubuntu. Nó đóng vai trò là một Drone duy nhất gửi dữ liệu telemetry.
- Máy ảo này sẽ kết nối đến IP của máy Kali. Gõ lệnh `ifconfig` trên Kali để xem IP (ví dụ `192.168.x.x`). Ta gọi nó là `192.168.136.141`.

Mẹo: Trước khi chuyển sang kịch bản mới, bạn nên bấm nút **Reset** trên giao diện Web để làm sạch DB lịch sử đánh giá.

---

## 1. Kịch Bản: Drone Sạch (Clean Drone)
Mục đích: Đảm bảo hệ thống nhận diện đúng drone không bị nhiễm mã độc, không sinh ra cảnh báo giả (False Positives).

**Lệnh chạy:**
```bash
python droneflood_simulator.py 192.168.136.141 5555 --scenario clean --speed demo
```

**👀 Quan sát Terminal:**
- Các drone xuất hiện trong mục `DRONE ACTIVE`.
- Cột `STATUS` sẽ là `ONLINE`, `MODE` sẽ hiển thị màu xanh là `NORMAL`.

**👀 Quan sát Giao diện HTML:**
- **Threat Score:** Giữ mức `0` (Màu xanh).
- **Fleet Health:** `100%`.
- **RE Findings:** Trống rỗng (Không có bằng chứng mã độc nào được ghi nhận).
- **MITRE Coverage:** Không có T-Code nào được bôi đỏ trong Navigator.

---

## 2. Kịch Bản: Chiếm Quyền & Nằm Vùng (Persistence Only)
Mục đích: Botnet tạo Mutex, ghi Registry/Startup Script để khởi động cùng hệ thống.

**Lệnh chạy:**
```bash
python droneflood_simulator.py 192.168.136.141 5555 --scenario persistence --speed demo
```

**👀 Quan sát Terminal:**
- Drone chuyển từ danh sách Active sang `DRONE BOT`.
- Cột `STAGE` chuyển thành màu vàng/đỏ: `PERSISTENCE`.
- Log chi tiết sẽ báo cáo: `Active Artifacts: 3` (Bao gồm: Mutex, Registry, Startup Config).

**👀 Quan sát Giao diện HTML:**
- **Evidence Chain:** Bạn sẽ thấy các bản ghi mới xuất hiện báo cáo `DF_MUTEX_01`, `DF_REG_RUN`.
- **RE Findings Panel:** Hệ thống sẽ tự động map (gán) bằng chứng Mutex/Registry vào kỹ thuật **T0866 (Unauthorized Service)** hoặc Enterprise T1547.
- **Threat Score:** Tăng lên mức `LOW` hoặc `MEDIUM`.
- **ICS Impact Matrix:** Sẽ sáng lên mục "Unauthorized Startup" hoặc "Modify Process".

---

## 3. Kịch Bản: Kênh Điều Khiển Bí Mật (Custom C2)
Mục đích: Botnet thiết lập liên lạc với máy chủ C2 qua giao thức mã hóa riêng.

**Lệnh chạy:**
```bash
python droneflood_simulator.py 192.168.136.141 5555 --scenario custom_c2 --speed demo
```

**👀 Quan sát Terminal:**
- Cột `STAGE` hiển thị: `CUSTOM C2`.
- `EFFECT` sẽ báo: `Loss of Telemetry`.
- Bằng chứng (`ART`) tăng lên `8`, do sinh thêm các dấu vết mạng (c2 domain, XOR+Base64 encoding).

**👀 Quan sát Giao diện HTML:**
- **Timeline / Alerts:** Cảnh báo đỏ về liên kết với IP/Domain C2 (VD: `c2.dronefleet.net`).
- **RE Findings Panel:** Bằng chứng `XOR+Base64` sẽ kích hoạt luật nhận diện **T1001 (Data Obfuscation)** và **T0885 (Commonly Used Port)**.
- **Recommendations Panel:** Giao diện lập tức sinh ra một đoạn mã **Snort Rule / YARA Rule** để chặn IP/Domain này. Bạn có thể copy rule đó.
- **Threat Score:** Đẩy lên mức `HIGH`.

---

## 4. Kịch Bản: Chiếm Quyền Bầy Đàn (Fleet Takeover)
Mục đích: Mã độc thực hiện cơ chế P2P lây lan lệnh điều khiển nội bộ giữa các drone.

**Lệnh chạy:**
```bash
python droneflood_simulator.py 192.168.136.141 5555 --scenario fleet_takeover --speed demo
```

**👀 Quan sát Terminal:**
- Cột `STAGE` hiển thị: `FLEET TAKEOVER`.
- Hiệu ứng: `Fleet Control Hijack`.

**👀 Quan sát Giao diện HTML:**
- **Evidence Chain:** Bắt được các hàm gọi `FLEET_SYNC`, `FLEET_COMMAND_PUSH`.
- **ICS Matrix:** Nhận diện ra hành vi đánh cắp liên lạc mạng nội bộ. Tác động lan rộng trong toàn Fleet.
- Giao diện `Campaign Intelligence` (nếu có) sẽ gộp các Drone này vào chung một cụm bị xâm phạm (Campaign: DF-2026).

---

## 5. Kịch Bản: Giả Mạo Tọa Độ (GPS Drift)
Mục đích: Mã độc can thiệp trực tiếp vào dữ liệu GPS, gửi tọa độ ảo về hệ thống điều hành để chuyển hướng bay.

**Lệnh chạy:**
```bash
python droneflood_simulator.py 192.168.136.141 5555 --scenario gps_drift --speed demo
```

**👀 Quan sát Terminal:**
- Cột `STAGE` chuyển đỏ: `GPS DRIFT`.
- **Chú ý cột GPS:** Bạn sẽ thấy tọa độ thực sự (Lat/Long) bị nhảy cóc một khoảng lớn (Drift) một cách bất thường thay vì di chuyển mượt mà.

**👀 Quan sát Giao diện HTML:**
- **RE Findings:** Thuật toán bắt được hàm `gps_spoof` và `waypoint_override` từ bộ nhớ RAM của Drone.
- **MITRE Mapping:** Lập tức map vào mã **T0831 (Manipulation of Control)** và **T0832 (Manipulation of View)** với độ tự tin cực cao (Confidence: 95%+).
- **Incident Report:** Cảnh báo **CRITICAL** vì drone đã bị khống chế phương hướng bay.

---

## 6. Kịch Bản: Phá Hoại Vật Lý (Mission Failure)
Mục đích: Mã độc vắt kiệt pin và làm nhiễu hệ thống nhiệt độ/cảm biến khiến drone rơi.

**Lệnh chạy:**
```bash
python droneflood_simulator.py 192.168.136.141 5555 --scenario mission_failure --speed demo
```

**👀 Quan sát Terminal:**
- Cột `STAGE` báo `MISSION FAILURE`.
- Cột `BATT` (Pin) bị trừ đi 5% mỗi nhịp chạy, tụt cực nhanh.
- Cột `EFFECT` hiện `Mission Failure`.
- Thông báo đỏ chót xuất hiện: `[!] BATTERY DEPLETED. DRONE OFFLINE`. Drone biến mất khỏi radar.

**👀 Quan sát Giao diện HTML:**
- **Fleet Health:** Giảm mạnh, số lượng "Drone Offline" tăng lên.
- **RE Findings:** Map kỹ thuật **T0806 (Brute Force I/O)** hoặc **Damage to Property (T0879)** vì nhận thấy hành vi battery_drain (rút pin).
- Nút **Generate Report** lúc này sẽ sinh ra báo cáo cực kỳ nghiêm trọng, khuyến nghị cách ly và thu hồi phần cứng ngay lập tức.

---

## 7. Trùm Cuối: Chiến Dịch Hoàn Chỉnh (Full Campaign)
Mục đích: Thấy được bức tranh toàn cảnh một cuộc tấn công APT diễn ra như thế nào theo trình tự thời gian.

**Lệnh chạy:**
```bash
python droneflood_simulator.py 192.168.136.141 5555 --scenario full_campaign --speed demo
```

**👀 Quan sát Terminal & HTML:**
- Drone bắt đầu ở trạng thái **Clean**.
- Sau 15 giây, Terminal chuyển drone sang **Persistence**, trên giao diện HTML bạn thấy Risk Score nhích lên 20.
- Tiếp 15 giây, chuyển sang **Custom C2**, UI hiện cảnh báo Snort Rule.
- Tiếp 15 giây, chuyển sang **GPS Drift**, UI map thẳng vào T0831, Risk Score đẩy vọt lên vùng Đỏ (Critical).
- Cuối cùng, drone cạn kiệt pin và "chết" hoàn toàn.

**Tính năng Dừng Để Đọc (Pause-After):**
Nếu diễn biến quá nhanh, bạn hãy dùng cờ `--pause-after` để hệ thống dừng lại ở giai đoạn bạn muốn quan sát:
```bash
python droneflood_simulator.py 192.168.136.141 5555 --scenario full_campaign --pause-after "Custom C2"
```
Hệ thống sẽ chạy tới khi xong `Custom C2` và bắt bạn nhấn `[ENTER]` trên terminal để chạy tiếp giai đoạn sau. Giúp bạn có đủ thời gian đọc dữ liệu phân tích trên Giao diện HTML.
