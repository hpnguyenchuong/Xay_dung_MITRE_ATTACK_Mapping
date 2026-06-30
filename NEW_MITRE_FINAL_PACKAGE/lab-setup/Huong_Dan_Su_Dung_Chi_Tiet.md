# 📚 SỔ TAY HƯỚNG DẪN SỬ DỤNG TOÀN DIỆN (ULTRA-DETAILED GUIDE)
**Dự án: Drone Fleet Malware Mapping Engine (MITRE ATT&CK ICS/Enterprise)**

Tài liệu này hướng dẫn bạn thực thi hệ thống "cầm tay chỉ việc", với các kịch bản chạy trên máy cục bộ (Localhost) và máy ảo (VM) kèm theo CÂU LỆNH CHUẨN và IP THỰC TẾ.

---

## PHẦN 1: KỊCH BẢN CHẠY TRÊN MỘT MÁY (LOCALHOST - `127.0.0.1`)
*(Khuyên dùng khi bạn đang code, test luồng hoặc muốn chạy nhanh Demo cho Giảng viên xem trực tiếp trên Laptop của bạn)*

### BƯỚC 1: BẬT MÁY CHỦ TRUNG TÂM (C2 SERVER)
- **Mục tiêu:** Mở C2 Server lắng nghe tín hiệu từ mã độc ở Port 5555 và mở Web Dashboard ở Port 9000.
- **Mở Terminal 1** (Đảm bảo đã `cd` vào thư mục gốc của dự án `NEW MITRE`).
- **Câu lệnh chạy:**
  ```bash
  python drone.py
  ```
- **Dấu hiệu thành công:** Terminal in ra màn hình:
  `[+] SOC Artifact DB Initialized`
  `[+] TCP Server listening on 0.0.0.0:5555`
  `[+] Web Dashboard running on 0.0.0.0:9000`

### BƯỚC 2: MỞ DASHBOARD THEO DÕI
- Mở trình duyệt Web (Chrome, Edge).
- Gõ chính xác URL sau: **http://127.0.0.1:9000**
- Giao diện "MITRE ATT&CK Fleet Mapping Dashboard" sẽ hiện ra. (Bản đồ ban đầu sẽ trống).

### BƯỚC 3: KÍCH HOẠT MÃ ĐỘC TỪ NẠN NHÂN (CHỌN 1 TRONG 3 CÁCH)
Mở một **Terminal 2** (Đảm bảo đã `cd` vào thư mục gốc của dự án).

**Cách 3A: Chạy mô phỏng 1 con Drone đơn lẻ (Bot Agent)**
*(Dùng để test 1 mục tiêu duy nhất).*
- **Câu lệnh chạy:**
  ```bash
  python drone_client.py 127.0.0.1 5555 --drone-id DRONE-001
  ```
- **Kết quả:** Trên trình duyệt web, Node `DRONE-001` xuất hiện, báo cáo các hành vi như "Spawning Mutex", "C2 Heartbeat", "GPS Drift".

**Cách 3B: Chạy giả lập tấn công Bầy Đàn (DroneFlood Simulator)**
*(Dùng để giả lập cùng lúc hàng chục drone bị tấn công).*
- **Câu lệnh chạy:**
  ```bash
  python droneflood_simulator.py 127.0.0.1 5555
  ```

**Cách 3C: Tấn công Bầy Đàn lặp lại liên tục (Stress Test)**
*(Dùng để bắn liên tiếp các đợt sóng tấn công, tạo ra đồ thị chằng chịt siêu đẹp cho báo cáo).*
- **Trên Windows (PowerShell):**
  ```powershell
  for ($i=1; $i -le 10; $i++) { python droneflood_simulator.py 127.0.0.1 5555; Start-Sleep -Seconds 1 }
  ```
- **Trên Mac/Linux (Bash):**
  ```bash
  for i in {1..10}; do python droneflood_simulator.py 127.0.0.1 5555; sleep 1; done
  ```

---

## PHẦN 2: KỊCH BẢN CHẠY TRÊN MÔI TRƯỜNG MÁY ẢO VM (VMWARE / VIRTUALBOX)
*(Bắt buộc khi Bảo vệ đồ án hoặc thu thập minh chứng Network Traffic bằng Wireshark)*

**Giả định thông số môi trường lab:**
1. **Máy ảo Kali Linux (Đóng vai trò Attacker & C2 Server):** IP là `192.168.136.151`.
2. **Máy ảo Ubuntu/Windows (Đóng vai trò Victim Drone):** IP là `192.168.136.160`.
*(Lưu ý: Bạn phải chỉnh mạng thành Bridged/NAT để hai máy ping thấy nhau. Hãy dùng lệnh `ipconfig` hoặc `ifconfig` để kiểm tra IP thực tế trên máy bạn, và thay thế các IP tương ứng bên dưới).*

### BƯỚC 1: KHỞI ĐỘNG C2 TRÊN MÁY KALI LINUX
- Sang máy Kali Linux (Ví dụ IP: `192.168.136.151`), mở Terminal tại thư mục chứa source.
- **Câu lệnh chạy:**
  ```bash
  python drone.py
  ```

### BƯỚC 2: MỞ DASHBOARD TỪ MÁY THẬT (HOST OS)
- Thay vì xem trên máy ảo nhỏ hẹp, bạn ra ngoài trình duyệt Chrome trên máy tính thật (Host Windows) của bạn.
- Nhập URL IP của máy Kali kèm Port 9000: **http://192.168.136.151:9000**
- Giao diện Dashboard sẽ hiện lên màn hình lớn.

### BƯỚC 3: CHẠY MÃ ĐỘC TỪ MÁY NẠN NHÂN (VICTIM)
- Chuyển sang máy ảo Victim (Ví dụ IP: `192.168.136.160`). Mở Terminal tại thư mục chứa source.
- Hãy chạy lệnh bắn thẳng mã độc về địa chỉ IP của máy Kali `192.168.136.151`:
- **Chạy Tấn công Drone đơn lẻ:**
  ```bash
  python drone_client.py 192.168.136.151 5555 --drone-id DRONE-VICTIM-99
  ```
- **Chạy Tấn công Bầy đàn:**
  ```bash
  python droneflood_simulator.py 192.168.136.151 5555
  ```

---

## PHẦN 3: HƯỚNG DẪN XÓA DỮ LIỆU & RESET TỪ ĐẦU (CLEAN START)
Trong quá trình test, nếu Dashboard đã hiển thị quá nhiều Node và bạn muốn dọn dẹp sạch sẽ để bắt đầu quay Demo video, hãy làm như sau:

1. **Tắt C2 Server:** Chuyển về Terminal 1 (đang chạy `drone.py`) và nhấn tổ hợp phím `Ctrl + C`.
2. **Xóa file Database:** Xóa file có tên là `soc_artifacts.db` nằm ở trong thư mục dự án.
   *(Trên Windows: Click chuột phải chọn Delete, Hoặc gõ lệnh: `del soc_artifacts.db`)*
3. **Chạy lại C2:** Gõ lại lệnh `python drone.py`. CSDL mới tinh sẽ tự được khởi tạo lại. Lên Web bấm `F5` tải lại trang, bản đồ sẽ hoàn toàn trống.

---

## PHẦN 4: THAO TÁC TRÍCH XUẤT MINH CHỨNG (Dành cho Final Report)

### 4.1. Cách xem và chụp chuỗi "8-Step Forensic Chain" (Minh chứng CLO5)
1. Tại Dashboard web, click vào Tab **"RE Findings / Evidence"**.
2. Tìm một dòng Log có cột `Severity` là **Critical** hoặc **High** (Màu đỏ/cam).
3. Phía góc phải của dòng đó, click vào nút biểu tượng **Kính lúp (Justification)**.
4. Một bảng điều khiển sẽ mở ra. Nó liệt kê chi tiết: Lý do phát hiện ➔ Kỹ thuật MITRE ➔ Cách tính điểm (Confidence Calculation) ➔ Tác động hệ thống ICS.
5. **Thực thi:** Chụp lại toàn bộ bảng này để đưa vào phần *Tương quan bằng chứng pháp y (Correlation)* trong Báo cáo cuối kỳ.

### 4.2. Cách xuất Rule YARA & Snort tự động (Minh chứng CLO6)
1. Trong bảng chi tiết Evidence (khi soi kỹ một hành vi "Spawning Mutex" hoặc "C2 Beacon"), bạn sẽ thấy hệ thống xuất hiện phần: **"[+] TỰ ĐỘNG SINH LUẬT BẢO VỆ:"**.
2. **Thực thi:** Hãy bôi đen copy đoạn code dạng `rule YARA_DF_Mutex_... { }` hoặc lệnh `alert tcp $EXTERNAL_NET...` vào dán trong báo cáo để chứng minh Engine có năng lực sinh luật tự động.

### 4.3. Đánh giá Toán học Ground Truth (Minh chứng CLO7)
1. Chuyển sang Tab cuối cùng **"Mapping Validation / Evaluation"**.
2. Click vào nút **"Run Validation"** (Chạy đánh giá).
3. Đọc 3 thông số vàng của thuật toán:
   - **Precision (Độ chính xác):** Tỷ lệ dự đoán trúng so với thực tế.
   - **Recall (Độ phủ):** Mức độ bắt lọt lưới mã độc.
   - **F1-Score:** Trung bình hài hòa (Thường > 0.8 là tuyệt vời).
4. **Thực thi:** Chụp màn hình thông số này đưa thẳng vào chương cuối của File Báo cáo và làm luận điểm bảo vệ thuật toán của nhóm.

---
**Chúc nhóm có một buổi bảo vệ đồ án thành công rực rỡ và giành trọn điểm A+! 🚁🛡️**
