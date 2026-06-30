# 🚁 Drone Fleet Malware Mapping Engine (Tier-5 SOC)

> **Dự án Nghiên cứu Học thuật (RBL) - FPT University Ho Chi Minh City**
> **Môn học:** IAM302T — Malware Analysis and Reverse Engineering
> **Học kỳ:** Summer 2026
> **Research Theme:** Drone Fleet Malware (Phân tích & Đảo ngược Mã độc hệ thống UAV)

---

## 📖 1. Giới thiệu Tổng quan

**Drone Fleet Malware Mapping Engine** là một hệ thống phân tích vòng đời mã độc và cảnh báo mối đe dọa tiên tiến. Thay vì chỉ dừng lại ở việc phát hiện mã độc (Black-box AI), dự án này tập trung vào việc **"Giải thích" (Explainability)**.

Hệ thống kết nối trực tiếp các bằng chứng kỹ thuật mức thấp (như Mutex, String trong Memory, Network Beacon) với những hậu quả vật lý mức cao trong mạng lưới công nghiệp (ICS/IoT) thông qua **Kiến trúc Dịch thuật 3 Cột (3-Column ICS Translation Engine)** dựa trên ma trận **MITRE ATT&CK**.

**🎯 Chuẩn đầu ra (CLO) được chứng minh trong hệ thống:**
*   **CLO5:** Liên kết tĩnh/động các dấu hiệu (Artifacts) vào MITRE ATT&CK (Enterprise & ICS) thông qua "8-Step Forensic Chain".
*   **CLO6:** Tự động hóa sinh tập luật phòng vệ (YARA, Snort, Sigma) - Đóng kín vòng lặp SOC.
*   **CLO7:** Đánh giá hiệu năng Engine bằng Ground Truth (Precision, Recall, F1-Score).

---

## 🏗️ 2. Kiến trúc Hệ thống (Architecture)

Hệ thống được mô phỏng theo mô hình 2-VMs (Client - Server) không phụ thuộc thư viện ngoài (Zero-dependency ngoài thư viện chuẩn của Python).

1.  **`drone.py` (C2 Server & Backend Engine):** Trái tim của hệ thống. Đóng vai trò máy chủ Command & Control độc hại, thu thập Telemetry từ Drone. Đồng thời nó chứa **Mapping Engine** để phân tích rủi ro và một máy chủ **HTTP Server** phát giao diện Dashboard. Sử dụng cơ sở dữ liệu `SQLite WAL-mode` để chịu tải cực cao.
2.  **`drone_client.py` (Victim Agent):** Mô phỏng một chiếc Drone đang chạy phần mềm điều khiển bị nhiễm mã độc. Nhiệm vụ của nó là liên tục gửi gói tin Telemetry (nhịp tim, GPS, pin) về C2.
3.  **`droneflood_simulator.py` (Attack Simulator):** Công cụ Stress-test. Giả lập một bầy đàn (Swarm) hàng chục/hàng trăm Drone cùng bị nhiễm mã độc và gửi dữ liệu về C2 cùng một lúc, gây bão mạng.
4.  **`templates/` (Frontend React SPA):** Giao diện Web động được viết bằng HTML/React/Babel, chia làm 42 components để render mượt mà biểu đồ Radar, Node Map và Bảng Pháp y.

---

## ⚡ 3. Tính năng Cốt lõi

### A. Chuỗi Phân tích Pháp y 8-Bước (8-Step Forensic Chain)
Hệ thống không kết luận bừa. Mọi quyết định cảnh báo đều đi qua luồng:
1️⃣ `Raw Packet` ➔ 2️⃣ `Decoded JSON` ➔ 3️⃣ `Forensic Artifact` ➔ 4️⃣ `Rule Trigger` ➔ 5️⃣ `Enterprise MITRE` (e.g. T1565) ➔ 6️⃣ `Confidence Score` (Tính toán linh động) ➔ 7️⃣ `ICS Translation` (e.g. T0831) ➔ 8️⃣ `ICS Impact`.

### B. Tự Động Sinh Luật (Automated Rule Generation)
Khi mã độc thực hiện hành vi, hệ thống trích xuất IOCs và điền vào các bộ luật chuẩn công nghiệp trong thư mục `detection/`:
*   **YARA (`yara_rules.yar`):** Quét bộ nhớ tĩnh (Strings, API Calls, XOR payload).
*   **Snort (`snort_rules.rules`):** Bắt chính xác payload mạng (FLEET_SYNC).
*   **Sigma (`sigma_rules.yml`):** Phát hiện qua Sysmon (Tạo Mutex, Mở Network Connection).

---

## ⚙️ 4. Hướng dẫn Cài đặt & Triển khai (Setup Guide)

### 📌 Yêu cầu hệ thống:
*   Python 3.8 trở lên.
*   Trình duyệt Web hiện đại (Chrome/Edge/Firefox).
*   Không cần `pip install` bất kỳ thư viện ngoài nào!

### 📌 Triển khai cục bộ (Chạy thẳng trên Windows/Mac):
1. Giải nén thư mục dự án `NEW_MITRE_FINAL_PACKAGE`.
2. Mở Terminal / Command Prompt tại thư mục dự án.
3. Đảm bảo port `5555` (C2) và `8080` (Web Dashboard) không bị chiếm dụng.

*(Nếu muốn chạy trên 2 máy ảo VM khác nhau, hãy sửa chuỗi `"localhost"` thành IP của máy ảo chứa file `drone.py` trong `drone_client.py` và `droneflood_simulator.py`)*

---

## 🚀 5. Hướng dẫn Demo Chạy Thực Tế (Kịch bản Bảo vệ Đồ án)

Đây là các bước chuẩn xác nhất để bạn có thể báo cáo và trình diễn (Live Demo) mượt mà trước Hội đồng Giám khảo:

### BƯỚC 1: Khởi động Trái tim Hệ thống (C2 Server)
*   Khuyên dùng: Xóa file `soc_artifacts.db` (nếu có) trước khi demo để có cơ sở dữ liệu sạch sẽ hoàn toàn.
*   Trên Terminal 1, chạy lệnh:
    ```bash
    python drone.py
    ```
*   *Kết quả mong đợi:* Terminal in ra "SOC Engine & C2 Server running on 0.0.0.0:5555" và "Dashboard GUI available at http://localhost:8080".

### BƯỚC 2: Mở Giao diện Giám sát SOC (Web Dashboard)
*   Mở trình duyệt, truy cập: `http://localhost:8080`
*   Bạn sẽ thấy giao diện React load lên cực nhanh. Hiện tại bảng dữ liệu sẽ trống.

### BƯỚC 3: Mô phỏng Nạn nhân thứ 1 (Single Drone Attack)
*   Trên Terminal 2, chạy một Client đơn lẻ:
    ```bash
    python drone_client.py
    ```
*   *Hành động trên Dashboard:* 
    * Chuyển sang Tab **"Evidence Board"** hoặc **"Drone Lifecycle"**.
    * Bạn sẽ thấy chiếc Drone đầu tiên xuất hiện. Mã độc sẽ tự động thực hiện các hành vi như sinh Mutex, gọi C2. Các khung MITRE Tactic sẽ dần hiện lên (Persistence, C2, v.v.).

### BƯỚC 4: Kích hoạt Chiến dịch Tấn công Bầy đàn (The DroneFlood Simulation)
*   Để trình diễn khả năng chịu tải của SQLite WAL Mode và Thread-locks, tắt Terminal 2 (Ctrl+C).
*   Trên Terminal 3, khởi động cuộc tấn công quy mô lớn:
    ```bash
    python droneflood_simulator.py
    ```
*   *Hành động trên Dashboard:*
    * Chuyển sang Tab **"Attack Map"**: Bạn sẽ thấy bản đồ mạng (Node Map) bùng nổ với hàng chục drone nối về máy chủ C2 (Node đỏ trung tâm).
    * Biểu đồ Radar sẽ mở rộng mạnh về hướng "Impact" và "C2".
    * Click biểu tượng "Kính lúp" (Justification) trên bất kỳ cảnh báo nào trong bảng Mapping log để hiển thị chi tiết **Chuỗi 8-bước giải thích**. (Minh chứng CLO5).

### BƯỚC 5: Chứng minh Khả năng Đánh giá & Tự phòng thủ
*   Chuyển sang Tab **"Mapping Validation"** trên Dashboard.
*   Hiển thị chỉ số F1-Score (CLO7). (Nhờ cấu hình chuẩn Ground Truth, điểm F1 sẽ rất cao > 90%).
*   Mở thư mục `detection/` bằng VS Code. Chiếu cho Giảng viên xem các file `yara_rules.yar` và `snort_rules.rules` để chứng minh hệ thống có thể tạo luật phòng vệ dựa trên IOCs thu được (Minh chứng CLO6).

---

## 📁 6. Cấu trúc Thư mục (Directory Structure)

```text
NEW_MITRE_FINAL_PACKAGE/
│
├── drone.py                    # C2 Server, Rule Engine, Web API & SQLite DB Handler
├── drone_client.py             # Victim Agent giả lập 1 drone bị nhiễm malware
├── droneflood_simulator.py     # Tự động hóa spawn nhiều Agent tạo tải tấn công
├── README.md                   # Tài liệu hướng dẫn sử dụng siêu chi tiết
│
├── datasets/
│   ├── ground_truth.json       # Chân lý để chấm điểm hiệu suất Engine (CLO7)
│   ├── strings_drone.csv       # Dữ liệu phục vụ trích xuất YARA
│   └── *_case.json             # Dữ liệu mô phỏng Time-series (Negative/Positive)
│
├── detection/                  # Nơi xuất bộ luật tự động sinh ra (CLO6)
│   ├── iocs.txt                # Danh sách Hashes, IPs, Domains
│   ├── sigma_rules.yml         # Luật Sysmon (Network & Mutex)
│   ├── snort_rules.rules       # Luật quét gói tin DPI
│   └── yara_rules.yar          # Luật quét file nhị phân & bộ nhớ
│
└── templates/                  # Bộ UI Dashboard React SPA cực mượt (42 files)
    ├── index.html              # Trang gốc Root mount
    ├── App.html                # Main React Component
    └── ...                     # Các Components hiển thị bảng, biểu đồ Radar
```

---

*Hệ thống được phát triển với niềm đam mê sâu sắc dành cho kiến trúc bảo mật Hệ thống Điều khiển Công nghiệp (ICS). Chúc các bạn bảo vệ Đồ án thành công rực rỡ!* 🎖️
