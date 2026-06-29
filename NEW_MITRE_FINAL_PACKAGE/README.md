<div align="center">
  <img src="https://img.icons8.com/color/96/000000/drone.png" alt="Drone Icon" width="120"/>
  
  # 🚁 Drone Fleet Malware Mapping Engine
  
  ### 🛡️ Nền tảng Phân tích & Ánh xạ Threat Intelligence mức Tier-5 (ICS/IoT)
  
  [![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
  [![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-v14.0-ff6666.svg?style=for-the-badge&logo=mitre)](https://attack.mitre.org/)
  [![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

  <p align="center">
    <em>Nền tảng nghiên cứu chuyên sâu giúp phân tích các bằng chứng dịch ngược (RE Artifacts) từ mã độc tấn công bầy drone (DroneFlood) và ánh xạ tự động vào ma trận MITRE ATT&CK Enterprise & ICS. Đáp ứng chuẩn đầu ra CLO5, CLO6, CLO7.</em>
  </p>
</div>

---

## 📌 Tổng quan dự án (Project Overview)

Dự án này là một **Explainable Mapping Engine (Công cụ ánh xạ có khả năng giải thích)** được thiết kế chuyên biệt cho hệ thống IoT và Hệ thống điều khiển công nghiệp (ICS). Dự án giải quyết bài toán phức tạp trong an toàn thông tin: *Làm thế nào để liên kết các bằng chứng kỹ thuật số ở mức thấp (network packets, memory offsets, mutices) thu thập được từ phân tích mã độc (Reverse Engineering - RE) với các tác động vận hành vật lý ở mức cao đối với một bầy drone (Drone Fleet).*

Khác với các hệ thống phân loại AI "hộp đen" (Black-box), hệ thống này sử dụng một **Candidate Competition Rule Engine** mang tính xác định (deterministic). Mọi quyết định ánh xạ từ bằng chứng số sang kỹ thuật tấn công (Technique) đều được chấm điểm (Confidence Score), đưa ra lý do (Justification) và tạo thành chuỗi bằng chứng rõ ràng.

### 🎯 Trọng tâm Học thuật (Course Learning Outcomes)

Dự án này được thiết kế và xây dựng để đáp ứng các chuẩn đầu ra (CLO) cực kỳ khắt khe của môn học/nghiên cứu:

- **📍 CLO5 - Tương quan bằng chứng RE (RE Artifact Correlation):** Thiết lập chuỗi suy luận 8 bước (8-Step Forensic Chain) từ dữ liệu thô (Raw packet) cho đến Hậu quả ICS (ICS Impact), giúp xóa bỏ khoảng trống ngữ nghĩa (Semantic gap) giữa mã độc và vận hành vật lý.
- **📍 CLO6 - Máy tạo luật tự động (Automated Rule Generation Engine):** Khả năng tự động sinh ra các rules phát hiện mối đe dọa dựa trên RE findings (Snort Rules cho Network và YARA Rules cho Host/Mutex).
- **📍 CLO7 - Đánh giá độ chính xác (Ground Truth Evaluation Metrics):** Tích hợp công cụ đánh giá bằng toán học, tính toán trực tiếp các chỉ số **Precision, Recall, F1-Score** bằng cách đối chiếu kết quả Mapping của Engine với tập dữ liệu gốc (Ground Truth).

---

## ✨ Tính năng chi tiết & Động cơ (Core Capabilities)

### 1. 8-Step Forensic Chain (Chuỗi điều tra số 8 bước)
Đảm bảo tính "Explainable" (có thể giải thích được) tuyệt đối. Khi hệ thống phát hiện 1 bất thường, nó không chỉ cảnh báo mà còn vạch ra toàn bộ lộ trình:
`Raw Packet ➜ Decoded JSON ➜ Artifact (Dấu vết) ➜ Rule Trigger ➜ MITRE Technique ➜ Confidence (Độ tin cậy) ➜ ICS Translation (Biên dịch sang ICS) ➜ ICS Impact (Tác động vật lý)`.

### 2. 3-Column ICS Translation Engine (Động cơ biên dịch ICS 3 cột)
Các chiến thuật IT thông thường (như *C2 Beaconing - T1071*) sẽ được Engine tự động dịch sang:
- **Cyber-Physical Drone Effects:** Tác động trực tiếp lên drone (VD: Chiếm kênh điều khiển từ xa).
- **ICS Consequences:** Hậu quả đối với hệ thống công nghiệp (VD: *Loss of Control, Loss of View, Navigation Deviation*).

### 3. Dynamic Attack Graphing (Đồ thị tấn công động)
Bảng điều khiển (Dashboard) sử dụng SVG/Flexbox thuần để vẽ trực tiếp đường đi của các cuộc tấn công theo thời gian thực dựa trên lịch sử Mapping, giúp dễ dàng hình dung Campaign của mã độc.

### 4. Hệ thống tính điểm rủi ro bầy (Segmented Threat Scoring)
Mỗi Drone sẽ được gán một mức độ rủi ro (Threat Score) từ 0-100 dựa trên các cuộc tấn công đang phải hứng chịu. Rủi ro được phân rã thành: Rủi ro mất điều khiển, Suy giảm nhiệm vụ, Thiệt hại tài sản.

---

## 🏗️ Kiến trúc hệ thống (System Architecture)

Hệ thống được thiết kế theo hướng Micro-architecture nhẹ nhàng và mô-đun hóa:

1. **`drone.py` (Core Analysis Engine & API Gateway):** Trái tim của hệ thống. File này tiếp nhận dữ liệu từ xa (Telemetry), xử lý RE findings qua Rule Engine nhiều bước (Multi-stage), lưu trữ vào cơ sở dữ liệu SQLite (`soc_artifacts.db`) và chạy một Web Server (Cung cấp REST APIs và Dashboard).
2. **`drone_client.py` (Bot Agent):** Giả lập một Drone độc lập đã bị xâm nhập. Kịch bản của Bot bao gồm việc gửi các gói tin C2 Heartbeat giả mạo và thay đổi các trạng thái vật lý (GPS drift, Altitude drop) theo lệnh C2.
3. **`droneflood_simulator.py` (Threat Simulator):** Chương trình giả lập toàn bộ một chiến dịch tấn công (Campaign) nhắm vào một "Bầy drone" (Fleet). Nó điều phối vòng đời xâm nhập từ *Persistence* ➜ *Custom C2* ➜ *Fleet Takeover*.
4. **`templates/` (Tier-5 SOC Dashboard):** Giao diện Single Page Application (SPA) viết bằng HTML/JS/TailwindCSS (Nhúng Babel/React) được cung cấp thông qua Web Server của `drone.py`.

---

## 🚀 Hướng dẫn Triển khai & Chạy Code Kỹ thuật (Advanced Execution Guide)

### 1. Chuẩn bị Môi trường (Environment Setup)

Hệ thống được thiết kế với tiêu chí **Zero-dependency** (Không phụ thuộc thư viện ngoài), chỉ sử dụng thư viện chuẩn của Python. Môi trường yêu cầu duy nhất là **Python 3.10+**. 

Để mô phỏng môi trường tấn công thực tế (Network Simulation), bạn nên chuẩn bị kiến trúc máy ảo (VM) như sau:
*   **Máy ảo 1 (SOC / Defender - VD: Ubuntu hoặc Windows):** Đóng vai trò là Trung tâm điều hành. Nơi này sẽ chạy `drone.py` để hứng dữ liệu, phân tích mã độc và cung cấp Dashboard hiển thị.
*   **Máy ảo 2 (Attacker / Compromised Fleet - VD: Kali Linux):** Đóng vai trò là bầy drone bị nhiễm mã độc. Nơi này sẽ chạy `droneflood_simulator.py` hoặc `drone_client.py` để bắn các gói tin tấn công và C2 Heartbeat về Máy ảo 1.
*   **Cấu hình mạng:** Thiết lập mạng dạng **Bridged** hoặc **NAT Network** để 2 máy ảo có thể ping và giao tiếp qua lại với nhau (Đảm bảo máy Defender mở port TCP `5555` và `9000`).

### 2. Các bước đầu tiên (First Steps)

1.  Clone toàn bộ mã nguồn về cả 2 máy ảo (hoặc tải ZIP):
    ```bash
    git clone https://github.com/hpnguyenchuong/Xay_dung_MITRE_ATTACK_Mapping.git
    cd Xay_dung_MITRE_ATTACK_Mapping
    ```
2.  Kiểm tra phiên bản Python trên máy: `python --version` (đảm bảo >= 3.10).
3.  Không cần chạy `pip install` vì mã nguồn đã được tối ưu hoàn toàn độc lập (Zero-dependency).

### 3. Khởi động Máy chủ Phân tích (Mapping Engine)

Trên **Máy ảo 1 (SOC/Defender)**, hãy khởi động lõi phân tích bằng lệnh:
```bash
python drone.py
```
*(Hệ thống sẽ tự động tạo CSDL `soc_artifacts.db`, mở TCP Server ở port `5555` để nhận tín hiệu drone, và mở Web Dashboard ở port `9000`).*

### 4. Các kịch bản chạy Mô phỏng (Simulator & Bot Agent)

Trên **Máy ảo 2 (Attacker)**, bạn có nhiều cách để khởi tạo tín hiệu mã độc. (Giả sử IP của Máy 1 là `192.168.1.100`):

**Cách 4.1 - Khởi chạy một chiến dịch bầy đàn (DroneFlood Campaign)**
Chạy script giả lập bầy drone bị nhiễm:
```bash
python droneflood_simulator.py 192.168.1.100 5555
```
*(Nếu chạy tất cả trên cùng một máy, hãy thay IP thành `127.0.0.1`)*

**Cách 4.2 - Mô phỏng tấn công bền bỉ (Persistent Threat)**
Nếu bạn muốn giả lập nhiều làn sóng tấn công liên tục (để test khả năng chịu tải của Rule Engine), hãy dùng vòng lặp bash:
```bash
# Dành cho Linux/Mac
for i in {1..5}; do python droneflood_simulator.py 192.168.1.100 5555; sleep 2; done
```

**Cách 4.3 - Chạy một Node riêng lẻ (Single Bot Agent)**
Nếu bạn muốn theo dõi vòng đời tấn công của một con Drone đơn duy nhất khi bị C2 chiếm quyền, hãy dùng `drone_client.py`:
```bash
python drone_client.py 192.168.1.100 5555 --drone-id DRONE-ALPHA-01
```

### 5. Truy cập Dashboard Phân tích
Trở lại **Máy ảo 1 (SOC/Defender)** (hoặc bất kỳ máy nào cùng mạng), mở trình duyệt web và truy cập vào địa chỉ:
> 🌐 **http://192.168.1.100:9000** (Hoặc `http://localhost:9000` nếu chạy cục bộ)

---

## 📊 Hướng dẫn Quan sát sự thay đổi trên Dashboard

Khi dữ liệu từ Simulator (`droneflood_simulator.py`) bắt đầu đổ về Engine (`drone.py`), bạn hãy truy cập `http://localhost:9000` để trực tiếp quan sát những thay đổi sau theo thời gian thực (Real-time):

### 1. Quan sát Bản đồ Nodes & Đồ thị tấn công (Dynamic Attack Graph)
- Ngay khi Simulator chạy, bạn sẽ thấy các chấm (Nodes) đại diện cho Drone xuất hiện.
- Các Node **Màu Xanh lá (Clean)** là các drone bình thường.
- Khi một Drone bắt đầu chuyển sang **Màu Cam (Suspicious)** hoặc **Đỏ (Compromised/Critical)**, hãy click vào Node đó!
- **Đồ thị Tấn công (Attack Graph):** Bên dưới Node sẽ vẽ ra một chuỗi đồ thị cho thấy mã độc đã đi qua các bước nào (ví dụ: *Initial Access -> Execution -> C2*).

### 2. Quan sát Chuỗi 8-Step Forensic Chain (Tại RE Evidence Panel)
- Click vào tab hoặc khu vực hiển thị **"RE Findings / Evidence"**.
- Khi một gói tin chứa dấu hiệu C2 (Custom C2 heartbeat) gửi lên, bạn sẽ thấy Rule Engine ngay lập tức "bắt" (Trigger) được nó.
- Hãy bấm vào nút **"Justification" (Lý do)** hoặc biểu tượng kính lúp bên cạnh mỗi Alert. Một bảng điều khiển sẽ trượt ra (Drawer/Panel) hiển thị rõ ràng: 
  * "Tại sao hệ thống lại cho rằng đây là T1071?" 
  * "Độ tin cậy (Confidence) được cộng như thế nào (từ Evidence +20, Mapping Reason +15, v.v.)?"

### 3. Quan sát ICS Translation (Tại Incident Report / Dashboard)
- Khi một kỹ thuật MITRE Enterprise được xác nhận (ví dụ `T1547 - Boot or Logon Autostart Execution`), hãy quan sát cột **ICS Impact** (hoặc bảng dịch ICS).
- Bạn sẽ thấy hệ thống tự động sinh ra các cảnh báo như: `[ICS] Loss of Control` hoặc `[ICS] Manipulation of Control`. Đây chính là "3-Column ICS Translation Engine" đang hoạt động.

### 4. Quan sát Việc tự động sinh luật - CLO6 (Rule Generation)
- Trong phần chi tiết của Evidence hoặc trong Logs, khi hệ thống phân tích ra một Mutex lạ (Ví dụ: `DF_MUTEX_01`) hoặc chuỗi Hardcoded IP, hệ thống sẽ đề xuất các đoạn mã (snippets) **Snort Rule** và **YARA Rule**. Điều này minh chứng cho CLO6 (Automated Rule Generation).

### 5. Quan sát Metrics Đánh giá Ground Truth - CLO7 (Evaluation Dashboard)
- Chuyển sang Tab đánh giá (Mapping Validation / Evaluation).
- Bạn sẽ thấy các con số **Accuracy, Precision, Recall, F1-Score** thay đổi khi hệ thống Mapping đối chiếu kết quả dự đoán (Predicted Techniques) với dữ liệu thực tế (Expected Techniques) được gán nhãn từ trước (được nạp sẵn từ Ground Truth).
- Độ chính xác thể hiện mức độ hiệu quả của Candidate Competition Rule Engine so với nhãn gốc (Ground Truth).

### 6. Cảnh báo thời gian thực & Threat Scoring
- Góc trên cùng của Dashboard luôn cập nhật **Tổng số Drone bị nhiễm (Critical Risk Drones)**.
- Khi các Drone có Score > 80, biểu đồ Health Trend sẽ kéo thanh màu đỏ lên cao.
- **Incident Report:** Engine cũng tự động tạo ra báo cáo HTML chi tiết lưu trong thư mục `reports/` cho mỗi Drone bị thỏa hiệp, ghi rõ các bước Incident Response (Phản ứng sự cố) cần làm.

---
<div align="center">
  <b>Phát triển cho Nghiên cứu Học thuật chuyên sâu về Cybersecurity, Bảo vệ ICS & Threat Intelligence.</b>
</div>
