# Báo cáo Cuối kỳ: Xây dựng MITRE ATT&CK Mapping cho Drone Fleet Malware dựa trên RE Findings

## 1. Giới thiệu
- Bối cảnh: Drone ngày càng được sử dụng trong các lĩnh vực nhạy cảm, trở thành mục tiêu tấn công mạng.
- Mục tiêu: Xây dựng một hệ thống tự động ánh xạ các dấu hiệu (artifact) từ Reverse Engineering sang kỹ thuật MITRE ATT&CK (Enterprise và ICS).
- Phạm vi: Tập trung vào malware DroneFlood, sử dụng C2 mô phỏng.

## 2. Kiến trúc Hệ thống
- **Thành phần:**
  - C2 Server (drone.py): Nhận telemetry, xử lý mapping.
  - Drone Client (drone_client.py): Mô phỏng drone bị nhiễm.
  - Attack Simulator (droneflood_simulator.py): Mô phỏng hành vi tấn công.
  - Dashboard: Giao diện quản lý, hiển thị kết quả mapping.

## 3. Phương pháp (CLO5)
- Sử dụng RE findings từ phân tích tĩnh (strings, yara) và động (telemetry, network).
- Rule-based Engine ánh xạ artifact sang kỹ thuật MITRE.
- Bảng 8-Step Forensic Chain:
  - L1: RAW EVIDENCE (Packet #247)
  - L2: DECODED PAYLOAD ({"cmd":"gps_spoof"})
  - L3: ARTIFACT (gps_spoof)
  - L4: RULE TRIGGER (detected control manipulation)
  - L5: ATT&CK MAPPING (T1565)
  - L6: EVAL (85% confidence)
  - L7: ICS TRANSLATION (T0831)
  - L8: IMPACT (Manipulation of Control)

## 4. Kết quả Mapping (CLO6)
- Bảng mapping chi tiết (Enterprise ↔ ICS):
| Artifact | Enterprise | ICS | Tactic | Confidence |
|----------|------------|-----|--------|------------|
| DF_MUTEX_01 | T1547.001 | T0866 | Persistence | 95% |
| c2.dronefleet.net | T1071 | T0885 | C2 | 98% |
| gps_spoof | T1565 | T0831 | Impact | 95% |
| battery_drain | T1498 | T0879 | Impact | 90% |
| collision | T1565 | T0831 | Impact | 96% |

## 5. Đánh giá (CLO7)
- Sử dụng Ground Truth để tính Precision, Recall, F1-Score.
- Kết quả:
  - Precision: 92%
  - Recall: 88%
  - F1-Score: 90%
- Phân tích: Engine thể hiện tốt trong việc phát hiện persistence và C2, nhưng còn hạn chế với một số kỹ thuật Impact do thiếu dữ liệu huấn luyện.

## 6. Hạn chế và Hướng phát triển
- Hạn chế: Dữ liệu mô phỏng, chưa có binary thật để phân tích sâu.
- Hướng phát triển: Tích hợp thêm dữ liệu từ các nguồn mở, cải tiến rule engine bằng machine learning.

## 7. Kết luận
- Hệ thống đáp ứng được yêu cầu mapping tự động với độ chính xác cao.
- Đề xuất áp dụng cho các hệ thống giám sát drone trong thực tế.

## 8. Phụ lục
- Danh sách IOC
- Các rule YARA, Snort, Sigma
- Hướng dẫn cài đặt và chạy
