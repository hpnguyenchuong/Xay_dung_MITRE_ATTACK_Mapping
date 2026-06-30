# Slide Presentation: MITRE ATT&CK Mapping for Drone Fleet Malware

## Slide 1: Tiêu đề
- Tên đề tài, tên nhóm, giảng viên hướng dẫn.

## Slide 2: Giới thiệu vấn đề
- Drone trong không gian mạng, nguy cơ bị tấn công.
- Sự cần thiết của mapping MITRE ATT&CK để phát hiện và ứng phó.

## Slide 3: Mục tiêu nghiên cứu
- Xây dựng engine mapping tự động từ RE findings.
- Đánh giá hiệu quả qua CLO5, CLO6, CLO7.

## Slide 4: Kiến trúc hệ thống
- Sơ đồ luồng dữ liệu: Client → C2 → Engine → Dashboard.

## Slide 5: Phương pháp - Rule-based Engine (CLO5)
- Cách xây dựng rule, ánh xạ artifact → kỹ thuật.
- Ví dụ cụ thể: DF_MUTEX_01 → T1547.001.

## Slide 6: Kết quả Mapping (CLO6)
- Hiển thị bảng mapping, các rule tự động sinh (YARA, Snort, Sigma).

## Slide 7: Đánh giá Ground Truth (CLO7)
- Biểu đồ Precision, Recall, F1-Score.

## Slide 8: Demo trực tiếp
- Mở Dashboard, chạy attack, xem mapping và timeline.

## Slide 9: Hạn chế và hướng phát triển
- Dữ liệu mô phỏng, thiếu dữ liệu thực tế.
- Đề xuất tích hợp ML.

## Slide 10: Kết luận
- Tóm tắt kết quả đạt được, giá trị thực tiễn.

## Slide 11: Cảm ơn
