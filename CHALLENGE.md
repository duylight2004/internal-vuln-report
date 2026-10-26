# Challenge: Internal Vulnerability Report System (IVRS)

- **Thể loại:** Web Security / Advanced SQL Injection
- **Độ khó:** Hard (SOC Tier 3 / Red Team Assessment)
- **Mục tiêu:** Thu thập cờ quản trị viên tối mật (`FLAG{...}`)

---

## 📌 Bối Cảnh (Scenario)

Bộ phận An ninh mạng nội bộ vừa đưa vào thử nghiệm cổng thông tin **IVRS (Internal Vulnerability Report System)** nhằm ghi nhận và quản lý các báo cáo lỗ hổng do các kỹ sư đệ trình.

Hệ thống được giới thiệu là "an toàn tuyệt đối" do toàn bộ các biểu mẫu đầu vào (Form Input) đều được kiểm tra nghiêm ngặt và áp dụng cơ chế Parameterized Query chuẩn mực. Các công cụ quét tự động (như `sqlmap`) hoàn toàn bất lực khi rà quét bề mặt ứng dụng.

Tuy nhiên, đội ngũ phát triển dường như đã bỏ qua một số luồng xử lý dữ liệu thứ cấp (second-order) và các thủ tục xử lý báo cáo tổng hợp ngầm bên dưới cơ sở dữ liệu.

---

## 🎯 Nhiệm Vụ Của Bạn

1. Truy cập cổng thông tin tại `http://<target-ip>:5001`.
2. Tự đăng ký một tài khoản thành viên để bắt đầu nghiên cứu bề mặt tấn công.
3. Tìm cách leo thang đặc quyền từ tài khoản thông thường (`user`) lên vai trò Kiểm duyệt viên (`reviewer`).
4. Tiếp cận khu vực Reviewer Dashboard và trích xuất cờ nhạy cảm lưu trữ trong hệ thống.

---

## 💡 Gợi Ý (Hints)

- Kiểm tra kỹ các tính năng xử lý dữ liệu sau khi người dùng đã đăng nhập (Post-Authentication features).
- Chú ý đến cấu trúc dữ liệu và các thủ tục lưu trữ (Stored Procedures) được đề cập trong tài liệu hoặc ghi chú hệ thống.
