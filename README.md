# 🛡️ Trạm Hỷ — Internal Vulnerability Report System (IVRS)

> **Category:** Web Security / Advanced SQL Injection  
> **Difficulty:** Hard (SOC Tier 3 / Red Team Assessment)  
> **Target:** 2 Sequential Flags (`FLAG{...}`)  
> **Author:** Nguyễn Duy Quang (HE181202) — Cyber Security & SOC Tier 3

---

## 📌 Tổng Quan Thách Thức (Overview)

**IVRS (Internal Vulnerability Report System)** là cổng thông tin tiếp nhận và quản lý báo cáo sự cố an toàn thông tin nội bộ của hệ thống **Trạm Hỷ**. 

Toàn bộ các biểu mẫu đầu vào vòng ngoài (Form Input `/register`, `/login`) đều được áp dụng chuẩn mực **Parameterized Query / Prepared Statements**, khiến các công cụ quét tự động (như `sqlmap`) hoàn toàn bất lực. Tuy nhiên, luồng xử lý dữ liệu thứ cấp (Second-Order) và các thủ tục lưu trữ tổng hợp ngầm (Stored Procedures) bên dưới cơ sở dữ liệu lại tiềm ẩn các lỗ hổng nghiêm trọng cho phép kẻ tấn công leo thang đặc quyền và chiếm đoạt bí mật hệ thống.

```
[Attacker / Player]
       │
       ▼ (HTTP Port 5001 -> Container 5000)
┌──────────────────────────────────────────────┐
│ Flask Web Application (Python 3.12)          │
│ - PyMySQL with CLIENT.MULTI_STATEMENTS       │
│ - Parameterized Insert at /register          │
│ - String Concatenation SQL at /export        │
│ - Procedure Call with raw input at /dashboard│
└──────────────────────┬───────────────────────┘
                       │ (MySQL Protocol Port 3306)
                       ▼
┌──────────────────────────────────────────────┐
│ MariaDB 10.11 Engine                         │
│ - Table: users (id, username, role, ...)     │
│ - Table: reports (id, user_id, title, ...)   │
│ - Table: admin_secrets (id, flag)            │
│ - Procedure: GetTopReporter(sortCol)         │
└──────────────────────────────────────────────┘
```

---

## 🚀 Khởi Động Nhanh (Quick Start)

Yêu cầu máy tính đã cài đặt **Docker** và **Docker Compose**:

```bash
# 1. Clone repository
git clone https://github.com/duylight2004/internal-vuln-report.git
cd internal-vuln-report

# 2. Tạo SECRET_KEY ngẫu nhiên (bắt buộc, file .env đã được gitignore)
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" > .env

# 3. Khởi động môi trường challenge
docker compose up --build -d

# 4. Mở trình duyệt và truy cập:
# http://localhost:5001
```

Để dừng môi trường:
```bash
docker compose down -v
```

---

## 🎯 Chuỗi Khai Thác 2 Giai Đoạn (2-Act Attack Chain)

| Act | Tên Lỗ Hổng | Bề Mặt Tấn Công | Mục Tiêu & Kết Quả |
| :---: | :--- | :--- | :--- |
| **Act 1** | **Second-Order Stacked Query SQLi** | `/register` ➔ `/export` | Tận dụng driver `CLIENT.MULTI_STATEMENTS` kích hoạt câu lệnh `UPDATE` lồng nhau qua tính năng xuất log &rarr; Leo quyền từ `user` lên `reviewer` &rarr; Nhận **Flag 1**. |
| **Act 2** | **Dynamic SQL in Stored Procedure** | `/dashboard?sort=...` | Khai thác tham số động truyền vào thủ tục lưu trữ `GetTopReporter` &rarr; UNION-based injection vào bảng `admin_secrets` &rarr; Nhận **Flag 2**. |

---

## ⚔️ Kiểm Thử Khai Thác Tự Động (Automated Exploit)

Trong thư mục `exploits/` đã chuẩn bị sẵn mã khai thác full-chain mẫu:

```bash
# Cài đặt thư viện requests
pip install requests

# Chạy PoC tự động giải trọn vẹn cả 2 Flag
python exploits/solve_all.py http://localhost:5001
```

**Kết quả mong đợi:**
```text
[*] Target URL: http://localhost:5001
[*] Generated exploit username: r_xxxx';UPDATE users SET role='reviewer';#
[*] [Act 1] Registering malicious user...
[*] [Act 1] Logging in...
[+] Logged in successfully.
[*] [Act 1] Triggering second-order SQLi via POST /export...
    Export response status: 200
[+] [Act 1 SUCCESS] Flag 1: FLAG{s3c0nd_0rd3r_st4ck3d_qu3ry_pwn3d}
[+] [Act 1 SUCCESS] Elevated to Reviewer! Dashboard access granted.
[*] [Act 2] Injecting into stored procedure GetTopReporter via sort parameter...
[+] [Act 2 SUCCESS] Extracted Flags:
    -> FLAG{st0r3d_pr0c3dur3_1nj3ct10n_m4st3r}
```

---

## 📚 Tài Liệu Kèm Theo (Documentation)

- 📜 **[CHALLENGE.md](CHALLENGE.md):** Đề bài chi tiết dành cho người chơi (bối cảnh SOC/Red Team, không spoil đáp án).
- 🔍 **[SPEC.md](SPEC.md):** Tài liệu phân tích kỹ thuật, nguyên nhân gốc rễ (Root Cause) và hướng dẫn giải (Walkthrough) cho ban giám khảo / tác giả.
- 💡 **[exploits/README.md](exploits/README.md):** Chi tiết phân tích kỹ thuật từng payload khai thác.

---

## ⚖️ Phòng Thủ & Khắc Phục (Remediation)

1. **Khắc phục Act 1:** Luôn sử dụng Parameterized Query ngay cả khi dữ liệu được trích xuất từ cơ sở dữ liệu nội bộ (chống Second-Order SQLi). Tắt cờ `CLIENT.MULTI_STATEMENTS` ở tầng driver nếu không thực sự cần thiết.
2. **Khắc phục Act 2:** Trong Stored Procedure, áp dụng Whitelist kiểm tra giá trị tham số sắp xếp (`IF sortCol NOT IN ('cnt', 'user_id') THEN ...`) trước khi ghép vào câu lệnh chuẩn bị (`PREPARE stmt`).
