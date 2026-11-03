# Remediation Guide — Internal Vulnerability Report System (IVRS)

> Tài liệu khắc phục dành cho đội Dev/SOC. Mỗi mục gồm: nguyên nhân, vị trí mã nguồn, cách sửa và kiểm chứng.
>
> **Lưu ý:** Đây là challenge CTF có chủ đích chứa lỗ hổng. Không áp dụng các bản vá dưới đây trực tiếp lên nhánh challenge; hãy tách nhánh `hardened` hoặc dùng cờ cấu hình môi trường.

---

## 1. Tổng Hợp Lỗ Hổng & Mức Độ Ưu Tiên

| # | Lỗ hổng | Vị trí | CWE / OWASP | Ưu tiên |
| :-: | :--- | :--- | :--- | :-: |
| 1 | Second-Order Stacked Query SQLi | `POST /export` — `src/app.py:178` | CWE-89 / A03:2021 | Critical |
| 2 | Dynamic SQL Injection trong Stored Procedure | `GetTopReporter` — `entrypoint.sh:45`, `GET /dashboard` | CWE-89 / A03:2021 | Critical |
| 3 | Bật `CLIENT.MULTI_STATEMENTS` không cần thiết | `src/app.py:25`, `entrypoint.sh:35` | CWE-89 | High |
| 4 | Phân quyền dựa trên `session['role']` | `src/app.py:56` | CWE-807 / A01:2021 | High |
| 5 | Băm mật khẩu SHA-256 không muối | `src/app.py:38` | CWE-916 / A02:2021 | High |
| 6 | Lộ thông báo lỗi SQL ra người dùng | `src/app.py:184`, `src/app.py:220` | CWE-209 | Medium |
| 7 | Thiếu CSRF token cho các form POST | `/register`, `/login`, `/reports`, `/export` | CWE-352 | Medium |
| 8 | Thiếu hardening cookie/security headers | `src/app.py` | CWE-614 / CWE-693 | Medium |
| 9 | Tài khoản DB ứng dụng có quyền quá rộng | `docker-compose.yml:6-8`, `schema.sql` | CWE-250 | Medium |
| 10 | Secret và credential mặc định trong repo | `docker-compose.yml:5-8`, `.env` | CWE-798 | Medium |

---

## 2. Act 1 — Second-Order Stacked Query SQL Injection

### Nguyên nhân

`/register` dùng parameterized query an toàn nên payload được lưu nguyên văn vào `users.username`. Tuy nhiên `/export` lấy lại `session['username']` và nối chuỗi trực tiếp:

```python
# src/app.py:178
query = f"UPDATE users SET last_export = NOW() WHERE username = '{username}'"
cur.execute(query)
```

Kết hợp với `CLIENT.MULTI_STATEMENTS`, payload `r_x';UPDATE users SET role='reviewer';#` thực thi thêm câu lệnh thứ hai và leo thang đặc quyền.

### Cách khắc phục

**Bước 1 — Parameterized query tại `/export`:**

```python
# src/app.py
cur.execute(
    "UPDATE users SET last_export = NOW() WHERE username = %s",
    (username,),
)
```

**Bước 2 — Tắt multi-statement ở driver (khuyến nghị bắt buộc):**

```python
# src/app.py
g.db = pymysql.connect(
    host=os.environ['DB_HOST'],
    user=os.environ['DB_USER'],
    password=os.environ['DB_PASS'],
    database=os.environ['DB_NAME'],
    client_flag=0,
    cursorclass=pymysql.cursors.DictCursor,
    autocommit=True,
)
```

Nếu thực sự cần chạy nhiều câu lệnh (migration, seed), tách riêng kết nối/script và không bao giờ trộn dữ liệu người dùng.

**Bước 3 — Chuẩn hóa dữ liệu đầu vào (defense-in-depth):**

```python
import re

USERNAME_RE = re.compile(r'^[A-Za-z0-9_.-]{3,30}$')

if not USERNAME_RE.fullmatch(username):
    flash('Tên đăng nhập chỉ gồm chữ, số, dấu chấm, gạch dưới; 3–30 ký tự.', 'danger')
    return render_template('register.html')
```

Sửa luôn thông báo lỗi hiện tại (`len(username) > 65` nhưng message ghi "under 30 chars") để khớp với ràng buộc thực tế.

**Bước 4 — Không cho ứng dụng tự đổi `role`:**

- Chỉ cấp quyền `UPDATE(last_export)` trên bảng `users` cho tài khoản ứng dụng.
- Việc nâng quyền phải đi qua luồng admin riêng, có audit log, không nằm trong câu lệnh của người dùng.

### Kiểm chứng

- Chạy lại `python exploits/solve_all.py http://localhost:5001`: Act 1 phải thất bại, `role` giữ nguyên `user`.
- Gửi username chứa `'`, `;`, `#`, `--` và xác nhận không có thay đổi ngoài ý muốn.
- Chạy `sqlmap` vào `/export` (đã đăng nhập) và xác nhận không phát hiện injection.

---

## 3. Act 2 — Dynamic SQL Injection trong Stored Procedure

### Nguyên nhân

`GetTopReporter` nhận `sortCol` từ query string `/dashboard?sort=...` rồi ghép thẳng vào câu SQL động:

```sql
SET @query = CONCAT(
  'SELECT user_id, COUNT(*) as cnt FROM reports GROUP BY user_id ',
  sortCol
);
PREPARE stmt FROM @query;
EXECUTE stmt;
```

Payload `UNION SELECT flag, 1 FROM admin_secrets` đọc được bảng bí mật vì tài khoản DB ứng dụng có quyền `SELECT` trên bảng này.

### Cách khắc phục

**Bước 1 — Whitelist thay vì ghép chuỗi (khuyến nghị):**

Đổi contract: app chỉ gửi khóa sắp xếp, procedure tự ánh xạ sang câu lệnh cố định.

```python
# src/app.py — /dashboard
sort_key = request.args.get('sort', 'cnt')
cur.callproc('GetTopReporter', (sort_key,))
```

```sql
CREATE PROCEDURE GetTopReporter(IN sortKey VARCHAR(32))
BEGIN
  CASE LOWER(sortKey)
    WHEN 'cnt' THEN
      SET @query = 'SELECT user_id, COUNT(*) AS cnt FROM reports GROUP BY user_id ORDER BY cnt DESC LIMIT 5';
    WHEN 'user_id' THEN
      SET @query = 'SELECT user_id, COUNT(*) AS cnt FROM reports GROUP BY user_id ORDER BY user_id DESC LIMIT 5';
    ELSE
      SET @query = 'SELECT user_id, COUNT(*) AS cnt FROM reports GROUP BY user_id ORDER BY cnt DESC LIMIT 5';
  END CASE;

  PREPARE stmt FROM @query;
  EXECUTE stmt;
  DEALLOCATE PREPARE stmt;
END
```

Không truyền nguyên mệnh đề `ORDER BY ... LIMIT ...` từ client như hiện tại (`src/app.py:209`); nếu buộc phải giữ, whitelist toàn bộ chuỗi chứ không chỉ tên cột.

**Bước 2 — Validate phía ứng dụng:**

```python
ALLOWED_SORTS = {'cnt', 'user_id'}
sort_key = request.args.get('sort', 'cnt')
if sort_key not in ALLOWED_SORTS:
    sort_key = 'cnt'
```

**Bước 3 — Least privilege ở tầng DB:**

- Thu hồi `SELECT` trên `admin_secrets` khỏi tài khoản ứng dụng.
- Nếu phải dùng procedure, đặt `SQL SECURITY DEFINER` với owner là tài khoản chỉ có quyền đọc `reports`, tuyệt đối không dùng `root`.
- Cấp `EXECUTE` trên đúng procedure thay vì quyền rộng trên schema.

```sql
REVOKE ALL PRIVILEGES ON vuln_report.admin_secrets FROM 'ctf_user'@'%';
GRANT SELECT, INSERT, UPDATE ON vuln_report.reports TO 'ctf_user'@'%';
GRANT SELECT, INSERT ON vuln_report.users TO 'ctf_user'@'%';
GRANT UPDATE (last_export) ON vuln_report.users TO 'ctf_user'@'%';
GRANT EXECUTE ON PROCEDURE vuln_report.GetTopReporter TO 'ctf_user'@'%';
```

### Kiểm chứng

- `/dashboard?sort=UNION SELECT flag, 1 FROM admin_secrets` phải trả về kết quả mặc định hoặc 400, không lộ flag.
- `/dashboard?sort=user_id DESC LIMIT 999` không làm thay đổi hành vi ngoài whitelist.
- Chạy lại `solve_all.py`: Act 2 phải thất bại.

---

## 4. Các Khắc Phục Bổ Sung

### 4.1. Phân quyền phía server, không tin session

`reviewer_required` đang đọc `session['role']` (`src/app.py:56`); session do client giữ và có thể lệch trạng thái. Luôn truy vấn lại role từ DB trước khi cấp quyền:

```python
def reviewer_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        cur = get_db().cursor()
        cur.execute("SELECT role FROM users WHERE id = %s", (session['user_id'],))
        row = cur.fetchone()
        if not row or row['role'] not in ('reviewer', 'admin'):
            abort(403)
        session['role'] = row['role']
        return f(*args, **kwargs)
    return decorated
```

### 4.2. Băm mật khẩu đúng chuẩn

SHA-256 không muối dễ bị rainbow table/GPU brute-force. Dùng Argon2id, scrypt hoặc bcrypt:

```python
from werkzeug.security import generate_password_hash, check_password_hash

password_hash = generate_password_hash(password, method='scrypt')
# Khi đăng nhập:
if check_password_hash(user['password_hash'], password):
    ...
```

Kế hoạch migrate: giữ cột `password_hash` hiện tại, thêm cột `algo`; khi user đăng nhập thành công bằng hash cũ thì rehash sang thuật toán mới.

Bổ sung rate limit + khóa tạm thời sau N lần sai (Flask-Limiter hoặc đếm trong DB) cho `/login` và `/register`.

### 4.3. Không trả lỗi SQL thô

Thay vì `flash(f'Export logs error: {e}')`, ghi log server-side (`app.logger.exception`) và trả thông báo chung:

```python
except Exception:
    app.logger.exception('export failed for user_id=%s', session.get('user_id'))
    flash('Không thể xuất log. Vui lòng thử lại sau.', 'danger')
```

### 4.4. CSRF protection

```python
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)
```

Thêm `csrf_token` vào mọi form POST trong `templates/*.html` (hoặc dùng `{{ form.hidden_tag() }}` nếu chuyển sang Flask-WTF forms).

### 4.5. Cookie & security headers

```python
from datetime import timedelta

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=True,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

@app.after_request
def security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'"
    )
    return resp
```

`SESSION_COOKIE_SECURE=True` chỉ bật khi chạy sau HTTPS; môi trường local HTTP cần tắt để tránh mất session.

### 4.6. Quản lý secret & credential

- `SECRET_KEY` đã được chuyển sang biến môi trường bắt buộc — giữ nguyên và xoay vòng định kỳ.
- Không commit `.env`; thêm `.env.example` chỉ chứa tên biến.
- Thay `MYSQL_ROOT_PASSWORD`, `MYSQL_PASSWORD` mặc định trong `docker-compose.yml` bằng secret injection (Docker secrets, vault, biến môi trường CI).
- Không lưu flag/bí mật dạng plaintext trong DB dùng chung; dùng secret manager hoặc mã hóa at-rest.

### 4.7. Giới hạn đầu vào & chống lạm dụng

- Giới hạn độ dài `title`/`description` (`reports`), chuẩn hóa Unicode.
- Rate limit toàn cục và theo IP cho `/login`, `/register`, `/export`, `/dashboard`.
- Ghi audit log cho thay đổi `role` và truy cập `admin_secrets` (nếu có).

### 4.8. Giám sát & phát hiện

- Alert khi username chứa `'`, `;`, `#`, `--`, `UNION`, `SLEEP(`, `INFORMATION_SCHEMA`.
- Alert khi có truy vấn đọc `admin_secrets` ngoài procedure hợp lệ.
- Bật slow query log, audit plugin của MariaDB; theo dõi lỗi SQL bất thường.

### 4.9. Quy trình

- Thêm SAST vào CI: `bandit`, `semgrep` (rule `formatted-sql-query`, `python.lang.security`).
- Quét dependency (`pip-audit`) và image (`trivy`).
- Review bắt buộc cho mọi thay đổi liên quan SQL, auth, session.

---

## 5. Checklist Kiểm Chứng Sau Khắc Phục

- [ ] `POST /export` dùng parameterized query; `MULTI_STATEMENTS` đã tắt.
- [ ] Username bị giới hạn charset/length ở cả client và server.
- [ ] `GetTopReporter` chỉ nhận khóa whitelist; app validate trước khi gọi.
- [ ] Tài khoản DB ứng dụng không đọc được `admin_secrets`, không `UPDATE` được `role`.
- [ ] `reviewer_required` truy vấn role từ DB mỗi request.
- [ ] Mật khẩu dùng scrypt/Argon2id/bcrypt; có rate limit đăng nhập.
- [ ] Không còn thông báo lỗi SQL thô trả về client.
- [ ] CSRF token có mặt trên tất cả form POST.
- [ ] Cookie `HttpOnly`/`SameSite`/`Secure`, có security headers.
- [ ] `python exploits/solve_all.py` thất bại ở cả 2 Act.
- [ ] `sqlmap` không phát hiện injection trên các endpoint đã đăng nhập.
- [ ] Log/alert cho mẫu payload SQLi hoạt động.

---

## 6. Tham Chiếu

- `README.md` — tổng quan challenge.
- `SPEC.md` — phân tích root cause và walkthrough.
- `exploits/README.md` — chi tiết payload khai thác.
- OWASP Top 10 2021: A03 Injection, A01 Broken Access Control, A02 Cryptographic Failures.
- CWE-89, CWE-250, CWE-352, CWE-209, CWE-807, CWE-916.
