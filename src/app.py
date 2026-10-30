import os
import hashlib
import pymysql
from pymysql.constants import CLIENT
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, g)
from functools import wraps

app = Flask(__name__,
            template_folder=os.path.join(os.path.dirname(__file__), '..', 'templates'),
            static_folder=os.path.join(os.path.dirname(__file__), '..', 'static'))
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    raise RuntimeError('SECRET_KEY environment variable is required')

# ── Database Connection ───────────────────────────────────────────────────
def get_db():
    # ponytail: connection scoped per request with multi-statement enabled for export
    if 'db' not in g:
        g.db = pymysql.connect(
            host=os.environ.get('DB_HOST', 'localhost'),
            user=os.environ.get('DB_USER', 'ctf_user'),
            password=os.environ.get('DB_PASS', 'ctf_pass'),
            database=os.environ.get('DB_NAME', 'vuln_report'),
            client_flag=CLIENT.MULTI_STATEMENTS,  # Required for stacked query in Act 1
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True
        )
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db:
        db.close()

# ── Auth & Helpers ────────────────────────────────────────────────────────
def hash_password(pw):
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Vui lòng đăng nhập để tiếp tục.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def reviewer_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Vui lòng đăng nhập để tiếp tục.', 'warning')
            return redirect(url_for('login'))
        if session.get('role') not in ('reviewer', 'admin'):
            flash('Truy cập bị từ chối: Yêu cầu quyền Reviewer hoặc Quản trị viên.', 'danger')
            return redirect(url_for('reports'))
        return f(*args, **kwargs)
    return decorated

# ── Routes ────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('reports'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash('Tên đăng nhập và mật khẩu không được để trống.', 'danger')
            return render_template('register.html')

        if len(username) > 65:
            flash('Username must be under 30 chars.', 'danger')
            return render_template('register.html')

        db = get_db()
        cur = db.cursor()
        try:
            # Parameterized insert: Safe against direct 1st-order SQLi
            cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                (username, hash_password(password))
            )
        except pymysql.err.IntegrityError:
            flash('Tên đăng nhập đã được đăng ký trên hệ thống.', 'danger')
            return render_template('register.html')

        flash('Đăng ký tài khoản thành công! Bạn có thể đăng nhập ngay.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        db = get_db()
        cur = db.cursor()
        cur.execute(
            "SELECT * FROM users WHERE username = %s AND password_hash = %s",
            (username, hash_password(password))
        )
        user = cur.fetchone()

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash(f'Chào mừng trở lại, {user["username"]}! Vai trò hiện tại: {user["role"]}', 'success')
            return redirect(url_for('reports'))
        else:
            flash('Sai tên đăng nhập hoặc mật khẩu.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Đã đăng xuất an toàn khỏi phiên làm việc.', 'info')
    return redirect(url_for('login'))

@app.route('/reports', methods=['GET', 'POST'])
@login_required
def reports():
    db = get_db()
    cur = db.cursor()

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        if title:
            cur.execute(
                "INSERT INTO reports (user_id, title, description) VALUES (%s, %s, %s)",
                (session['user_id'], title, description)
            )
            flash('Đã lưu báo cáo lỗ hổng thành công.', 'success')

    cur.execute(
        "SELECT * FROM reports WHERE user_id = %s ORDER BY created_at DESC",
        (session['user_id'],)
    )
    user_reports = cur.fetchall()

    # Refresh current user role
    cur.execute("SELECT role FROM users WHERE id = %s", (session['user_id'],))
    row = cur.fetchone()
    if row:
        session['role'] = row['role']

    flag1 = None
    if session.get('role') == 'reviewer':
        flag1 = "FLAG{s3c0nd_0rd3r_st4ck3d_qu3ry_pwn3d}"

    return render_template('reports.html', reports=user_reports, role=session.get('role'), flag1=flag1)

@app.route('/export', methods=['POST'])
@login_required
def export_log():
    """
    Act 1 Trigger: Second-order Stacked Query SQL Injection.
    Username was stored safely via parameterized query during registration,
    but here it is concatenated unsafely into an UPDATE query.
    With CLIENT.MULTI_STATEMENTS enabled, stacked statements are executed.
    """
    db = get_db()
    cur = db.cursor()
    username = session['username']

    query = f"UPDATE users SET last_export = NOW() WHERE username = '{username}'"
    try:
        cur.execute(query)
        while cur.nextset():
            pass
    except Exception as e:
        flash(f'Export logs error: {e}', 'danger')
        return redirect(url_for('reports'))

    # Re-fetch updated role from database
    cur.execute("SELECT role FROM users WHERE id = %s", (session['user_id'],))
    row = cur.fetchone()
    if row:
        session['role'] = row['role']
        if row['role'] == 'reviewer':
            flash('Xuất log thành công! Đặc quyền Reviewer đã được kích hoạt trên tài khoản.', 'success')
        else:
            flash('Xuất log hoạt động thành công.', 'info')

    return redirect(url_for('reports'))

@app.route('/dashboard')
@reviewer_required
def dashboard():
    """
    Act 2: Reviewer Dashboard.
    Calls stored procedure GetTopReporter with unsanitized sort parameter.
    Procedure builds query via CONCAT and PREPARE stmt, allowing UNION injection.
    """
    db = get_db()
    cur = db.cursor()
    sort_param = request.args.get('sort', 'ORDER BY cnt DESC LIMIT 5')

    results = []
    error = None
    try:
        cur.callproc('GetTopReporter', (sort_param,))
        results = cur.fetchall()
        while cur.nextset():
            pass
    except Exception as e:
        error = str(e)
        flash(f'Lỗi thực thi thủ tục thống kê: {e}', 'danger')

    return render_template('dashboard.html', results=results, sort=sort_param, error=error)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
