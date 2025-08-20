from flask import Flask, render_template, request, redirect, session, flash, url_for
import requests
import json
import traceback
import sqlite3
import hashlib
import csv
import io
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'

# 数据库配置
DATABASE = 'survey.db'

# 默认管理员账号
DEFAULT_ADMIN = {
    'username': 'admin',
    'password': 'admin123',
    'is_admin': True
}
LIMESURVEY_BASE = "http://127.0.0.1:20050"
# LimeSurvey 默认配置
DEFAULT_LIMESURVEY_CONFIG = {
    'ls_url': f'{LIMESURVEY_BASE}/index.php/admin/remotecontrol',
    'ls_admin': 'admin',
    'ls_password': 'admin123'
}

# 数据库初始化
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # 用户表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 问卷表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS surveys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            survey_id INTEGER UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 用户答题记录表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_survey_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            survey_id INTEGER,
            token TEXT,
            attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (survey_id) REFERENCES surveys (survey_id),
            UNIQUE (user_id, survey_id)
        )
    ''')
    
    # 系统配置表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')
    
    # 插入默认管理员账号
    admin_password_hash = hashlib.sha256(DEFAULT_ADMIN['password'].encode()).hexdigest()
    cursor.execute('''
        INSERT OR IGNORE INTO users (username, password_hash, is_admin)
        VALUES (?, ?, ?)
    ''', (DEFAULT_ADMIN['username'], admin_password_hash, True))
    
    # 插入默认配置
    for key, value in DEFAULT_LIMESURVEY_CONFIG.items():
        cursor.execute('INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)', (key, value))
    
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, password_hash):
    return hash_password(password) == password_hash

def get_config():
    conn = get_db_connection()
    config = {}
    for row in conn.execute('SELECT key, value FROM config').fetchall():
        config[row['key']] = row['value']
    conn.close()
    return config

def require_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        conn = get_db_connection()
        user = conn.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        
        if not user or not user['is_admin']:
            flash('需要管理员权限', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# -------------------------------
def rpc_request(method, params, config=None):
    if config is None:
        config = get_config()
    
    payload = {
        "method": method,
        "params": params,
        "id": 1
    }
    res = requests.post(config['ls_url'], json=payload)
    res.raise_for_status()
    return res.json()["result"]

# 登录路由
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT id, username, password_hash, is_admin FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        conn.close()
        
        if user and verify_password(password, user['password_hash']):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            
            if user['is_admin']:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            error = "用户名或密码错误"
    
    return render_template("login.html", error=error)

# 退出登录
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

# 用户仪表板
@app.route("/dashboard")
@require_login
def dashboard():
    conn = get_db_connection()
    
    # 获取活跃的问卷
    surveys = conn.execute(
        'SELECT survey_id, title, description FROM surveys WHERE is_active = 1'
    ).fetchall()
    
    # 获取用户已完成的问卷
    completed_surveys = conn.execute(
        '''SELECT survey_id FROM user_survey_attempts 
           WHERE user_id = ?''',
        (session['user_id'],)
    ).fetchall()
    completed_survey_ids = [s['survey_id'] for s in completed_surveys]
    
    conn.close()
    
    return render_template("dashboard.html", 
                         surveys=surveys, 
                         completed_survey_ids=completed_survey_ids)

# 开始问卷
@app.route("/start_survey/<int:survey_id>")
@require_login
def start_survey(survey_id):
    conn = get_db_connection()
    
    # 检查是否已经完成过该问卷
    attempt = conn.execute(
        'SELECT token FROM user_survey_attempts WHERE user_id = ? AND survey_id = ?',
        (session['user_id'], survey_id)
    ).fetchone()
    
    if attempt:
        # 已经有token，直接跳转
        config = get_config()
        survey_url = f"{LIMESURVEY_BASE}/index.php/{survey_id}?token={attempt['token']}"
        conn.close()
        return redirect(survey_url)
    
    # 获取问卷信息
    survey = conn.execute(
        'SELECT * FROM surveys WHERE survey_id = ? AND is_active = 1',
        (survey_id,)
    ).fetchone()
    
    if not survey:
        conn.close()
        flash('问卷不存在或已关闭', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        config = get_config()
        session_key = rpc_request("get_session_key", [config['ls_admin'], config['ls_password']], config)
        
        participant = {
            "firstname": session['username'],
            "lastname": "",
            "email": f"{session['username']}@example.com",
            "language": "zh-Hans"
        }
        token_info = rpc_request("add_participants", [session_key, survey_id, [participant], True], config)
        
        token = None
        if isinstance(token_info, list) and len(token_info) > 0:
            token = token_info[0].get("token")
        elif isinstance(token_info, dict) and "status" in token_info:
            # 已存在的参与者，尝试获取现有 token
            participants = rpc_request("list_participants", [session_key, survey_id, 0, 10, False, {"email": f"{session['username']}@example.com"}], config)
            if participants:
                token = participants[0].get("token")
        
        if not token:
            raise Exception(f"无法获取 token, API 返回: {token_info}")
        
        # 保存用户答题记录
        conn.execute(
            'INSERT INTO user_survey_attempts (user_id, survey_id, token) VALUES (?, ?, ?)',
            (session['user_id'], survey_id, token)
        )
        conn.commit()
        
        survey_url = f"http://127.0.0.1:20050/index.php/{survey_id}?token={token}"
        rpc_request("release_session_key", [session_key], config)
        
        conn.close()
        return redirect(survey_url)
        
    except Exception as e:
        conn.close()
        flash(f"启动问卷失败: {e}", 'error')
        return redirect(url_for('dashboard'))

# 修改密码
@app.route("/change_password", methods=["GET", "POST"])
@require_login
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")
        
        if new_password != confirm_password:
            flash("新密码确认不匹配", "error")
            return render_template("change_password.html")
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT password_hash FROM users WHERE id = ?',
            (session['user_id'],)
        ).fetchone()
        
        if not verify_password(current_password, user['password_hash']):
            flash("当前密码错误", "error")
            conn.close()
            return render_template("change_password.html")
        
        new_password_hash = hash_password(new_password)
        conn.execute(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            (new_password_hash, session['user_id'])
        )
        conn.commit()
        conn.close()
        
        flash("密码修改成功", "success")
        return redirect(url_for('dashboard'))
    
    return render_template("change_password.html")

# 管理员仪表板
@app.route("/admin")
@require_admin
def admin_dashboard():
    conn = get_db_connection()
    
    # 获取用户统计
    user_count = conn.execute('SELECT COUNT(*) as count FROM users WHERE is_admin = 0').fetchone()['count']
    survey_count = conn.execute('SELECT COUNT(*) as count FROM surveys').fetchone()['count']
    attempt_count = conn.execute('SELECT COUNT(*) as count FROM user_survey_attempts').fetchone()['count']
    
    conn.close()
    
    return render_template("admin_dashboard.html", 
                         user_count=user_count,
                         survey_count=survey_count,
                         attempt_count=attempt_count)

# 用户管理
@app.route("/admin/users")
@require_admin
def admin_users():
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, created_at FROM users WHERE is_admin = 0 ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template("admin_users.html", users=users)

# 添加用户
@app.route("/admin/users/add", methods=["GET", "POST"])
@require_admin
def admin_add_user():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if not username or not password:
            flash("用户名和密码不能为空", "error")
            return render_template("admin_add_user.html")
        
        conn = get_db_connection()
        
        # 检查用户是否已存在
        existing = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing:
            flash("用户名已存在", "error")
            conn.close()
            return render_template("admin_add_user.html")
        
        try:
            password_hash = hash_password(password)
            conn.execute(
                'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)',
                (username, password_hash, False)
            )
            conn.commit()
            flash("用户添加成功", "success")
            conn.close()
            return redirect(url_for('admin_users'))
        except Exception as e:
            flash(f"添加用户失败: {e}", "error")
            conn.close()
            return render_template("admin_add_user.html")
    
    return render_template("admin_add_user.html")

# 修改用户密码
@app.route("/admin/users/change_password/<int:user_id>", methods=["GET", "POST"])
@require_admin
def admin_change_user_password(user_id):
    conn = get_db_connection()
    user = conn.execute(
        'SELECT id, username FROM users WHERE id = ? AND is_admin = 0',
        (user_id,)
    ).fetchone()
    
    if not user:
        flash("用户不存在", "error")
        conn.close()
        return redirect(url_for('admin_users'))
    
    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")
        
        if not new_password:
            flash("新密码不能为空", "error")
            conn.close()
            return render_template("admin_change_user_password.html", user=user)
        
        if new_password != confirm_password:
            flash("密码确认不匹配", "error")
            conn.close()
            return render_template("admin_change_user_password.html", user=user)
        
        try:
            new_password_hash = hash_password(new_password)
            conn.execute(
                'UPDATE users SET password_hash = ? WHERE id = ?',
                (new_password_hash, user_id)
            )
            conn.commit()
            flash(f"用户 {user['username']} 的密码修改成功", "success")
            conn.close()
            return redirect(url_for('admin_users'))
        except Exception as e:
            flash(f"修改密码失败: {e}", "error")
            conn.close()
            return render_template("admin_change_user_password.html", user=user)
    
    conn.close()
    return render_template("admin_change_user_password.html", user=user)

# 删除用户
@app.route("/admin/users/delete/<int:user_id>", methods=["POST"])
@require_admin
def admin_delete_user(user_id):
    conn = get_db_connection()
    
    # 删除用户的答题记录
    conn.execute('DELETE FROM user_survey_attempts WHERE user_id = ?', (user_id,))
    # 删除用户
    conn.execute('DELETE FROM users WHERE id = ? AND is_admin = 0', (user_id,))
    conn.commit()
    conn.close()
    
    flash("用户删除成功", "success")
    return redirect(url_for('admin_users'))

# 批量导入用户
@app.route("/admin/users/import", methods=["GET", "POST"])
@require_admin
def admin_import_users():
    if request.method == "POST":
        if 'csv_file' not in request.files:
            flash("请选择CSV文件", "error")
            return render_template("admin_import_users.html")
        
        file = request.files['csv_file']
        if file.filename == '':
            flash("请选择CSV文件", "error")
            return render_template("admin_import_users.html")
        
        if not file.filename.endswith('.csv'):
            flash("请上传CSV格式文件", "error")
            return render_template("admin_import_users.html")
        
        try:
            # 读取CSV内容
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            csv_input = csv.reader(stream)
            
            conn = get_db_connection()
            success_count = 0
            error_count = 0
            
            for row in csv_input:
                if len(row) >= 2:
                    username, password = row[0].strip(), row[1].strip()
                    if username and password:
                        # 检查用户是否已存在
                        existing = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
                        if not existing:
                            try:
                                password_hash = hash_password(password)
                                conn.execute(
                                    'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)',
                                    (username, password_hash, False)
                                )
                                success_count += 1
                            except:
                                error_count += 1
                        else:
                            error_count += 1
                    else:
                        error_count += 1
                else:
                    error_count += 1
            
            conn.commit()
            conn.close()
            
            flash(f"导入完成: 成功 {success_count} 个，失败 {error_count} 个", "success")
            return redirect(url_for('admin_users'))
            
        except Exception as e:
            flash(f"导入失败: {e}", "error")
            return render_template("admin_import_users.html")
    
    return render_template("admin_import_users.html")

# 问卷管理
@app.route("/admin/surveys")
@require_admin
def admin_surveys():
    conn = get_db_connection()
    surveys = conn.execute('SELECT * FROM surveys ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template("admin_surveys.html", surveys=surveys)

# 添加问卷
@app.route("/admin/surveys/add", methods=["GET", "POST"])
@require_admin
def admin_add_survey():
    if request.method == "POST":
        survey_id = request.form.get("survey_id")
        title = request.form.get("title")
        description = request.form.get("description", "")
        is_active = request.form.get("is_active") == "on"
        
        if not survey_id or not title:
            flash("问卷ID和标题不能为空", "error")
            return render_template("admin_add_survey.html")
        
        try:
            survey_id = int(survey_id)
        except ValueError:
            flash("问卷ID必须是数字", "error")
            return render_template("admin_add_survey.html")
        
        conn = get_db_connection()
        
        # 检查问卷是否已存在
        existing = conn.execute('SELECT id FROM surveys WHERE survey_id = ?', (survey_id,)).fetchone()
        if existing:
            flash("问卷ID已存在", "error")
            conn.close()
            return render_template("admin_add_survey.html")
        
        try:
            conn.execute(
                'INSERT INTO surveys (survey_id, title, description, is_active) VALUES (?, ?, ?, ?)',
                (survey_id, title, description, is_active)
            )
            conn.commit()
            flash("问卷添加成功", "success")
            conn.close()
            return redirect(url_for('admin_surveys'))
        except Exception as e:
            flash(f"添加问卷失败: {e}", "error")
            conn.close()
            return render_template("admin_add_survey.html")
    
    return render_template("admin_add_survey.html")

# 编辑问卷
@app.route("/admin/surveys/edit/<int:survey_id>", methods=["GET", "POST"])
@require_admin
def admin_edit_survey(survey_id):
    conn = get_db_connection()
    survey = conn.execute('SELECT * FROM surveys WHERE survey_id = ?', (survey_id,)).fetchone()
    
    if not survey:
        flash("问卷不存在", "error")
        conn.close()
        return redirect(url_for('admin_surveys'))
    
    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description", "")
        is_active = request.form.get("is_active") == "on"
        
        if not title:
            flash("标题不能为空", "error")
            conn.close()
            return render_template("admin_edit_survey.html", survey=survey)
        
        try:
            conn.execute(
                'UPDATE surveys SET title = ?, description = ?, is_active = ? WHERE survey_id = ?',
                (title, description, is_active, survey_id)
            )
            conn.commit()
            flash("问卷更新成功", "success")
            conn.close()
            return redirect(url_for('admin_surveys'))
        except Exception as e:
            flash(f"更新问卷失败: {e}", "error")
            conn.close()
            return render_template("admin_edit_survey.html", survey=survey)
    
    conn.close()
    return render_template("admin_edit_survey.html", survey=survey)

# 删除问卷
@app.route("/admin/surveys/delete/<int:survey_id>", methods=["POST"])
@require_admin
def admin_delete_survey(survey_id):
    conn = get_db_connection()
    
    # 删除相关的答题记录
    conn.execute('DELETE FROM user_survey_attempts WHERE survey_id = ?', (survey_id,))
    # 删除问卷
    conn.execute('DELETE FROM surveys WHERE survey_id = ?', (survey_id,))
    conn.commit()
    conn.close()
    
    flash("问卷删除成功", "success")
    return redirect(url_for('admin_surveys'))

# 系统配置
@app.route("/admin/config", methods=["GET", "POST"])
@require_admin
def admin_config():
    if request.method == "POST":
        ls_url = request.form.get("ls_url")
        ls_admin = request.form.get("ls_admin")
        ls_password = request.form.get("ls_password")
        
        if not all([ls_url, ls_admin, ls_password]):
            flash("所有配置项都不能为空", "error")
            return render_template("admin_config.html", config=get_config())
        
        conn = get_db_connection()
        try:
            conn.execute('UPDATE config SET value = ? WHERE key = ?', (ls_url, 'ls_url'))
            conn.execute('UPDATE config SET value = ? WHERE key = ?', (ls_admin, 'ls_admin'))
            conn.execute('UPDATE config SET value = ? WHERE key = ?', (ls_password, 'ls_password'))
            conn.commit()
            flash("配置更新成功", "success")
        except Exception as e:
            flash(f"配置更新失败: {e}", "error")
        finally:
            conn.close()
    
    config = get_config()
    return render_template("admin_config.html", config=config)

# -------------------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
