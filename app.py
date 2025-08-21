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
    conn.row_factory = sqlite3.Row  # 设置 row_factory
    cursor = conn.cursor()
    
    # 用户组表 - 支持多层级
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            parent_id INTEGER,
            full_path TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (parent_id) REFERENCES user_groups (id)
        )
    ''')
    
    # 用户表 - 添加组ID
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            group_id INTEGER,
            is_admin BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (group_id) REFERENCES user_groups (id)
        )
    ''')
    
    # 问卷表 - 添加组权限控制
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS surveys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            survey_id INTEGER UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            is_active BOOLEAN DEFAULT TRUE,
            access_type TEXT DEFAULT 'all',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 问卷组权限表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS survey_group_access (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            survey_id INTEGER,
            group_id INTEGER,
            FOREIGN KEY (survey_id) REFERENCES surveys (survey_id),
            FOREIGN KEY (group_id) REFERENCES user_groups (id),
            UNIQUE (survey_id, group_id)
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
    
    # 检查并创建默认用户组
    root_group = cursor.execute('SELECT id FROM user_groups WHERE name = ? AND parent_id IS NULL', ('根组织',)).fetchone()
    if not root_group:
        cursor.execute('''
            INSERT INTO user_groups (name, parent_id, full_path, description) 
            VALUES (?, ?, ?, ?)
        ''', ('根组织', None, '根组织', '系统默认根组织'))
        root_group_id = cursor.lastrowid
        print(f"✓ 创建根组织 (ID: {root_group_id})")
    else:
        root_group_id = root_group['id']
        print(f"✓ 根组织已存在 (ID: {root_group_id})")
    
    # 插入默认管理员账号并确保关联到根组织
    admin_exists = cursor.execute('SELECT id, group_id FROM users WHERE username = ?', (DEFAULT_ADMIN['username'],)).fetchone()
    if not admin_exists:
        admin_password_hash = hashlib.sha256(DEFAULT_ADMIN['password'].encode()).hexdigest()
        cursor.execute('''
            INSERT INTO users (username, password_hash, is_admin, group_id)
            VALUES (?, ?, ?, ?)
        ''', (DEFAULT_ADMIN['username'], admin_password_hash, True, root_group_id))
        print(f"✓ 创建默认管理员账号: {DEFAULT_ADMIN['username']}")
    else:
        # 如果管理员已存在但没有分配到根组织，则更新
        if admin_exists['group_id'] != root_group_id:
            cursor.execute('''
                UPDATE users SET group_id = ? WHERE username = ?
            ''', (root_group_id, DEFAULT_ADMIN['username']))
            print(f"✓ 更新管理员账号组织关联: {DEFAULT_ADMIN['username']} -> 根组织")
        else:
            print(f"✓ 管理员账号已存在: {DEFAULT_ADMIN['username']}")
    
    # 插入默认配置
    config_count = 0
    for key, value in DEFAULT_LIMESURVEY_CONFIG.items():
        config_exists = cursor.execute('SELECT key FROM config WHERE key = ?', (key,)).fetchone()
        if not config_exists:
            cursor.execute('INSERT INTO config (key, value) VALUES (?, ?)', (key, value))
            config_count += 1
    if config_count > 0:
        print(f"✓ 创建 {config_count} 个默认配置项")
    else:
        print("✓ 默认配置已存在")
    
    conn.commit()
    conn.close()

def clean_duplicate_root_groups():
    """清理重复的根组织，只保留第一个"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 查找所有根组织（parent_id为NULL的组织）
    root_groups = cursor.execute('''
        SELECT id, name FROM user_groups 
        WHERE parent_id IS NULL 
        ORDER BY id
    ''').fetchall()
    
    if len(root_groups) > 1:
        # 保留第一个根组织，删除其他的
        keep_root_id = root_groups[0]['id']
        
        for i in range(1, len(root_groups)):
            duplicate_root_id = root_groups[i]['id']
            
            # 将引用重复根组织的用户转移到保留的根组织
            cursor.execute('''
                UPDATE users SET group_id = ? WHERE group_id = ?
            ''', (keep_root_id, duplicate_root_id))
            
            # 将重复根组织的子组织的parent_id更新为保留的根组织
            cursor.execute('''
                UPDATE user_groups SET parent_id = ? WHERE parent_id = ?
            ''', (keep_root_id, duplicate_root_id))
            
            # 删除重复的根组织
            cursor.execute('DELETE FROM user_groups WHERE id = ?', (duplicate_root_id,))
            
            print(f"清理重复根组织: {root_groups[i]['name']} (ID: {duplicate_root_id})")
    
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

# 用户组相关函数
def get_all_groups():
    conn = get_db_connection()
    groups = conn.execute('''
        SELECT id, name, parent_id, full_path, description 
        FROM user_groups 
        ORDER BY full_path
    ''').fetchall()
    conn.close()
    return groups

def get_group_hierarchy():
    """获取用户组层级结构"""
    conn = get_db_connection()
    groups = conn.execute('''
        SELECT id, name, parent_id, full_path, description 
        FROM user_groups 
        ORDER BY full_path
    ''').fetchall()
    conn.close()
    
    # 构建层级结构
    hierarchy = []
    for group in groups:
        level = group['full_path'].count('/') if '/' in group['full_path'] else 0
        hierarchy.append({
            'id': group['id'],
            'name': group['name'],
            'parent_id': group['parent_id'],
            'full_path': group['full_path'],
            'description': group['description'],
            'level': level,
            'indent': '　' * level  # 用全角空格缩进
        })
    return hierarchy

def create_group(name, parent_id, description=''):
    """创建用户组"""
    conn = get_db_connection()
    
    # 获取父组路径
    if parent_id:
        parent = conn.execute('SELECT full_path FROM user_groups WHERE id = ?', (parent_id,)).fetchone()
        if parent:
            full_path = f"{parent['full_path']}/{name}"
        else:
            full_path = name
    else:
        full_path = name
    
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO user_groups (name, parent_id, full_path, description)
        VALUES (?, ?, ?, ?)
    ''', (name, parent_id, full_path, description))
    
    group_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return group_id

def update_group_paths():
    """更新所有组的完整路径"""
    conn = get_db_connection()
    
    # 递归函数更新路径
    def update_path(group_id, parent_path=''):
        group = conn.execute('SELECT id, name, parent_id FROM user_groups WHERE id = ?', (group_id,)).fetchone()
        if not group:
            return
        
        if parent_path:
            full_path = f"{parent_path}/{group['name']}"
        else:
            full_path = group['name']
        
        conn.execute('UPDATE user_groups SET full_path = ? WHERE id = ?', (full_path, group_id))
        
        # 更新所有子组
        children = conn.execute('SELECT id FROM user_groups WHERE parent_id = ?', (group_id,)).fetchall()
        for child in children:
            update_path(child['id'], full_path)
    
    # 从根组开始更新
    root_groups = conn.execute('SELECT id FROM user_groups WHERE parent_id IS NULL').fetchall()
    for root in root_groups:
        update_path(root['id'])
    
    conn.commit()
    conn.close()

def get_user_accessible_surveys(user_id):
    """获取用户可访问的问卷"""
    conn = get_db_connection()
    
    # 获取用户组ID
    user = conn.execute('SELECT group_id FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user or not user['group_id']:
        # 没有组的用户只能看到全局问卷
        surveys = conn.execute('''
            SELECT survey_id, title, description 
            FROM surveys 
            WHERE is_active = 1 AND access_type = 'all'
        ''').fetchall()
    else:
        # 获取用户组及所有父组
        user_groups = get_user_group_hierarchy(user['group_id'])
        group_ids = [g['id'] for g in user_groups]
        
        if group_ids:
            placeholders = ','.join('?' * len(group_ids))
            surveys = conn.execute(f'''
                SELECT DISTINCT s.survey_id, s.title, s.description 
                FROM surveys s
                LEFT JOIN survey_group_access sga ON s.survey_id = sga.survey_id
                WHERE s.is_active = 1 AND (
                    s.access_type = 'all' OR 
                    (s.access_type = 'groups' AND sga.group_id IN ({placeholders}))
                )
            ''', group_ids).fetchall()
        else:
            surveys = conn.execute('''
                SELECT survey_id, title, description 
                FROM surveys 
                WHERE is_active = 1 AND access_type = 'all'
            ''').fetchall()
    
    conn.close()
    return surveys

def get_user_group_hierarchy(group_id):
    """获取用户所在组及所有父组"""
    conn = get_db_connection()
    groups = []
    
    current_id = group_id
    while current_id:
        group = conn.execute('''
            SELECT id, name, parent_id, full_path 
            FROM user_groups WHERE id = ?
        ''', (current_id,)).fetchone()
        
        if not group:
            break
            
        groups.append(group)
        current_id = group['parent_id']
    
    conn.close()
    return groups

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
    # 使用新的组权限逻辑获取问卷
    surveys = get_user_accessible_surveys(session['user_id'])
    
    # 获取用户已完成的问卷
    conn = get_db_connection()
    completed_surveys = conn.execute(
        '''SELECT survey_id FROM user_survey_attempts 
           WHERE user_id = ?''',
        (session['user_id'],)
    ).fetchall()
    completed_survey_ids = [s['survey_id'] for s in completed_surveys]
    
    # 获取用户组信息
    user_group = conn.execute('''
        SELECT ug.full_path 
        FROM users u 
        LEFT JOIN user_groups ug ON u.group_id = ug.id 
        WHERE u.id = ?
    ''', (session['user_id'],)).fetchone()
    
    conn.close()
    
    return render_template("dashboard.html", 
                         surveys=surveys, 
                         completed_survey_ids=completed_survey_ids,
                         user_group=user_group['full_path'] if user_group and user_group['full_path'] else '未分组')

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
        
        survey_url = f"{LIMESURVEY_BASE}/index.php/{survey_id}?token={token}"
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
    
    # 获取统计数据
    user_count = conn.execute('SELECT COUNT(*) as count FROM users WHERE is_admin = 0').fetchone()['count']
    survey_count = conn.execute('SELECT COUNT(*) as count FROM surveys').fetchone()['count']
    attempt_count = conn.execute('SELECT COUNT(*) as count FROM user_survey_attempts').fetchone()['count']
    group_count = conn.execute('SELECT COUNT(*) as count FROM user_groups').fetchone()['count']
    
    conn.close()
    
    return render_template("admin_dashboard.html", 
                         user_count=user_count,
                         survey_count=survey_count,
                         attempt_count=attempt_count,
                         group_count=group_count)

# 用户组管理
@app.route("/admin/groups")
@require_admin
def admin_groups():
    groups = get_group_hierarchy()
    return render_template("admin_groups.html", groups=groups)

# 添加用户组
@app.route("/admin/groups/add", methods=["GET", "POST"])
@require_admin
def admin_add_group():
    if request.method == "POST":
        name = request.form.get("name")
        parent_id = request.form.get("parent_id")
        description = request.form.get("description", "")
        
        if not name:
            flash("组名不能为空", "error")
            return render_template("admin_add_group.html", all_groups=get_all_groups())
        
        try:
            parent_id = int(parent_id) if parent_id and parent_id != '' else None
            create_group(name, parent_id, description)
            flash("用户组添加成功", "success")
            return redirect(url_for('admin_groups'))
        except Exception as e:
            flash(f"添加用户组失败: {e}", "error")
    
    all_groups = get_all_groups()
    return render_template("admin_add_group.html", all_groups=all_groups)

# 编辑用户组
@app.route("/admin/groups/edit/<int:group_id>", methods=["GET", "POST"])
@require_admin
def admin_edit_group(group_id):
    conn = get_db_connection()
    group = conn.execute('SELECT * FROM user_groups WHERE id = ?', (group_id,)).fetchone()
    
    if not group:
        flash("用户组不存在", "error")
        conn.close()
        return redirect(url_for('admin_groups'))
    
    if request.method == "POST":
        name = request.form.get("name")
        parent_id = request.form.get("parent_id")
        description = request.form.get("description", "")
        
        if not name:
            flash("组名不能为空", "error")
            conn.close()
            return render_template("admin_edit_group.html", group=group, all_groups=get_all_groups())
        
        try:
            parent_id = int(parent_id) if parent_id and parent_id != '' else None
            
            # 不能设置自己或子组为父组
            if parent_id == group_id:
                flash("不能设置自己为父组", "error")
                conn.close()
                return render_template("admin_edit_group.html", group=group, all_groups=get_all_groups())
            
            conn.execute('''
                UPDATE user_groups 
                SET name = ?, parent_id = ?, description = ? 
                WHERE id = ?
            ''', (name, parent_id, description, group_id))
            conn.commit()
            
            # 更新所有组的路径
            update_group_paths()
            
            flash("用户组更新成功", "success")
            conn.close()
            return redirect(url_for('admin_groups'))
        except Exception as e:
            flash(f"更新用户组失败: {e}", "error")
    
    all_groups = get_all_groups()
    conn.close()
    return render_template("admin_edit_group.html", group=group, all_groups=all_groups)

# 删除用户组
@app.route("/admin/groups/delete/<int:group_id>", methods=["POST"])
@require_admin
def admin_delete_group(group_id):
    if group_id == 1:  # 保护根组织
        flash("不能删除根组织", "error")
        return redirect(url_for('admin_groups'))
    
    conn = get_db_connection()
    
    # 检查是否有子组
    children = conn.execute('SELECT COUNT(*) as count FROM user_groups WHERE parent_id = ?', (group_id,)).fetchone()
    if children['count'] > 0:
        flash("请先删除所有子组", "error")
        conn.close()
        return redirect(url_for('admin_groups'))
    
    # 检查是否有用户
    users = conn.execute('SELECT COUNT(*) as count FROM users WHERE group_id = ?', (group_id,)).fetchone()
    if users['count'] > 0:
        flash("请先将组内用户转移到其他组", "error")
        conn.close()
        return redirect(url_for('admin_groups'))
    
    try:
        # 删除组的问卷权限
        conn.execute('DELETE FROM survey_group_access WHERE group_id = ?', (group_id,))
        # 删除组
        conn.execute('DELETE FROM user_groups WHERE id = ?', (group_id,))
        conn.commit()
        flash("用户组删除成功", "success")
    except Exception as e:
        flash(f"删除用户组失败: {e}", "error")
    
    conn.close()
    return redirect(url_for('admin_groups'))

# 用户管理
@app.route("/admin/users")
@require_admin
def admin_users():
    conn = get_db_connection()
    users = conn.execute('''
        SELECT u.id, u.username, u.created_at, ug.full_path as group_path
        FROM users u 
        LEFT JOIN user_groups ug ON u.group_id = ug.id 
        WHERE u.is_admin = 0 
        ORDER BY u.created_at DESC
    ''').fetchall()
    conn.close()
    return render_template("admin_users.html", users=users)

# 添加用户
@app.route("/admin/users/add", methods=["GET", "POST"])
@require_admin
def admin_add_user():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        group_id = request.form.get("group_id")
        
        if not username or not password:
            flash("用户名和密码不能为空", "error")
            return render_template("admin_add_user.html", all_groups=get_all_groups())
        
        conn = get_db_connection()
        
        # 检查用户是否已存在
        existing = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing:
            flash("用户名已存在", "error")
            conn.close()
            return render_template("admin_add_user.html", all_groups=get_all_groups())
        
        try:
            password_hash = hash_password(password)
            group_id = int(group_id) if group_id and group_id != '' else None
            conn.execute(
                'INSERT INTO users (username, password_hash, is_admin, group_id) VALUES (?, ?, ?, ?)',
                (username, password_hash, False, group_id)
            )
            conn.commit()
            flash("用户添加成功", "success")
            conn.close()
            return redirect(url_for('admin_users'))
        except Exception as e:
            flash(f"添加用户失败: {e}", "error")
            conn.close()
            return render_template("admin_add_user.html", all_groups=get_all_groups())
    
    all_groups = get_all_groups()
    return render_template("admin_add_user.html", all_groups=all_groups)

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
            return render_template("admin_import_users.html", all_groups=get_all_groups())
        
        file = request.files['csv_file']
        default_group_id = request.form.get("default_group_id")
        
        if file.filename == '':
            flash("请选择CSV文件", "error")
            return render_template("admin_import_users.html", all_groups=get_all_groups())
        
        if not file.filename.endswith('.csv'):
            flash("请上传CSV格式文件", "error")
            return render_template("admin_import_users.html", all_groups=get_all_groups())
        
        try:
            # 读取CSV内容
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            csv_input = csv.reader(stream)
            
            conn = get_db_connection()
            success_count = 0
            error_count = 0
            
            # 获取组映射（组全路径 -> 组ID）
            groups_map = {}
            all_groups = conn.execute('SELECT id, full_path FROM user_groups').fetchall()
            for group in all_groups:
                groups_map[group['full_path']] = group['id']
            
            default_group_id = int(default_group_id) if default_group_id and default_group_id != '' else None
            
            def get_or_create_group_by_path(group_path):
                """根据路径获取或创建组织"""
                if not group_path or group_path in groups_map:
                    return groups_map.get(group_path)
                
                # 分解路径，逐级创建组织
                path_parts = group_path.split('/')
                current_path = ''
                parent_id = None
                
                for part in path_parts:
                    part = part.strip()
                    if not part:
                        continue
                    
                    if current_path:
                        current_path += '/' + part
                    else:
                        current_path = part
                    
                    if current_path not in groups_map:
                        # 创建新组织
                        cursor.execute('''
                            INSERT INTO user_groups (name, parent_id, full_path, description)
                            VALUES (?, ?, ?, ?)
                        ''', (part, parent_id, current_path, f'通过CSV导入自动创建'))
                        
                        new_group_id = cursor.lastrowid
                        groups_map[current_path] = new_group_id
                        parent_id = new_group_id
                    else:
                        parent_id = groups_map[current_path]
                
                return groups_map.get(group_path)
            
            cursor = conn.cursor()
            
            for row in csv_input:
                if len(row) >= 2:
                    username = row[0].strip()
                    password = row[1].strip()
                    group_path = row[2].strip() if len(row) > 2 else None
                    
                    if username and password:
                        # 检查用户是否已存在
                        existing = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
                        if not existing:
                            try:
                                # 确定用户组ID
                                user_group_id = default_group_id
                                if group_path:
                                    user_group_id = get_or_create_group_by_path(group_path)
                                
                                password_hash = hash_password(password)
                                conn.execute(
                                    'INSERT INTO users (username, password_hash, is_admin, group_id) VALUES (?, ?, ?, ?)',
                                    (username, password_hash, False, user_group_id)
                                )
                                success_count += 1
                            except Exception as ex:
                                print(f"创建用户失败: {username}, 错误: {ex}")  # 调试用
                                error_count += 1
                        else:
                            error_count += 1
                    else:
                        error_count += 1
                else:
                    error_count += 1
            
            conn.commit()
            conn.close()
            
            # 显示更详细的导入结果
            if success_count > 0:
                flash(f"导入完成！成功创建 {success_count} 个用户，失败 {error_count} 个", "success")
            else:
                flash(f"导入完成！成功 {success_count} 个，失败 {error_count} 个。请检查CSV格式是否正确", "warning")
            
            return redirect(url_for('admin_users'))
            
        except Exception as e:
            flash(f"导入失败: {e}", "error")
            return render_template("admin_import_users.html", all_groups=get_all_groups())
    
    all_groups = get_all_groups()
    return render_template("admin_import_users.html", all_groups=all_groups)

# 问卷管理
@app.route("/admin/surveys")
@require_admin
def admin_surveys():
    conn = get_db_connection()
    surveys = conn.execute('''
        SELECT s.*, 
               GROUP_CONCAT(ug.full_path) as allowed_groups
        FROM surveys s
        LEFT JOIN survey_group_access sga ON s.survey_id = sga.survey_id
        LEFT JOIN user_groups ug ON sga.group_id = ug.id
        GROUP BY s.id
        ORDER BY s.created_at DESC
    ''').fetchall()
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
        access_type = request.form.get("access_type", "all")
        selected_groups = request.form.getlist("selected_groups")
        
        if not survey_id or not title:
            flash("问卷ID和标题不能为空", "error")
            return render_template("admin_add_survey.html", all_groups=get_all_groups())
        
        try:
            survey_id = int(survey_id)
        except ValueError:
            flash("问卷ID必须是数字", "error")
            return render_template("admin_add_survey.html", all_groups=get_all_groups())
        
        conn = get_db_connection()
        
        # 检查问卷是否已存在
        existing = conn.execute('SELECT id FROM surveys WHERE survey_id = ?', (survey_id,)).fetchone()
        if existing:
            flash("问卷ID已存在", "error")
            conn.close()
            return render_template("admin_add_survey.html", all_groups=get_all_groups())
        
        try:
            # 添加问卷
            conn.execute(
                'INSERT INTO surveys (survey_id, title, description, is_active, access_type) VALUES (?, ?, ?, ?, ?)',
                (survey_id, title, description, is_active, access_type)
            )
            
            # 如果是组权限，添加组权限记录
            if access_type == 'groups' and selected_groups:
                for group_id in selected_groups:
                    if group_id:
                        conn.execute(
                            'INSERT INTO survey_group_access (survey_id, group_id) VALUES (?, ?)',
                            (survey_id, int(group_id))
                        )
            
            conn.commit()
            flash("问卷添加成功", "success")
            conn.close()
            return redirect(url_for('admin_surveys'))
        except Exception as e:
            flash(f"添加问卷失败: {e}", "error")
            conn.close()
            return render_template("admin_add_survey.html", all_groups=get_all_groups())
    
    all_groups = get_all_groups()
    return render_template("admin_add_survey.html", all_groups=all_groups)

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
    
    # 获取当前问卷的组权限
    current_groups = conn.execute('''
        SELECT group_id FROM survey_group_access WHERE survey_id = ?
    ''', (survey_id,)).fetchall()
    current_group_ids = [str(g['group_id']) for g in current_groups]
    
    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description", "")
        is_active = request.form.get("is_active") == "on"
        access_type = request.form.get("access_type", "all")
        selected_groups = request.form.getlist("selected_groups")
        
        if not title:
            flash("标题不能为空", "error")
            conn.close()
            return render_template("admin_edit_survey.html", 
                                 survey=survey, 
                                 all_groups=get_all_groups(),
                                 current_group_ids=current_group_ids)
        
        try:
            # 更新问卷信息
            conn.execute(
                'UPDATE surveys SET title = ?, description = ?, is_active = ?, access_type = ? WHERE survey_id = ?',
                (title, description, is_active, access_type, survey_id)
            )
            
            # 删除旧的组权限
            conn.execute('DELETE FROM survey_group_access WHERE survey_id = ?', (survey_id,))
            
            # 如果是组权限，添加新的组权限记录
            if access_type == 'groups' and selected_groups:
                for group_id in selected_groups:
                    if group_id:
                        conn.execute(
                            'INSERT INTO survey_group_access (survey_id, group_id) VALUES (?, ?)',
                            (survey_id, int(group_id))
                        )
            
            conn.commit()
            flash("问卷更新成功", "success")
            conn.close()
            return redirect(url_for('admin_surveys'))
        except Exception as e:
            flash(f"更新问卷失败: {e}", "error")
    
    all_groups = get_all_groups()
    conn.close()
    return render_template("admin_edit_survey.html", 
                         survey=survey, 
                         all_groups=all_groups,
                         current_group_ids=current_group_ids)

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
    print("🚀 启动问卷调查系统...")
    print("📋 初始化数据库...")
    init_db()
    print("🧹 清理重复数据...")
    clean_duplicate_root_groups()
    print("✅ 系统启动完成！")
    print("🌐 访问地址: http://localhost:5000")
    print("👤 默认管理员: admin / admin123")
    print("-" * 50)
    app.run(host="0.0.0.0", port=5000, debug=True)
