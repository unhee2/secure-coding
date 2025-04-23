import sqlite3
import uuid
import re
import logging
import html
import time
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify
from flask_socketio import SocketIO, send, join_room, emit
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta



app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)  # 세션 만료 기간 설정

# CSRF 보호 설정
csrf = CSRFProtect(app)
DATABASE = 'market.db'
socketio = SocketIO(app)
limiter = Limiter(get_remote_address,app=app,)
logging.basicConfig(level=logging.INFO)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 사용자 정보를 템플릿에 주입입
@app.context_processor
def inject_user():
    user = None
    if 'user_id' in session:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
    return dict(current_user=user)


# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                balance INTEGER DEFAULT 0,
                role TEXT DEFAULT 'user',
                status TEXT DEFAULT 'active'
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                status TEXT DEFAULT 'active'
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        
        # 송금 테이블
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transfer (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.commit()
# 내부 에러 메시지
@app.errorhandler(500)
def internal_error(e):
    # 로깅 가능 (예: print, logging 모듈 등)
    print(f"Internal Error: {e}")
    return render_template("error.html", message="알 수 없는 오류가 발생했습니다."), 500

@app.errorhandler(404)
def not_found_error(e):
    return render_template("error.html", message="페이지를 찾을 수 없습니다."), 404


# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not (4 <= len(username) <= 20):
            flash("사용자명은 4자 이상 20자 이하로 입력해주세요.")
            return redirect(url_for('register'))

        if not re.match("^[a-zA-Z0-9_]+$", username):
            flash("사용자명은 영문, 숫자, 밑줄(_)만 사용할 수 있습니다.")
            return redirect(url_for('register'))

        if len(password) < 6:
            flash("비밀번호는 6자 이상이어야 합니다.")
            return redirect(url_for('register'))
        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        hashed_password = generate_password_hash(password)
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, hashed_password))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # 로그인 시도 제한
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']    
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ? ", (username,))
        user = cursor.fetchone()
        if user and check_password_hash(user['password'], password):
            if user['status'] == 'blocked':
                flash('정지된 계정입니다. 관리자에게 문의하세요.')
                return redirect(url_for('login'))
            # 관리자 로그인 처리
            if user['role']=='admin':
                session['user_id'] = user['id']
                flash('관리자 로그인 성공!')
                session.permanent = True  # 세션을 영구적으로 설정
                return redirect(url_for('admin_dashboard'))
            session['user_id'] = user['id']
            flash('로그인 성공!')
            session.permanent = True  # 세션을 영구적으로 설정
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        price = request.form['price'].strip()

        # 🔒 입력값 유효성 검증
        if not title or len(title) > 100:
            flash("제목은 1~100자 이내로 입력해주세요.")
            return redirect(url_for('new_product'))

        if not description or len(description) > 1000:
            flash("설명은 1~1000자 이내로 입력해주세요.")
            return redirect(url_for('new_product'))

        if not price.isdigit() or int(price) <= 0 or int(price) > 10000000:
            flash("가격은 1 이상 10,000,000 이하의 정수로 입력해주세요.")
            return redirect(url_for('new_product'))
        
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        target_id = request.form['target_id'].strip()
        reason = request.form['reason'].strip()

        # 유효성 검증
        if not target_id or not reason or len(reason) > 500:
            flash("올바른 신고 내용을 입력해주세요.")
            return redirect(url_for('report'))

        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())

        # 로그 기록
        logging.info(f"신고 접수: 사용자 {session['user_id']} → 대상 {target_id} | 사유: {reason[:100]}...")

        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('report.html')

# 유저별 최근 메시지 전송 시간 기록
last_message_time = {}


# 실시간 채팅: 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    user_id = session.get('user_id')
    now = time.time()

    # ✅ Rate limit: 1초에 1회 이하로 제한
    if user_id:
        last = last_message_time.get(user_id, 0)
        if now - last < 1:
            return  # 무시
        last_message_time[user_id] = now

    message = data.get('message', '').strip()
    username = data.get('username', '익명')

    # 메시지 길이 검증
    if not isinstance(message, str) or len(message) == 0 or len(message) > 500:
        return  # 메시지 무시

    # XSS 방지 처리
    #safe_message = html.escape(message)
    safe_username = html.escape(username)

    data['message_id'] = str(uuid.uuid4())
    data['message'] = message
    data['username'] = safe_username

    send(data, broadcast=True)


# 1:1 채팅: 특정 방 입장
@socketio.on('join_room')
def handle_join_room(data):
    room = data['room']
    join_room(room)

# 1:1 채팅 메시지 전송
@socketio.on('send_private_message')
def handle_private_message(data):
    user_id = session.get('user_id')
    now = time.time()

    if user_id:
        last = last_message_time.get(user_id, 0)
        if now - last < 1:
            return
        last_message_time[user_id] = now

    room = data['room']
    message = data.get('message', '').strip()
    senderName = data.get('senderName', '익명')

    if not isinstance(message, str) or len(message) == 0 or len(message) > 500:
        return

    #safe_message = html.escape(message)
    safe_sender = html.escape(senderName)

    emit('receive_message', {
        'message': message,
        'senderName': safe_sender
    }, room=room)


# 사용자 목록 조회
@app.route('/users')
def user_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username, bio FROM user")
    users = cursor.fetchall()

    return render_template('user_list.html', users=users)

# 비밀번호 변경 기능
@app.route('/profile/password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()

    if request.method == 'POST':
        current_pw = request.form['current_password']
        new_pw = request.form['new_password']
        confirm_pw = request.form['confirm_password']

        if not check_password_hash(user['password'], current_pw):
            flash('현재 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('change_password'))

        if new_pw != confirm_pw:
            flash('새 비밀번호가 일치하지 않습니다.')
            return redirect(url_for('change_password'))

        hashed_new = generate_password_hash(new_pw)
        cursor.execute("UPDATE user SET password = ? WHERE id = ?", (hashed_new, session['user_id']))
        db.commit()
        flash('비밀번호가 성공적으로 변경되었습니다.')
        return redirect(url_for('profile'))

    return render_template('change_password.html')

# 내 상품 목록 조회
@app.route('/my-products')
def my_products():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE seller_id = ?", (session['user_id'],))
    products = cursor.fetchall()

    return render_template('my_products.html', products=products)


# 상품 수정
@app.route('/product/edit/<product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product or product['seller_id'] != session['user_id']:
        flash("상품을 수정할 권한이 없습니다.")
        return redirect(url_for('my_products'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']

        # 🔒 입력 검증 추가
        if not title or len(title) > 100:
            flash("제목은 1~100자 이내로 입력해주세요.")
            return redirect(url_for('edit_product', product_id=product_id))

        if not description or len(description) > 1000:
            flash("설명은 1~1000자 이내로 입력해주세요.")
            return redirect(url_for('edit_product', product_id=product_id))

        if not price.isdigit() or int(price) <= 0 or int(price) > 10000000:
            flash("가격은 1 이상 10,000,000 이하의 정수로 입력해주세요.")
            return redirect(url_for('edit_product', product_id=product_id))

        cursor.execute("""
            UPDATE product
            SET title = ?, description = ?, price = ?
            WHERE id = ?
        """, (title, description, price, product_id))
        db.commit()
        flash("상품 정보가 수정되었습니다.")
        return redirect(url_for('view_product', product_id=product_id))

    return render_template('edit_product.html', product=product)

# 상품 삭제
@app.route('/product/delete/<product_id>', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product or product['seller_id'] != session['user_id']:
        flash("상품을 삭제할 권한이 없습니다.")
        return redirect(url_for('my_products'))

    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash("상품이 삭제되었습니다.")
    return redirect(url_for('my_products'))

# 1:1 채팅 기능
@app.route('/chat/<target_id>')
def chat(target_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    # 대상 사용자 확인
    cursor.execute("SELECT * FROM user WHERE id = ?", (target_id,))
    target_user = cursor.fetchone()

    if not target_user:
        flash("대상 사용자를 찾을 수 없습니다.")
        return redirect(url_for('user_list'))

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    return render_template('chat.html', target_user=target_user, current_user=current_user)

# 사용자간 송금 기능
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 사용자 목록 조회
    cursor.execute("SELECT id, username FROM user WHERE id != ?", (session['user_id'],))
    users = cursor.fetchall()

    if request.method == 'POST':
        receiver_id = request.form['receiver_id']
        amount = int(request.form['amount'])

        # 현재 사용자 잔액 조회
        cursor.execute("SELECT balance FROM user WHERE id = ?", (session['user_id'],))
        sender_balance = cursor.fetchone()['balance']

        if amount <= 0:
            flash("0원 이상의 금액을 입력해주세요.")
        elif amount > sender_balance:
            flash("잔액이 부족합니다.")
        else:
            # 송금 처리
            cursor.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (amount, session['user_id']))
            cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, receiver_id))

            # 기록 저장
            transfer_id = str(uuid.uuid4())
            cursor.execute("INSERT INTO transfer (id, sender_id, receiver_id, amount) VALUES (?, ?, ?, ?)",
                           (transfer_id, session['user_id'], receiver_id, amount))
            db.commit()
            flash("송금이 완료되었습니다.")
            return redirect(url_for('dashboard'))

    return render_template('transfer.html', users=users)

# 상품 검색
@app.route('/search')
def search():
    query = request.args.get('q', '')

    products = []
    if query:
        db = get_db()
        cursor = db.cursor()
        wildcard = f'%{query}%'
        cursor.execute("""
            SELECT * FROM product
            WHERE (title LIKE ? OR description LIKE ?)
              AND status = 'active'
        """, (wildcard, wildcard))
        products = cursor.fetchall()

    return render_template('search_results.html', query=query, products=products)

# 관리자 대시보드
@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    if current_user['role'] != 'admin':
        flash("관리자만 접근할 수 있습니다.")
        return redirect(url_for('dashboard'))

    # 전체 사용자, 상품, 신고 조회
    cursor.execute("SELECT * FROM user")
    users = cursor.fetchall()

    cursor.execute("SELECT * FROM product")
    products = cursor.fetchall()

    cursor.execute("""
        SELECT report.*, u.username AS reporter_name
        FROM report
        JOIN user u ON report.reporter_id = u.id
    """)
    reports = cursor.fetchall()

    return render_template("admin_dashboard.html", users=users, products=products, reports=reports)

# 관리자 기능 - 사용자 정지
@app.route('/admin/block-user/<target_id>', methods=['POST'])
def block_user(target_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 현재 로그인한 사용자가 관리자임을 확인
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    if current_user['role'] != 'admin':
        flash("관리자 권한이 필요합니다.")
        return redirect(url_for('dashboard'))

    # 사용자 정지 처리
    cursor.execute("UPDATE user SET status = 'blocked' WHERE id = ?", (target_id,))
    db.commit()
    flash("사용자가 정지되었습니다.")
    return redirect(url_for('admin_dashboard'))

# 관리자 기능 - 상품 삭제
@app.route('/admin/delete-product/<target_id>', methods=['POST'])
def delete_reported_product(target_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 관리자 여부 확인
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    if current_user['role'] != 'admin':
        flash("관리자 권한이 필요합니다.")
        return redirect(url_for('dashboard'))

    # 상품 상태를 'deleted'로 업데이트 (물리 삭제 아님)
    cursor.execute("UPDATE product SET status = 'deleted' WHERE id = ?", (target_id,))
    db.commit()
    flash("상품이 삭제 처리되었습니다.")
    return redirect(url_for('admin_dashboard'))


# 에러 로그 기록 설정 (콘솔 또는 파일로 저장 가능)
logging.basicConfig(level=logging.INFO)

@app.errorhandler(400)
def bad_request(error):
    logging.warning(f"[400 Bad Request] {error}")
    return render_template("error.html", message="잘못된 요청입니다."), 400

@app.errorhandler(403)
def forbidden(error):
    logging.warning(f"[403 Forbidden] {error}")
    return render_template("error.html", message="접근이 금지되었습니다."), 403

@app.errorhandler(404)
def not_found(error):
    logging.warning(f"[404 Not Found] {error}")
    return render_template("error.html", message="페이지를 찾을 수 없습니다."), 404

@app.errorhandler(500)
def internal_error(error):
    logging.error(f"[500 Internal Server Error] {error}")
    return render_template("error.html", message="서버 내부 오류가 발생했습니다. 잠시 후 다시 시도해주세요."), 500

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=False)
