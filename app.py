import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# -----------------------
# app + DB 설정
# -----------------------
app = Flask(__name__)
# 환경변수 DATABASE_URL이 있으면 사용, 없으면 sqlite 폴백
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///rez.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-secret')

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# -----------------------
# SITE 정보 (템플릿에서 사용)
# -----------------------
@app.context_processor
def inject_site_name():
    return {
        "SITE_NAME": "REZEnesis",
        "POST_NAME_SINGULAR": "Pebble",
        "POST_NAME_PLURAL": "Pebbles"
    }

# -----------------------
# 모델 정의
# -----------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False)
    is_developer = db.Column(db.Boolean, default=False)
    posts = db.relationship('Post', backref='user', lazy=True)
    comments = db.relationship('Comment', backref='user', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='post', cascade="all, delete-orphan", lazy=True)
    likes = db.relationship('Like', backref='post', cascade="all, delete-orphan", lazy=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    is_like = db.Column(db.Boolean, nullable=False)  # True=like / False=dislike

# -----------------------
# 로그인 설정
# -----------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -----------------------
# 라우트
# -----------------------
@app.route('/')
def index():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    likes_counts = {p.id: Like.query.filter_by(post_id=p.id, is_like=True).count() for p in posts}
    dislikes_counts = {p.id: Like.query.filter_by(post_id=p.id, is_like=False).count() for p in posts}
    return render_template('index.html', posts=posts, likes_counts=likes_counts, dislikes_counts=dislikes_counts)

@app.route('/create', methods=['GET','POST'])
@login_required
def create_post():
    if request.method == 'POST':
        title = request.form.get('title','').strip()
        content = request.form.get('content','').strip()
        if not title or not content:
            flash("제목과 내용을 입력하세요.")
            return redirect(url_for('create_post'))
        post = Post(title=title, content=content, user_id=current_user.id)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('create_post.html')

@app.route('/post/<int:post_id>', methods=['GET','POST'])
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)
    if request.method == 'POST':
        if not current_user.is_authenticated:
            flash("댓글을 작성하려면 로그인하세요.")
            return redirect(url_for('login'))
        content = request.form.get('content','').strip()
        if content:
            comment = Comment(post_id=post.id, user_id=current_user.id, content=content)
            db.session.add(comment)
            db.session.commit()
            return redirect(url_for('post_detail', post_id=post.id))
    comments = Comment.query.filter_by(post_id=post.id).order_by(Comment.created_at.asc()).all()
    likes_count = Like.query.filter_by(post_id=post.id, is_like=True).count()
    dislikes_count = Like.query.filter_by(post_id=post.id, is_like=False).count()
    return render_template('post_detail.html', post=post, comments=comments, likes_count=likes_count, dislikes_count=dislikes_count)

@app.route('/like/<int:post_id>')
@login_required
def like(post_id):
    post = Post.query.get_or_404(post_id)
    existing = Like.query.filter_by(user_id=current_user.id, post_id=post.id).first()
    if existing:
        if existing.is_like:
            db.session.delete(existing)  # 취소
        else:
            existing.is_like = True
    else:
        db.session.add(Like(user_id=current_user.id, post_id=post.id, is_like=True))
    db.session.commit()
    return redirect(request.referrer or url_for('index'))

@app.route('/dislike/<int:post_id>')
@login_required
def dislike(post_id):
    post = Post.query.get_or_404(post_id)
    existing = Like.query.filter_by(user_id=current_user.id, post_id=post.id).first()
    if existing:
        if not existing.is_like:
            db.session.delete(existing)
        else:
            existing.is_like = False
    else:
        db.session.add(Like(user_id=current_user.id, post_id=post.id, is_like=False))
    db.session.commit()
    return redirect(request.referrer or url_for('index'))

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    # 작성자 or 개발자만 삭제 가능
    if post.user_id != current_user.id and not current_user.is_developer:
        flash("삭제 권한이 없습니다.")
        return redirect(url_for('index'))
    db.session.delete(post)
    db.session.commit()
    flash("게시물이 삭제되었습니다.")
    return redirect(url_for('index'))

# -----------------------
# 인증 라우트: signup / login / logout
# -----------------------
@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        password2 = request.form.get('password2','')
        if not username or not password:
            flash("아이디와 비밀번호를 입력하세요.")
            return redirect(url_for('signup'))
        if password != password2:
            flash("비밀번호 확인이 일치하지 않습니다.")
            return redirect(url_for('signup'))
        if User.query.filter_by(username=username).first():
            flash("이미 존재하는 사용자입니다.")
            return redirect(url_for('signup'))
        hashed = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed)
        db.session.add(new_user)
        db.session.commit()
        flash("회원가입 완료! 로그인하세요.")
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        flash("아이디 또는 비밀번호가 틀렸습니다.")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# -----------------------
# 개발자 계정 자동 생성 (앱 첫 시작 시 하나만 생성)
# -----------------------
def ensure_developer_account():
    dev_username = os.environ.get('DEV_USERNAME', 'dev')
    dev_password = os.environ.get('DEV_PASSWORD', 'devpass')
    with app.app_context():
        if not User.query.filter_by(username=dev_username).first():
            dev = User(username=dev_username,
                       password=generate_password_hash(dev_password, method='pbkdf2:sha256'),
                       is_developer=True)
            db.session.add(dev)
            db.session.commit()
            print(f"Developer account created: {dev_username}")

# -----------------------
# 실행
# -----------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        ensure_developer_account()
    # 개발용: host 0.0.0.0으로 외부접속 허용
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5001)), debug=True)
