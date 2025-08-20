from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///community.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

# ================================
# 데이터베이스 모델
# ================================
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_developer = db.Column(db.Boolean, default=False)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='posts')
    comments = db.relationship('Comment', backref='post', cascade="all, delete-orphan")
    likes = db.relationship('Like', backref='post', cascade="all, delete-orphan")

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='comments')
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    is_like = db.Column(db.Boolean, nullable=False)

# ================================
# 로그인 설정
# ================================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ================================
# 라우팅
# ================================
@app.route('/')
def index():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    likes_counts = {post.id: Like.query.filter_by(post_id=post.id, is_like=True).count() for post in posts}
    dislikes_counts = {post.id: Like.query.filter_by(post_id=post.id, is_like=False).count() for post in posts}
    return render_template('index.html', posts=posts, likes_counts=likes_counts, dislikes_counts=dislikes_counts)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        post = Post(title=title, content=content, user_id=current_user.id)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('create_post.html')

@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)
    if request.method == 'POST':
        if not current_user.is_authenticated:
            flash("댓글을 작성하려면 로그인하세요.")
            return redirect(url_for('login'))
        content = request.form['content']
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
            db.session.delete(existing)
        else:
            existing.is_like = True
    else:
        db.session.add(Like(user_id=current_user.id, post_id=post.id, is_like=True))
    db.session.commit()
    return redirect(request.referrer)

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
    return redirect(request.referrer)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id and not current_user.is_developer:
        flash("삭제 권한이 없습니다.")
        return redirect(url_for('index'))
    db.session.delete(post)
    db.session.commit()
    flash("게시물이 삭제되었습니다.")
    return redirect(url_for('index'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash("아이디 또는 비밀번호가 틀렸습니다.")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method=='POST':
        if User.query.filter_by(username=request.form['username']).first():
            flash("이미 존재하는 사용자입니다.")
            return redirect(url_for('signup'))
        if request.form['password'] != request.form['password2']:
            flash("비밀번호와 확인이 일치하지 않습니다.")
            return redirect(url_for('signup'))
        hashed_pw = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        new_user = User(username=request.form['username'], password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("회원가입 완료! 로그인하세요.")
        return redirect(url_for('login'))
    return render_template('signup.html')

# ================================
# 실행 및 DB 초기화
# ================================
if __name__ == '__main__':
    with app.app_context():
        db.drop_all()      # 기존 테이블 초기화
        db.create_all()    # 새 테이블 생성
        print("DB와 테이블 초기화 완료")

        # 개발자 계정 생성
        if not User.query.filter_by(username='dev').first():
            dev_user = User(username='dev',
                            password=generate_password_hash('devpass', method='pbkdf2:sha256'),
                            is_developer=True)
            db.session.add(dev_user)
            db.session.commit()
            print("개발자 계정(dev) 생성 완료")
            
    app.run(host='0.0.0.0', port=5001, debug=True)
