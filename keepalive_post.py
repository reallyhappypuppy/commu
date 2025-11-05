# keepalive_post.py
import time, traceback
from datetime import datetime
from werkzeug.security import generate_password_hash

try:
    from app import app, db, User, Post
except Exception as e:
    print("ERROR: app.py에서 필요한 객체를 가져오지 못했습니다.")
    print(e)
    raise

SLEEP_SECONDS_BEFORE_DELETE = 10
BOT_USERNAME = "auto-bot"
BOT_PASSWORD = "auto-bot-pass"

def create_transient_post():
    try:
        with app.app_context():
            bot = User.query.filter_by(username=BOT_USERNAME).first()
            if not bot:
                bot = User(username=BOT_USERNAME,
                           password=generate_password_hash(BOT_PASSWORD, method='pbkdf2:sha256'))
                db.session.add(bot)
                db.session.commit()
                print(f"Created bot user id={bot.id}")

            now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            title = f"[AUTO-TEST] {now}"
            content = f"This is an automated test Pebble created at {now}. It will be removed after {SLEEP_SECONDS_BEFORE_DELETE} seconds."
            post = Post(title=title, content=content, user_id=bot.id)
            db.session.add(post)
            db.session.commit()
            print(f"Created post id={post.id}")
            return post.id
    except Exception:
        traceback.print_exc()
        return None

def delete_post_by_id(post_id):
    try:
        with app.app_context():
            p = Post.query.get(post_id)
            if p:
                db.session.delete(p)
                db.session.commit()
                print(f"Deleted post id={post_id}")
            else:
                print("Post already gone.")
    except Exception:
        traceback.print_exc()

if __name__ == "__main__":
    pid = create_transient_post()
    if pid:
        time.sleep(SLEEP_SECONDS_BEFORE_DELETE)
        delete_post_by_id(pid)
    else:
        print("Failed to create transient post.")
