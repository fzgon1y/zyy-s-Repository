from app import app
from models import db, User

with app.app_context():
    # 添加管理员用户
    admin = User(username="admin", is_admin=True)
    admin.set_password("admin123")  # 使用哈希方法
    db.session.add(admin)

    # 添加普通用户
    user = User(username="user")
    user.set_password("user123")
    db.session.add(user)

    db.session.commit()