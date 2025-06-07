from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.fields import EmailField
from flask_wtf import RecaptchaField  # 正确导入
from wtforms.validators import DataRequired
from werkzeug.utils import secure_filename
from models import db, User, File
import os
from captcha.image import ImageCaptcha
import random
import string
from flask import session, send_file
from io import BytesIO

app = Flask(__name__)
app.config["SECRET_KEY"] = "your-secret-key-here"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["RECAPTCHA_PUBLIC_KEY"] = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"
app.config["RECAPTCHA_PRIVATE_KEY"] = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'instance', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 初始化数据库和登录管理
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# 登录表单
class LoginForm(FlaskForm):
    username = StringField("用户名", validators=[DataRequired()])
    password = PasswordField("密码", validators=[DataRequired()])
    captcha = StringField("验证码", validators=[DataRequired()])
    submit = SubmitField("登录")

# 个人信息表单
class ProfileForm(FlaskForm):
    email = EmailField("邮箱")
    submit = SubmitField("保存")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
@login_required
def index():
    if current_user.is_admin:
        return redirect(url_for("admin"))
    else:
        return redirect(url_for("user"))

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        class LoginForm(FlaskForm):
            username = StringField("用户名", validators=[DataRequired()])
            password = PasswordField("密码", validators=[DataRequired()])
            captcha = StringField("验证码", validators=[DataRequired()])
            submit = SubmitField("登录")         
        if form.captcha.data.strip().upper() != session.get('captcha_code', ''):
            flash("验证码错误")
            return render_template("login.html", form=form)
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for("index"))
        flash("用户名或密码错误")
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for("index"))
    return render_template("admin.html", username=current_user.username)

@app.route("/admin/users")
@login_required
def admin_users():
    if not current_user.is_admin:
        return "无权限", 403
    users = User.query.all()
    return render_template("admin_users.html", users=users)

@app.route("/user")
@login_required
def user():
    return render_template("user.html", username=current_user.username)

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    form = ProfileForm(obj=current_user)
    if form.validate_on_submit():
        current_user.email = form.email.data
        db.session.commit()
        flash("信息已更新")
        return redirect(url_for("profile"))
    return render_template("profile.html", form=form)

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        file = request.files.get("file")
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            new_file = File(filename=filename, uploader_id=current_user.id)
            db.session.add(new_file)
            db.session.commit()
            flash("上传成功")
            return redirect(url_for("files"))
    return render_template("upload.html")

@app.route("/files")
@login_required
def files():
    if current_user.is_admin:
        files = File.query.all()
    else:
        files = File.query.filter_by(uploader_id=current_user.id).all()
    return render_template("files.html", files=files)

@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    file = File.query.get_or_404(file_id)
    if not current_user.is_admin and file.uploader_id != current_user.id:
        return "无权限", 403
    return send_from_directory(app.config['UPLOAD_FOLDER'], file.filename, as_attachment=True)

# 生成验证码图片的路由
@app.route("/captcha")
def captcha():
    image = ImageCaptcha()
    code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    session['captcha_code'] = code
    data = image.generate(code)
    return send_file(data, mimetype='image/png')

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)