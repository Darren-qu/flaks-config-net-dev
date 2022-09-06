from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user
from models import User
from blueprints import net_config_device
from flask_migrate import Migrate
from exts import db_mysql
import click
import config

app = Flask(__name__)
app.config['SECRET_KEY'] = '365818fd398f1bc6db5743907791d6c067e9c8362a8d742d74c6e1c811f2abbf'

app.config.from_object(config)

db_mysql.init_app(app)

with app.app_context():
    db_mysql.create_all()


app.register_blueprint(net_config_device)

migrate = Migrate(app, db_mysql)


login_manager = LoginManager(app)
login_manager.login_view = 'login'


# 使用 click.option() 装饰器设置的两个选项分别用来接受输入用户名和密码。执行 flask admin 命令，输入用户名和密码后，即可创建管理员账户。
@app.cli.command()
@click.option('--username', prompt=True, help='The username used to login.')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='The password used to login.')
def admin(username, password):
    """Create user."""
    if db_mysql.session.query(User.id).filter_by(username=username).scalar() is not None:
        user = User.query.filter_by(username=username).first()
        click.echo('Updating user...')
        user.set_password(password)  # 设置密码
    else:
        click.echo('Creating user...')
        user = User(username=username, user_type='Admin')
        user.set_password(password)  # 设置密码
        db_mysql.session.add(user)

    db_mysql.session.commit()  # 提交数据库会话
    click.echo('Done.')


@login_manager.user_loader
def load_user(user_id):  # 创建用户加载回调函数，接受用户 ID 作为参数
    user = User.query.get(int(user_id))  # 用 ID 作为 User 模型的主键查询对应的用户
    return user  # 返回用户对象


@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == "GET":
        return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Invalid input.')
            return redirect(url_for('login'))
        user = User.query.filter_by(username=username).first()
        # 验证用户名和密码是否一致

        if username == user.username and user.validate_password(password):
            login_user(user)  # 登入用户
            # flash('Login success.')
            return redirect(url_for('config_devices.config_devices'))  # 重定向到主页

        flash('Invalid username or password.')  # 如果验证失败，显示错误消息
        return redirect(url_for('login'))  # 重定向回登录页面

    return render_template('login.html')


@app.route('/logout')
@login_required  # 用于视图保护，后面会详细介绍
def logout():
    logout_user()  # 登出用户
    flash('Goodbye.')
    return redirect(url_for('login'))  # 重定向回首页


if __name__ == '__main__':
    app.run(debug=True)
