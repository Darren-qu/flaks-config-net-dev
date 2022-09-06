from exts import db_mysql
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


class User(db_mysql.Model, UserMixin):
    __tablename__ = "user_info"
    id = db_mysql.Column(db_mysql.Integer, primary_key=True, autoincrement=True)
    user_type = db_mysql.Column(db_mysql.String(255))
    username = db_mysql.Column(db_mysql.String(255))
    password_hash = db_mysql.Column(db_mysql.String(128))  # 密码散列值

    def set_password(self, password):  # 用来设置密码的方法，接受密码作为参数
        self.password_hash = generate_password_hash(password)  # 将生成的密码保持到对应字段

    def validate_password(self, password):  # 用于验证密码的方法，接受密码作为参数
        return check_password_hash(self.password_hash, password)  # 返回布尔值


class ConfigDevices(db_mysql.Model):
    __tablename__ = "config_device"
    id = db_mysql.Column(db_mysql.Integer, primary_key=True, autoincrement=True)
    ip_address = db_mysql.Column(db_mysql.String(255), nullable=False)
    hostname = db_mysql.Column(db_mysql.String(255), nullable=False)
    username = db_mysql.Column(db_mysql.String(255), nullable=False)
    password = db_mysql.Column(db_mysql.String(255), nullable=False)
    ssh_port = db_mysql.Column(db_mysql.Integer, nullable=False, default=22)
    vendor = db_mysql.Column(db_mysql.String(255), nullable=False)


class ConfigDevicesLog(db_mysql.Model):
    __tablename__ = "config_device_log"
    id = db_mysql.Column(db_mysql.Integer, primary_key=True, autoincrement=True)
    remote_ip_addr = db_mysql.Column(db_mysql.String(255), nullable=False, default="None")
    target = db_mysql.Column(db_mysql.String(255), nullable=False)
    action = db_mysql.Column(db_mysql.String(255), nullable=False)
    status = db_mysql.Column(db_mysql.String(255), nullable=False)
    time = db_mysql.Column(db_mysql.String(255), nullable=False)
    messages = db_mysql.Column(db_mysql.String(255), nullable=False)