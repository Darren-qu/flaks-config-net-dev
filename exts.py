from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet

key = b'yF0P1mLcYoMznwQPSPJSfT1ucnUM-qje8j0PUqXtZKc='
fernet = Fernet(key)

db_mysql = SQLAlchemy()
