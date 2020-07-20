import os
from flask import Flask
from flask_dropzone import Dropzone
from flaskext.mysql import MySQL

app = Flask(__name__)
mysql = MySQL()
basedir = os.path.abspath(os.path.dirname(__file__))
app.config.update(
    UPLOADED_PATH=os.path.join(basedir, 'static/uploads'),
    TEMPORARY_PATH=os.path.join(basedir, 'static/temp'),
    OUTPUT_PATH=os.path.join(basedir, 'static/outputs'),
    SECRET_KEY='frommixigamingwithlove',
    # Flask-Dropzone config:
    DROPZONE_ALLOWED_FILE_CUSTOM = True,
    DROPZONE_ALLOWED_FILE_TYPE = '.apk, .zip',
    DROPZONE_MAX_FILE_SIZE = 768,
    DROPZONE_REDIRECT_VIEW = 'handle',  # set redirect view
    # MySQL configurations
    MYSQL_DATABASE_USER = 'root',
    MYSQL_DATABASE_PASSWORD = '09061999',
    MYSQL_DATABASE_DB = '3heroes',
    MYSQL_DATABASE_HOST = 'localhost',
)

dropzone = Dropzone(app)
mysql.init_app(app)

from application import routes