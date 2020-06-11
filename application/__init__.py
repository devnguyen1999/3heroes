import os
from flask import Flask
from flask_dropzone import Dropzone

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config.update(
    UPLOADED_PATH=os.path.join(basedir, 'static/uploads'),
    OUTPUT_PATH=os.path.join(basedir, 'static/outputs'),
    # Flask-Dropzone config:
    DROPZONE_ALLOWED_FILE_CUSTOM=True,
    DROPZONE_ALLOWED_FILE_TYPE='.apk',
    DROPZONE_MAX_FILE_SIZE=1024,
)
dropzone = Dropzone(app)

from application import routes