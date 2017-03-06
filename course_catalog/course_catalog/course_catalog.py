# import sqlite3
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__, instance_relative_config=True)
# app = Flask(__name__)
app.config.from_object('course_catalog.default_settings')
# TODO: Why debug not working?
app.config.from_pyfile('config.py', silent=True)
# app.run(host='0.0.0.0', port=5000)
db = SQLAlchemy(app)

import views

def init_db():
    db.create_all()
