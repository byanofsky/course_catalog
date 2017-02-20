import os
import sqlite3
from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash

# app = Flask(__name__, instance_relative_config=True)
app = Flask(__name__)
app.config.from_object(__name__)

app.config.update(dict(
    DATABASE=os.path.join(app.root_path, 'course_catalog.db'),
    SECRET_KEY='development key'
))

# app.config.from_object('course_catalog.default_settings')
# app.config.from_pyfile('config.py', silent=True)
app.config.from_envvar('FLASKR_SETTINGS', silent=True)

# app.run(host='0.0.0.0', port=5000)


@app.route('/')
def hello_world():
    return 'Hello, World!'
