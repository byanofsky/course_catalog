import sqlite3
from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash

app = Flask(__name__, instance_relative_config=True)
app.config.from_object('course_catalog.default_settings')
app.config.from_pyfile('config.py', silent=True)
# app.run(host='0.0.0.0', port=5000)

import views
