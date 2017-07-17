from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Set filenames relative to 'instance' directory
app = Flask(__name__, instance_relative_config=True)
# Attempt to use instance/config.py. If does not exist, uses default.config
app.config.from_object('course_catalog.default_config')
app.config.from_pyfile('config.py', silent=True)
# Create database instance
db = SQLAlchemy(app)

# Import statement not at top as recommended in Flask docs
import views


# Function that can be used to initiate database
# TODO: might be able to add this to a setup file
def init_db():
    db.create_all()
