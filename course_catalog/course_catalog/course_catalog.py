from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Set filenames relative to 'instance' directory
app = Flask(__name__)
# Attempt to use instance/config.py. If does not exist, uses default.config
app.config.from_pyfile('default_config.py')
app.config.from_pyfile('./instance/config.py', silent=True)
# Create database instance
db = SQLAlchemy(app)

# Import statement not at top as recommended in Flask docs
import views
