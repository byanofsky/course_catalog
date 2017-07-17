from flask import Flask

# Set filenames relative to 'instance' directory
app = Flask(__name__, instance_relative_config=True)
# Attempt to use instance/config.py. If does not exist, uses default.config
app.config.from_object('course_catalog.default_config')
app.config.from_pyfile('config.py', silent=True)

# Import statement not at top as recommended in Flask docs
import views
