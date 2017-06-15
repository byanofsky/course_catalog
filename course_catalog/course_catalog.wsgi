#!/usr/bin/python
import sys
# import logging
# logging.basicConfig(stream=sys.stderr)
# sys.path.insert(0, '/var/www/html/course_catalog')

# sys.stdout = sys.stderr

activate_this = '/var/www/html/course_catalog/venv/bin/activate_this.py'
execfile(activate_this, dict(__file__=activate_this))

from course_catalog import app as application
