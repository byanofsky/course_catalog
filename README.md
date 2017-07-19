# Course Catalog

A simple course catalog. Working example here: https://bay-course-catalog.herokuapp.com

Users can add courses and organize them by school and category.

Users are able to create accounts or log in through OAuth providers.

Item Catalog project for Udacity Full Stack Nanodegree, built with
Flask framework, using Flask-SQLAlchemy.

## Dependencies

Python 2.7.x

All other dependencies will be installed during setup below.

## Installation

1. Clone this repository to your local machine
2. `cd` to `course_catalog/course_catalog`
3. [Optional, but highly recommended] Create a new virtual environment using
[virtualenv](https://pypi.python.org/pypi/virtualenv).
```
virtualenv venv
. venv/bin/activate
```
4. Run `pip install --editable .` This will install all needed dependencies.
5. Create an instance directory to store database and configuration files:
```
mkdir instance
```
6. Copy the default config file to the `instance` directory:
```
cp course_catalog/default_config.py instance/config.py
```
7. Open the newly created `config.py` and add a SECRET_KEY as well as IDs and Secret Keys for all OAuth providers
8. Start python in your terminal. Run the code below to create the database:
```
from course_catalog.course_catalog import *
init_db()
```
9. Run the following in your command line to assign the flask app:
```
export FLASK_APP=course_catalog
```
10. Turn on debug mode on development only. If it is production, turn this off (0):
```
export FLASK_DEBUG=1
```
11. Start the application with `flask run`
12. Open `localhost:5000` in your browser

## Testing

To run testing suite:
```
python tests/test_course_catalog.py
```

## TODO

* Add additional functionality.
* Finetune this README file.
* Add to the testing suite.
