import random, string
from functools import wraps

from flask import render_template, session, request, make_response, flash, redirect, url_for
from flask_bcrypt import Bcrypt
import requests

from course_catalog import app
from models import User, School
from modules.form_validation import check_registration, check_login, check_add_school, check_edit_school


bcrypt = Bcrypt(app)


# Function decorator for handling login requirements
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_id') is None:
            flash('Please log in to continue')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
@app.route('/courses/')
def view_all_courses():
    courses = None
    return render_template('view_all_courses.html', courses=courses)


@app.route('/register/', methods=['GET', 'POST'])
def register():
    errors = None
    fields = None
    if request.method == 'POST':
        fields = {
            'email': request.form['email'],
            'name': request.form['name'],
            'password': request.form['password'],
            'verify_password': request.form['verify_password']
        }
        errors = check_registration(fields, User.get_by_email(fields['email']))
        if not errors:
            user = User.create(
                name=fields['name'],
                email=fields['email'],
                pwhash=bcrypt.generate_password_hash(fields['password'], 10)
            )
            session['user_id'] = user.id
            flash('You were successfully registered')
            return redirect(url_for('view_all_courses'))

    return render_template('register.html', fields=fields, errors=errors)


@app.route('/login/', methods=['GET', 'POST'])
def login():
    errors = None
    fields = None
    if request.method == 'POST':
        fields = {
            'email': request.form['email'],
            'password': request.form['password']
        }
        errors = check_login(fields=fields)
        if not errors:
            user = User.get_by_email(fields['email'])
            if not user:
                errors['user_exists'] = True
            elif not bcrypt.check_password_hash(user.pwhash, fields['password']):
                errors['password'] = True
            else:
                session['user_id'] = user.id
                flash('You were successfully logged in')
                redirect_url = request.args.get('next', url_for('view_all_courses'))
                return redirect(redirect_url)
    # Creates and stores an anti-forgery token
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    session['state'] = state
    return render_template('login.html', STATE=state, fields=fields, errors=errors)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    # TODO: this needs testing if user can't log in
    # if 1 == 1:
    if request.args.get('state') != session['state']:
        response = make_response(json.dumps('Invalid state parameter'))
        response.headers['Content-Type'] = 'application/json'
        return response
    short_lived_token = request.data

    # Exchange client token for server-side token
    url = 'https://graph.facebook.com/oauth/access_token'
    payload = {
        'grant_type': 'fb_exchange_token',
        'client_id': app.config['FB_APP_ID'],
        'client_secret': app.config['FB_APP_SECRET'],
        'fb_exchange_token': short_lived_token
    }
    r = requests.get(url, params=payload)
    token = r.text.split("&")[0]

    # Get user info from api
    url = 'https://graph.facebook.com/v2.8/me?%s&fields=name,id,email' % token
    r = requests.get(url)
    data = r.json()

    # Store user info in session
    session['provider'] = 'facebook'
    session['email'] = data['email']
    session['facebook_id'] = data['id']
    session['name'] = data['name']
    session['token'] = token

    print "User logged in as %s" % session['name']
    return "You are now logged in as %s" % session['name']


@app.route('/fbdisconnect/')
def fbdisconnect():
    # Check if user is logged in with facebook
    if session.get('provider') == 'facebook':
        token = session['token']
        facebook_id = session['facebook_id']

        url = 'https://graph.facebook.com/v2.8/%s/permissions?%s' \
              % (facebook_id, token)
        r = requests.delete(url)
        print r
    return 'Disconnected'


@app.route('/logout/')
def logout():
    session.pop('user_id', None)
    flash('You were successfully logged out')
    return redirect(url_for('login'))


@app.route('/course/add/', methods=['GET', 'POST'])
def add_course():
    return render_template('add_course.html')


@app.route('/course/<int:course_id>/')
def view_course(course_id):
    return 'View single course with id ' + str(course_id)


@app.route('/course/<int:course_id>/edit/')
def edit_course(course_id):
    return 'Edit course with id ' + str(course_id)


@app.route('/course/<int:course_id>/delete/')
def delete_course(course_id):
    return 'Delete course with id ' + str(course_id)


@app.route('/schools/')
def view_all_schools():
    schools = School.get_all()
    return render_template('view_all_schools.html', schools=schools)


@app.route('/school/add/', methods=['GET', 'POST'])
@login_required
def add_school():
    errors = None
    fields = None
    user_id = session['user_id']
    if request.method == 'POST':
        fields = {
            'name': request.form['name'],
            'url': request.form['url']
        }
        errors = check_add_school(fields=fields)
        if not errors:
            if School.get_by_name(fields['name']):
                errors['name_exists'] = True
            else:
                school = School.create(
                    name=fields['name'],
                    url=fields['url'],
                    user_id=user_id
                )
                flash('School created')
                return redirect(url_for('view_school', school_id=school.id))
    return render_template('add_school.html', fields=fields, errors=errors)


@app.route('/school/<int:school_id>/')
def view_school(school_id):
    school = School.get_by_id(school_id)
    return render_template('view_school.html', school=school)


@app.route('/school/<int:school_id>/edit/', methods=['GET', 'POST'])
@login_required
def edit_school(school_id):
    school = School.get_by_id(school_id)
    errors = None
    if request.method == 'POST':
        fields = {
            'name': request.form['name'],
            'url': request.form['url']
        }
        errors = check_edit_school(fields=fields)
        if not errors:
            if (School.get_by_name(fields['name']) and
                    School.get_by_name(fields['name']).id != school.id):
                errors['name_exists'] = True
            else:
                school.edit(
                    name=fields['name'],
                    url=fields['url']
                )
                flash('School edited')
                return redirect(url_for('view_school', school_id=school.id))
    else:
        fields = {
            'name': school.name,
            'url': school.url
        }
    return render_template('edit_school.html', fields=fields, errors=errors)


@app.route('/school/<int:school_id>/delete/')
def delete_school(school_id):
    return 'Delete school with id ' + str(school_id)


@app.route('/categories/')
def view_all_categories():
    return 'Show all categories'


@app.route('/category/add/')
def add_category():
    return 'Add a new category'


@app.route('/category/<int:category_id>/')
def view_category(category_id):
    return 'View single category with id ' + str(category_id)


@app.route('/category/<int:category_id>/edit/')
def edit_category(category_id):
    return 'Edit category with id ' + str(category_id)


@app.route('/category/<int:category_id>/delete/')
def delete_category(category_id):
    return 'Delete category with id ' + str(category_id)
