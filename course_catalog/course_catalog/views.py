import random, string
from functools import wraps

from flask import render_template, session, request, make_response, flash, redirect, url_for
from flask_bcrypt import Bcrypt
import requests

from course_catalog import app
from models import User, Course, School, Category
from modules.form_validation import check_registration, check_login, \
    check_no_blanks


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


def user_authorized(model):
    def decorator(f):
        @wraps(f)
        def decorated_function(id, *args, **kwargs):
            user_id = session.get('user_id')
            item = model.query.filter_by(id=id).first()
            if user_id is None or user_id != item.user_id:
                flash('You are not authorized to edit this')
                return redirect(url_for('login', next=request.url))
            return f(id, *args, **kwargs)
        return decorated_function
    return decorator


@app.route('/')
@app.route('/courses/')
def view_all_courses():
    courses = Course.get_all()
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
@login_required
def add_course():
    errors = None
    fields = None
    user_id = session['user_id']
    categories = Category.get_all()
    schools = School.get_all()
    if request.method == 'POST':
        fields = {
            'name': request.form['name'],
            'url': request.form['url'],
            'school': request.form.get('school', ''),
            'category': request.form.get('category', '')
        }
        errors = check_no_blanks(fields=fields)
        if not errors:
            # Check if course by same name exists witin school
            school_courses = School.get_by_id(fields['school']).courses
            for school_course in school_courses:
                if school_course.name == fields['name']:
                    errors['name_exists'] = True
            if not errors:
                course = Course.create(
                    name=fields['name'],
                    url=fields['url'],
                    school_id=fields['school'],
                    category_id=fields['category'],
                    user_id=user_id
                )
                flash('Course created')
                return redirect(url_for('view_course', id=course.id))
    return render_template('add_course.html',
                           fields=fields,
                           categories=categories,
                           schools=schools,
                           errors=errors)


@app.route('/course/<int:id>/')
def view_course(id):
    course = Course.get_or_404(id)
    return render_template('view_course.html', course=course)


@app.route('/course/<int:id>/edit/', methods=['GET', 'POST'])
def edit_course(id):
        course = Course.get_or_404(id)
        errors = None
        categories = Category.get_all()
        schools = School.get_all()
        if request.method == 'POST':
            fields = {
                'name': request.form['name'],
                'url': request.form['url'],
                'school': request.form.get('school', ''),
                'category': request.form.get('category', '')
            }
            errors = check_no_blanks(fields=fields)
            if not errors:
                school_courses = School.get_by_id(fields['school']).courses
                for school_course in school_courses:
                    if school_course.name == fields['name'] and school_course.id != course.id:
                        errors['name_exists'] = True
                if not errors:
                    course.edit(
                        name=fields['name'],
                        url=fields['url'],
                        school_id=fields['school'],
                        category_id=fields['category']
                    )
                    flash('Course edited')
                    return redirect(url_for('view_course', id=course.id))
        else:
            fields = {
                'name': course.name,
                'url': course.url,
                'school': course.school.id,
                'category': course.category.id
            }
        return render_template('edit_course.html', fields=fields, errors=errors, categories=categories, schools=schools)


@app.route('/course/<int:id>/delete/', methods=['GET', 'POST'])
def delete_course(id):
        course = Course.get_or_404(id)
        if course is None:
            flash('There is no course with that id')
            return redirect(url_for('view_all_courses'))
        if request.method == 'POST':
            course.delete()
            flash('Course successfully deleted')
            return redirect(url_for('view_all_courses'))
        return render_template('delete_course.html', course=course)


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
        errors = check_no_blanks(fields=fields)
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
                return redirect(url_for('view_school', id=school.id))
    return render_template('add_school.html', fields=fields, errors=errors)


@app.route('/school/<int:id>/')
def view_school(id):
    school = School.get_or_404(id)
    return render_template('view_school.html', school=school)


@app.route('/school/<int:id>/edit/', methods=['GET', 'POST'])
@user_authorized(School)
def edit_school(id):
    school = School.get_or_404(id)
    errors = None
    if request.method == 'POST':
        fields = {
            'name': request.form['name'],
            'url': request.form['url']
        }
        errors = check_no_blanks(fields=fields)
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
                return redirect(url_for('view_school', id=school.id))
    else:
        fields = {
            'name': school.name,
            'url': school.url
        }
    return render_template('edit_school.html', fields=fields, errors=errors)


@app.route('/school/<int:id>/delete/', methods=['GET', 'POST'])
# @user_authorized
def delete_school(id):
    school = School.get_or_404(id)
    if school is None:
        flash('There is no school with that id')
        return redirect(url_for('view_all_schools'))
    if request.method == 'POST':
        school.delete()
        flash('School successfully deleted')
        return redirect(url_for('view_all_schools'))
    return render_template('delete_school.html', school=school)


@app.route('/categories/')
def view_all_categories():
    categories = Category.get_all()
    return render_template('view_all_categories.html', categories=categories)


@app.route('/category/add/', methods=['GET', 'POST'])
@login_required
def add_category():
    errors = None
    fields = None
    user_id = session['user_id']
    if request.method == 'POST':
        fields = {
            'name': request.form['name']
        }
        errors = check_no_blanks(fields=fields)
        if not errors:
            if Category.get_by_name(fields['name']):
                errors['name_exists'] = True
            else:
                category = Category.create(
                    name=fields['name'],
                    user_id=user_id
                )
                flash('Category created')
                return redirect(url_for('view_category', id=category.id))
    return render_template('add_category.html', fields=fields, errors=errors)


@app.route('/category/<int:id>/')
def view_category(id):
    category = Category.get_or_404(id)
    return render_template('view_category.html', category=category)


@app.route('/category/<int:id>/edit/', methods=['GET', 'POST'])
@user_authorized(Category)
def edit_category(id):
    category = Category.get_or_404(id)
    errors = None
    if request.method == 'POST':
        fields = {
            'name': request.form['name']
        }
        errors = check_no_blanks(fields=fields)
        if not errors:
            if (Category.get_by_name(fields['name']) and
                    Category.get_by_name(fields['name']).id != category.id):
                errors['name_exists'] = True
            else:
                category.edit(
                    name=fields['name']
                )
                flash('Category edited')
                return redirect(url_for('view_category', id=category.id))
    else:
        fields = {
            'name': category.name
        }
    return render_template('edit_category.html', fields=fields, errors=errors)


@app.route('/category/<int:id>/delete/', methods=['POST', 'GET'])
def delete_category(id):
    category = Category.get_or_404(id)
    if category is None:
        flash('There is no category with that id')
        return redirect(url_for('view_all_categories'))
    if request.method == 'POST':
        category.delete()
        flash('Category successfully deleted')
        return redirect(url_for('view_all_categories'))
    return render_template('delete_category.html', category=category)
