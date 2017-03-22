import random, string
from functools import wraps

from flask import render_template, session, request, make_response, flash, \
    redirect, url_for, abort, json, jsonify
from flask_bcrypt import Bcrypt
import requests
import json
import base64
# Needed for Google API Calls
from apiclient import discovery
import httplib2
from oauth2client import client

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
            item = model.query.get_or_404(id)
            # item = model.query.filter_by(id=id).first()
            if user_id != item.user_id:
                abort(403)
            return f(id, *args, **kwargs)
        return decorated_function
    return decorator


@app.route('/')
def frontpage():
    courses = Course.get_n(5, desc=True)
    return render_template('frontpage.html', courses=courses)


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
    return render_template('login.html', fields=fields, errors=errors)

@app.route('/fblogin/')
def fblogin():
    # Creates and stores an anti-forgery token
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    session['state'] = state
    return render_template('fblogin.html', STATE=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    # Check that state exists in args and session, and that they match
    if not (request.args.get('state') and session.get('state')) or \
            request.args.get('state') != session.get('state'):
        print 'Invalid state parameter'
        abort(403)
    short_lived_token = request.form['access_token']
    # short_lived_token = '12345'

    # Exchange client token for server-side token
    url = 'https://graph.facebook.com/oauth/access_token'
    payload = {
        'grant_type': 'fb_exchange_token',
        'client_id': app.config['FB_APP_ID'],
        'client_secret': app.config['FB_APP_SECRET'],
        'fb_exchange_token': short_lived_token
    }
    r = requests.get(url, params=payload)
    access_token = r.text.split("&")[0].split("=")[1]

    # Get user info from api
    url = 'https://graph.facebook.com/v2.8/me'
    payload = {
        'access_token': access_token,
        'fields': 'name,id,email'
    }
    r = requests.get(url, params=payload)
    data = r.json()

    # Store user info for easy access
    email = data['email']
    name = data['name']
    facebook_id = data['id']

    # Check if user exists by provider id or email
    user = User.get_by_providerid(facebook_id, 'facebook') or \
        User.get_by_email(email)
    # If there is no user, create a user
    if not user:
        # If user does not exist, create entry in database
        # First create a random password
        pw = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in xrange(32))
        user = User.create(
            name=name,
            email=email,
            pwhash=bcrypt.generate_password_hash(pw, 10),
            facebook_id=facebook_id
        )
    else:
        # User exists, so check it has facebook_id assigned.
        # If does not exist, assign it
        if not user.facebook_id:
            user.edit(facebook_id=facebook_id)

    session['user_id'] = user.id
    # TODO: Remove these and store in database
    session['fb_token'] = access_token
    session['facebook_id'] = facebook_id

    flash('You are now logged in with Facebook')

    print "User logged in as %s" % user.name
    return "You are now logged in as %s" % user.name


@app.route('/fbdisconnect/', methods=['GET', 'POST'])
def fbdisconnect():
    if request.method == 'POST':
        # Get facebook access token and facebook user id
        token = session.get('fb_token')
        facebook_id = session.get('facebook_id')
        if not (token and facebook_id):
            flash('You are not logged in to Facebook')
            return redirect(url_for('fblogin'))

        # Make api call to Facebook to revoke permissions
        url = 'https://graph.facebook.com/v2.8/%s/permissions' % facebook_id
        payload = {
            'access_token': token
            # 'access_token': app.config['FB_APP_ID'] + '|' + app.config['FB_APP_SECRET']
        }
        r = requests.delete(url, params=payload)

        if r.status_code != requests.codes.ok:
            print 'Issue revoking facebook permissions'
            print r.text
            flash('There was an issue revoking permissions. Try logging in and trying again.')
            return redirect(url_for('fblogin'))

        # Remove facebook info from user session
        session.pop('fb_token', None)
        session.pop('facebook_id', None)
        flash('You have disconnected from Facebook')
        return redirect(url_for('login'))
    return render_template('fbdisconnect.html')

@app.route('/googlelogin/')
def googlelogin():
    # Creates and stores an anti-forgery token
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    session['state'] = state
    return render_template('googlelogin.html', STATE=state)

@app.route('/googleconnect', methods=['GET', 'POST'])
def googleconnect():
    # Check that state exists in args and session, and that they match
    if not (request.args.get('state') and session.get('state')) or \
            request.args.get('state') != session.get('state'):
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.args.get('code')
    print url_for('googleconnect', _external=True)

    url = 'https://www.googleapis.com/oauth2/v4/token'
    payload = {
        'code': code,
        'client_id': app.config['GOOGLE_CLIENT_ID'],
        'client_secret': app.config['GOOGLE_CLIENT_SECRET'],
        'redirect_uri': url_for('googleconnect', _external=True),
        'grant_type': 'authorization_code'
    }
    r = requests.post(url, params=payload)
    data = r.json()
    print data
    access_token = data.get('access_token')
    if not access_token:
        response = make_response(json.dumps('Error connecting with Google.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print access_token

    url = 'https://www.googleapis.com/oauth2/v3/userinfo'
    headers = {
        'Authorization': 'Bearer ' + access_token
    }
    r = requests.get(url, headers=headers)
    if r.status_code != requests.codes.ok:
        response = make_response(json.dumps('Error connecting with Google.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    data = r.json()
    email = data['email']
    name = data['name']
    google_id = data['sub']

    # Check if user exists by provider id or email
    user = User.get_by_providerid(google_id, 'google') or \
        User.get_by_email(email)
    if not user :
        # If user does not exist, create entry in database
        # First create a random password
        pw = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in xrange(32))
        user = User.create(
            name=name,
            email=email,
            pwhash=bcrypt.generate_password_hash(pw, 10),
            google_id=google_id
        )
    else:
        # User exists, so check it has google_id assigned.
        # If does not exist, assign it
        if not user.google_id:
            user.edit(google_id=google_id)


    session['user_id'] = user.id
    # TODO: remove tokens because stored in database
    session['google_token'] = access_token
    session['google_id'] = google_id

    print "User logged in as %s" % user.name
    flash("You are now logged in as %s" % user.name)
    return redirect(url_for('view_all_courses'))

@app.route('/googledisconnect/', methods=['GET', 'POST'])
def googledisconnect():
    if request.method == 'POST':
        # Get google access token and google user id
        token = session['google_token']
        google_id = session['google_id']
        if not (token and google_id):
            flash('You are not logged in with Google')
            return redirect(url_for('googlelogin'))

        # Make api call to Google to revoke permissions
        headers = {'Content-type': 'application/x-www-form-urlencoded'}
        url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' \
              % token
        r = requests.get(url)

        if r.status_code != requests.codes.ok:
            print 'Issue revoking google permissions'
            print r.text
            flash('There was an issue revoking permissions. Try logging in and trying again.')
            # return redirect(url_for('googlelogin'))
            return 'issue'

        # Remove google info from user session
        session.pop('google_token', None)
        session.pop('google_id', None)
        flash('Your account was disconnected from Google')
        return redirect(url_for('login'))
    return render_template('googledisconnect.html')


@app.route('/githublogin/')
def githublogin():
    # Creates and stores an anti-forgery token
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    session['state'] = state
    return render_template('githublogin.html', STATE=state)

@app.route('/githubconnect/')
def githubconnect():
    # Store state
    state = request.args.get('state')
    # Check that state exists in args and session, and that they match
    if not (state and session.get('state')) or \
            state != session.get('state'):
        print 'States do not match'
        abort(403)
    # Store code that GitHub returns
    code = request.args.get('code')

    # Exchange code for access token
    url = 'https://github.com/login/oauth/access_token'
    payload = {
        'client_id': app.config['GITHUB_CLIENT_ID'],
        'client_secret': app.config['GITHUB_CLIENT_SECRET'],
        'code': code,
        'state': state
    }
    r = requests.post(url, params=payload)
    # Store access token
    access_token = r.text.split('&')[0].split('=')[1]

    # Make request to API for email
    url = 'https://api.github.com/user/emails'
    headers = {'Authorization': 'token %s' % access_token}
    r = requests.get(url, headers=headers)
    # Store user info
    email = r.json()[0]['email']

    # Make request to API for user info
    url = 'https://api.github.com/user'
    headers = {'Authorization': 'token %s' % access_token}
    r = requests.get(url, headers=headers)
    data = r.json()

    # If name is 'None', then use login
    name = data['name'] or data['login']
    github_id = data['id']

    # Check if user exists by provider id or email
    user = User.get_by_providerid(github_id, 'github') or \
        User.get_by_email(email)
    if not user :
        # If user does not exist, create entry in database
        # First create a random password
        pw = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in xrange(32))
        user = User.create(
            name=name,
            email=email,
            pwhash=bcrypt.generate_password_hash(pw, 10),
            github_id=github_id
        )
    else:
        # User exists, so check it has github_id assigned.
        # If does not exist, assign it
        if not user.github_id:
            user.edit(github_id=github_id)

    session['user_id'] = user.id
    session['github_token'] = access_token
    # TODO: Can remove id since stored to database
    session['github_id'] = github_id

    print "User logged in as %s" % user.name
    flash('You are now logged in.')
    return redirect(url_for('view_all_courses'))

@app.route('/githubdisconnect/', methods=['GET', 'POST'])
def githubdisconnect():
    if request.method == 'POST':
        token = session.get('github_token')
        github_id = session.get('github_id')
        if not (token and github_id):
            flash('You are not logged in to GitHub')
            return redirect(url_for('githublogin'))
        # Remove github info from user session
        url = 'https://api.github.com/applications/%s/grants/%s' \
            % (app.config['GITHUB_CLIENT_ID'], token)
        auth = app.config['GITHUB_CLIENT_ID'] + ':' + app.config['GITHUB_CLIENT_SECRET']
        headers = {
            'Authorization': 'Basic ' + base64.b64encode(auth)
        }
        print url
        r = requests.delete(url, headers=headers)
        if r.status_code != 204:
            flash('There was an issue disconnecting. Please try again.')
            return redirect(url_for('githubdisconnect'))
        session.pop('github_token', None)
        session.pop('github_id', None)
        flash('Disconnected from GitHub')
        return redirect(url_for('logout'))
    return render_template('githubdisconnect.html')

@app.route('/logout/', methods=['GET', 'POST'])
def logout():
    if request.method == 'POST':
        session.clear()
        flash('You were successfully logged out')
        return redirect(url_for('login'))
    return render_template('logout.html')


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

@app.route('/courses/')
def view_all_courses():
    courses = Course.get_all()
    return render_template(
        'view_all_courses.html',
        courses=courses
    )

@app.route('/courses/JSON/')
def view_all_courses_json():
    courses = Course.get_all()
    courses_json = []
    for course in courses:
        courses_json.append(
            {
                'id': course.id,
                'name': course.name,
                'url': course.url,
                'school': course.school.name,
                'category': course.category.name
            }
        )
    return jsonify(courses_json)


@app.route('/course/<int:id>/')
def view_course(id):
    course = Course.get_or_404(id)
    return render_template('view_course.html', course=course)

@app.route('/course/<int:id>/JSON/')
def view_course_json(id):
    course = Course.get_or_404(id)
    course_json = {
        'id': course.id,
        'name': course.name,
        'url': course.url,
        'school': course.school.name,
        'category': course.category.name
    }
    return jsonify(course_json)


@app.route('/course/<int:id>/edit/', methods=['GET', 'POST'])
@login_required
@user_authorized(Course)
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
@login_required
@user_authorized(Course)
def delete_course(id):
        course = Course.get_or_404(id)
        if request.method == 'POST':
            course.delete()
            flash('Course successfully deleted')
            return redirect(url_for('view_all_courses'))
        return render_template('delete_course.html', course=course)


@app.route('/schools/')
def view_all_schools():
    schools = School.get_all()
    return render_template('view_all_schools.html', schools=schools)


@app.route('/schools/JSON/')
def schools_json():
    schools = School.get_all()
    schools_json = []
    for school in schools:
        schools_json.append(
            {
                'id': school.id,
                'name': school.name,
                'url': school.url,
                'courses': [{'id': course.id, 'name': course.name, 'url': course.url, 'school': course.school.name, 'category': course.category.name} for course in school.courses]
            }
        )
    return jsonify(schools_json)


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


@app.route('/school/<int:id>/JSON/')
def view_school_json(id):
    school = School.get_or_404(id)
    school_json = {
        'id': school.id,
        'name': school.name,
        'url': school.url,
        'courses': [{'id': course.id, 'name': course.name, 'url': course.url, 'school': course.school.name, 'category': course.category.name} for course in school.courses]
    }
    return jsonify(school_json)


@app.route('/school/<int:id>/edit/', methods=['GET', 'POST'])
@login_required
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
@login_required
@user_authorized(School)
def delete_school(id):
    school = School.get_or_404(id)
    if request.method == 'POST':
        school.delete()
        flash('School successfully deleted')
        return redirect(url_for('view_all_schools'))
    return render_template('delete_school.html', school=school)


@app.route('/categories/')
def view_all_categories():
    categories = Category.get_all()
    return render_template('view_all_categories.html', categories=categories)


@app.route('/categories/JSON/')
def view_all_categories_json():
    categories = Category.get_all()
    categories_json = []
    for category in categories:
        categories_json.append(
            {
                'id': category.id,
                'name': category.name,
                'courses': [{'id': course.id, 'name': course.name, 'url': course.url, 'school': course.school.name, 'category': course.category.name} for course in category.courses]
            }
        )
    return jsonify(categories_json)


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


@app.route('/category/<int:id>/JSON/')
def view_category_json(id):
    category = Category.get_or_404(id)
    category_json = {
        'id': category.id,
        'name': category.name,
        'courses': [{'id': course.id, 'name': course.name, 'url': course.url, 'school': course.school.name, 'category': course.category.name} for course in category.courses]
    }
    return jsonify(category_json)


@app.route('/category/<int:id>/edit/', methods=['GET', 'POST'])
@login_required
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
@login_required
@user_authorized(Category)
def delete_category(id):
    category = Category.get_or_404(id)
    if request.method == 'POST':
        category.delete()
        flash('Category successfully deleted')
        return redirect(url_for('view_all_categories'))
    return render_template('delete_category.html', category=category)
