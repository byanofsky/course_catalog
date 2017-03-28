import random
import string
from functools import wraps

from flask import render_template, session, request, make_response, flash,\
                  redirect, url_for, abort, json, jsonify
from flask_bcrypt import Bcrypt
import requests
import json
import base64

from course_catalog import app
from models import User, Course, School, Category
from modules.form_validation import check_registration, check_login, \
                                    check_no_blanks


# Create an instance of bcrypt for password hashing
bcrypt = Bcrypt(app)


def create_state():
    """Helper function that creates a string of len=32
    and assigns it to state attribute in session.
    Is used to prevent CSRF.
    """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    session['state'] = state
    return state


def login_required(f):
    """Decorator to check if user is logged in.
    If not, redirects to login page.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_id') is None:
            flash('Please log in to continue')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def user_authorized(model):
    """Decorator to check if user is authorized to access associated model
    instance. If user is not authorized, aborts with 403 error.

    Args:
        model (object): The database model of the instance.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(id, *args, **kwargs):
            """Checks that logged in user_id matches user_id of instance."""
            # Get user_id of logged in user
            user_id = session['user_id']
            # Get item by id. If it does not exist, return 404.
            item = model.query.get_or_404(id)
            # Make sure that item does have a user, or return 500 error
            assert item.user_id
            # If user does not exist, or user does not own item,
            # return 403 status
            if user_id != item.user_id:
                abort(403)
            return f(id, *args, **kwargs)
        return decorated_function
    return decorator


@app.route('/')
def frontpage():
    # Get 5 courses in descending order (5 most recent)
    courses = Course.get_n(5, desc=True)
    return render_template('frontpage.html', courses=courses)


@app.route('/register/', methods=['GET', 'POST'])
def register():
    # Start with no validation errors and no field entries
    errors = None
    fields = None
    if request.method == 'POST':
        fields = {
            'email': request.form['email'],
            'name': request.form['name'],
            'password': request.form['password'],
            'verify_password': request.form['verify_password'],
            # 'state': request.form['state']
        }
        # Check that registration form fields validate
        errors = check_registration(fields, User.get_by_email(fields['email']))
        # Check that state token matches, or ask user to try again.
        # TODO: Implement state check for registration
        # if fields['state'] != session['state']:
        #     errors['state'] = True
        #     flash('There was an error, please try again.')
        # If there are no validation errors, create user
        if not errors:
            user = User.create(
                name=fields['name'],
                email=fields['email'],
                pwhash=bcrypt.generate_password_hash(fields['password'], 10)
            )
            session['user_id'] = user.id
            flash('You were successfully registered')
            return redirect(url_for('view_all_courses'))
    # If method is GET, or there are errors above, return register template.
    state = create_state()
    return render_template(
        'register.html',
        state=state,
        fields=fields,
        errors=errors
    )


@app.route('/login/', methods=['GET', 'POST'])
def login():
    # Start with no errors and no fields
    errors = None
    fields = None
    if request.method == 'POST':
        # Get fields passed through form
        fields = {
            'email': request.form['email'],
            'password': request.form['password']
        }
        # Validate login fields (does not authenticate yet)
        errors = check_login(fields=fields)
        if not errors:
            # Attempt to find user in database by email
            user = User.get_by_email(fields['email'])
            # Performs authentication. First checks if user exists,
            # then checks if password is correct.
            if not user:
                # TODO: change to 'not exists'
                errors['user_not_exist'] = True
            elif not bcrypt.check_password_hash(user.pwhash,
                                                fields['password']):
                errors['password'] = True
            else:
                # User is authenaticated. Save user id to session
                session['user_id'] = user.id
                flash('You were successfully logged in')
                # If user was directed to login page from another page,
                # direct user back to that page.
                next_url = request.args.get('next',
                                            url_for('view_all_courses'))
                return redirect(next_url)
    return render_template('login.html', fields=fields, errors=errors)


@app.route('/fblogin/')
def fblogin():
    # Creates and stores an anti-forgery token
    state = create_state()
    return render_template('fblogin.html', state=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    # Check that state exists in args and session, and that they match
    if not (request.args.get('state') and session.get('state')) or \
            request.args.get('state') != session.get('state'):
        print 'Invalid state parameter'
        return 'Invalid state parameter', 403
    # Store short lived token
    short_lived_token = request.form['access_token']

    # Exchange short lived token for server-side access token
    url = 'https://graph.facebook.com/oauth/access_token'
    payload = {
        'grant_type': 'fb_exchange_token',
        'client_id': app.config['FB_APP_ID'],
        'client_secret': app.config['FB_APP_SECRET'],
        'fb_exchange_token': short_lived_token
    }
    r = requests.get(url, params=payload)
    data = r.json()
    # Store server-side access token
    access_token = data['access_token']

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

    # Check if user exists in database by provider id or email
    user = User.get_by_providerid(facebook_id, 'facebook') or \
        User.get_by_email(email)
    # If there is no user, create a new user
    if not user:
        # TODO: let user choose password
        # Create a random password for user
        pw = ''.join(random.choice(string.ascii_uppercase + string.digits)
                     for x in xrange(32))
        user = User.create(
            name=name,
            email=email,
            pwhash=bcrypt.generate_password_hash(pw, 10),
            facebook_id=facebook_id
        )
    else:
        # TODO: should this occur? Or should user manually add it?
        # User exists, so check if facebook_id was assigned.
        # If does not have facebook_id, assign it
        if not user.facebook_id:
            user.edit(facebook_id=facebook_id)

    # Add user id to session
    session['user_id'] = user.id
    # TODO: Remove these and store in database. \
    # Needs to work with refresh token.
    # Store access token and facebook user id for additional calls
    session['fb_token'] = access_token
    session['facebook_id'] = facebook_id

    flash('You are now logged in with Facebook')
    return "You are now logged in as %s" % user.name


@app.route('/fbdisconnect/', methods=['GET', 'POST'])
@login_required
def fbdisconnect():
    if request.method == 'GET':
        return render_template('fbdisconnect.html')
    elif request.method == 'POST':
        # Get facebook access token and facebook user id
        # TODO: retrieve these from database and get refresh token if needed
        token = session.get('fb_token')
        facebook_id = session.get('facebook_id')
        # TODO: need to use refresh token here
        # If there is not a token or facebook_id, user is not logged in to fb
        if not (token and facebook_id):
            flash('You are not logged in to Facebook')
            return redirect(url_for('fblogin'))

        # Make api call to Facebook to revoke permissions
        url = 'https://graph.facebook.com/v2.8/%s/permissions' % facebook_id
        payload = {
            'access_token': token
            # TODO: might not need access token to revoke. Check fb docs.
            # 'access_token': app.config['FB_APP_ID'] + '|' + \
            #                  app.config['FB_APP_SECRET']
        }
        r = requests.delete(url, params=payload)
        # Check status code if revoke was successful
        if r.status_code == requests.codes.ok:
            # Remove facebook info from user session
            # TODO: if store in db, need to remove from db
            session.pop('fb_token', None)
            session.pop('facebook_id', None)
            flash('You have disconnected from Facebook')
            return redirect(url_for('login'))
        else:
            # Issue revoking permissions.
            # Print error for debug purposes
            print 'Issue revoking facebook permissions'
            print r.text
            # TODO: Maybe this would be better to do redirect to fb login
            # then back to disconnect.
            flash('There was an issue revoking permissions. Please try again.')
            return redirect(url_for('fblogin'))


@app.route('/googlelogin/')
def googlelogin():
    # Creates and stores an anti-forgery token
    state = create_state()
    return render_template('googlelogin.html', state=state)


@app.route('/googleconnect', methods=['GET', 'POST'])
def googleconnect():
    # Check that state exists in args and session, and that they match
    if not (request.args.get('state') and session.get('state')) or \
            request.args.get('state') != session.get('state'):
        print 'Invalid state parameter'
        return 'Invalid state parameter', 403
    # Store code sent by Google
    code = request.args.get('code')

    # Exchange code for an access token
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
    access_token = data.get('access_token')

    # Make sure we received an access token, or return an error
    if not access_token:
        # TODO: should this be returning error or redirect?
        # return 'Error connecting with Google.', 401
        flash('There was an error connecting with Google. Please try again.')
        return redirect(url_for('googlelogin'))

    # Make API call to Google for user info
    url = 'https://www.googleapis.com/oauth2/v3/userinfo'
    headers = {
        'Authorization': 'Bearer ' + access_token
    }
    r = requests.get(url, headers=headers)
    # Check status code for any errors
    if r.status_code != requests.codes.ok:
        # TODO: should this be returning error or redirect?
        # return 'Error connecting with Google.', 401
        flash('There was an error connecting with Google. Please try again.')
        return redirect(url_for('googlelogin'))
    # Store user info
    data = r.json()
    email = data['email']
    name = data['name']
    google_id = data['sub']

    # Check if user exists by provider id or email
    user = User.get_by_providerid(google_id, 'google') or \
        User.get_by_email(email)
    # If there is no user, create a new user
    if not user:
        # TODO: let user choose password
        # Create a random password for user
        pw = ''.join(random.choice(string.ascii_uppercase + string.digits)
                     for x in xrange(32))
        user = User.create(
            name=name,
            email=email,
            pwhash=bcrypt.generate_password_hash(pw, 10),
            google_id=google_id
        )
    else:
        # TODO: should this occur? Or should user manually add it?
        # User exists, so check if google_id was assigned.
        # If does not have google_id, assign it
        if not user.google_id:
            user.edit(google_id=google_id)

    # Add user id to session
    session['user_id'] = user.id
    # TODO: Remove these and store in database. \
    # Needs to work with refresh token.
    # Store google token and google user id for additional calls
    session['google_token'] = access_token
    session['google_id'] = google_id

    flash("You are now logged in with Google account for %s" % name)
    return redirect(url_for('frontpage'))


@app.route('/googledisconnect/', methods=['GET', 'POST'])
@login_required
def googledisconnect():
    if request.method == 'GET':
        return render_template('googledisconnect.html')
    elif request.method == 'POST':
        # Get google access token and google user id
        # TODO: retrieve these from database and get refresh token if needed
        token = session.get('google_token')
        google_id = session.get('google_id')
        # TODO: need to use refresh token here
        # If there is not a token or google_id, user is not logged in to Google
        if not (token and google_id):
            flash('You are not logged in with Google')
            return redirect(url_for('googlelogin'))

        # Make api call to Google to revoke permissions
        url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % token
        headers = {'Content-type': 'application/x-www-form-urlencoded'}
        r = requests.get(url)
        # Check status code if revoke was successful
        if r.status_code == requests.codes.ok:
            # Remove google info from user session
            # TODO: if store in db, need to remove from db
            session.pop('google_token', None)
            session.pop('google_id', None)
            flash('Your account was disconnected from Google')
            return redirect(url_for('login'))
        else:
            # Issue revoking permissions.
            # Print error for debug purposes
            print 'Issue revoking google permissions'
            print r.text
            # TODO: Maybe this would be better to do redirect to fb login
            # then back to disconnect.
            flash('There was an issue revoking permissions. \
                  Try logging in and trying again.')
            return redirect(url_for('googlelogin'))


@app.route('/githublogin/')
def githublogin():
    # Creates and stores an anti-forgery token
    state = create_state()
    return render_template('githublogin.html', state=state)


@app.route('/githubconnect/')
def githubconnect():
    # Check that state exists in args and session, and that they match
    if not (request.args.get('state') and session.get('state')) or \
            request.args.get('state') != session.get('state'):
        print 'Invalid state parameter'
        return 'Invalid state parameter', 403
    # Store code that GitHub returns
    code = request.args.get('code')

    # Exchange code for access token
    url = 'https://github.com/login/oauth/access_token'
    payload = {
        'client_id': app.config['GITHUB_CLIENT_ID'],
        'client_secret': app.config['GITHUB_CLIENT_SECRET'],
        'code': code,
        'state': request.args['state']
    }
    r = requests.post(url, params=payload)
    # Store access token
    access_token = r.text.split('&')[0].split('=')[1]

    # Make sure we received an access token, or return an error
    if not access_token:
        # TODO: should this be returning error or redirect?
        # return 'Error connecting with GitHub.', 401
        flash('There was an error connecting with GitHub. Please try again.')
        return redirect(url_for('githublogin'))

    # Make request to API for user's email
    url = 'https://api.github.com/user/emails'
    headers = {
        'Authorization': 'token %s' % access_token
    }
    r1 = requests.get(url, headers=headers)
    # Store user email
    email = r1.json()[0]['email']

    # Make request to API for user info
    url = 'https://api.github.com/user'
    headers = {
        'Authorization': 'token %s' % access_token
    }
    r2 = requests.get(url, headers=headers)
    # Check status code for any errors
    if (r1.status_code != requests.codes.ok or
            r1.status_code != requests.codes.ok):
        # TODO: should this be returning error or redirect?
        # return 'Error connecting with GitHub.', 401
        flash('There was an error connecting with GitHub. Please try again.')
        return redirect(url_for('githublogin'))
    data = r2.json()
    # Name could be 'None'. If it is, use their login username
    name = data['name'] or data['login']
    github_id = data['id']

    # Check if user exists by provider id or email
    user = User.get_by_providerid(github_id, 'github') or \
        User.get_by_email(email)
    # If there is no user, create a new user
    if not user:
        # TODO: let user choose password
        # Create a random password for user
        pw = ''.join(random.choice(string.ascii_uppercase + string.digits)
                     for x in xrange(32))
        user = User.create(
            name=name,
            email=email,
            pwhash=bcrypt.generate_password_hash(pw, 10),
            github_id=github_id
        )
    else:
        # TODO: should this occur? Or should user manually add it?
        # User exists, so check if github_id was assigned.
        # If does not have github_id, assign it
        if not user.github_id:
            user.edit(github_id=github_id)

    # Add user id to session
    session['user_id'] = user.id
    # TODO: Remove these and store in database. \
    # Needs to work with refresh token.
    # Store github token and github user id for additional calls
    session['github_token'] = access_token
    session['github_id'] = github_id

    flash("You are now logged in with GitHub account for %s" % name)
    return redirect(url_for('frontpage'))


@app.route('/githubdisconnect/', methods=['GET', 'POST'])
@login_required
def githubdisconnect():
    if request.method == 'GET':
        return render_template('githubdisconnect.html')
    if request.method == 'POST':
        # Get github access token and github user id
        token = session.get('github_token')
        github_id = session.get('github_id')
        # TODO: need to use refresh token here
        # If there is not a token or github_id, user is not logged in to github
        if not (token and github_id):
            flash('You are not logged in to GitHub')
            return redirect(url_for('githublogin'))

        # Make API call to github to revoke permissions
        url = 'https://api.github.com/applications/%s/grants/%s' \
            % (app.config['GITHUB_CLIENT_ID'], token)
        auth = app.config['GITHUB_CLIENT_ID'] + ':' + \
            app.config['GITHUB_CLIENT_SECRET']
        headers = {
            'Authorization': 'Basic ' + base64.b64encode(auth)
        }
        r = requests.delete(url, headers=headers)
        # Check status if revoke was successful
        if r.status_code == 204:
            # Remove github info from user session
            # TODO: if store in db, need to remove from db
            session.pop('github_token', None)
            session.pop('github_id', None)
            flash('You have disconnected from GitHub')
            return redirect(url_for('login'))
        else:
            # Issue revoking permissions.
            # Print error for debug purposes
            print 'Issue revoking github permissions'
            print r.text
            # TODO: Maybe this would be better to do redirect to github login
            # then back to disconnect.
            flash('There was an issue disconnecting. Please try again.')
            return redirect(url_for('githublogin'))


@app.route('/logout/', methods=['GET', 'POST'])
def logout():
    if request.method == 'POST':
        # Remove all stored session data
        session.clear()
        flash('You were successfully logged out')
        return redirect(url_for('login'))
    return render_template('logout.html')


@app.route('/courses/')
def view_all_courses():
    # Gets all courses in database
    # TODO: add pagination or limit to how many courses load at a time
    courses = Course.get_all()
    return render_template(
        'view_all_courses.html',
        courses=courses
    )


@app.route('/courses/JSON/')
def view_all_courses_json():
    # Get all courses from database
    courses = Course.get_all()
    # Create a list to store courses for JSON
    courses_json = []
    # Iterate through courses and extract info for JSON
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
    return jsonify(courses=courses_json)


@app.route('/course/<int:id>/')
def view_course(id):
    # Get course from db, or 404
    course = Course.get_or_404(id)
    return render_template('view_course.html', course=course)


@app.route('/course/<int:id>/JSON/')
def view_course_json(id):
    # Get course from db, or 404
    course = Course.get_or_404(id)
    # Extract data needed for JSON
    course_json = {
        'id': course.id,
        'name': course.name,
        'url': course.url,
        'school': course.school.name,
        'category': course.category.name
    }
    return jsonify(course_json)


@app.route('/course/add/', methods=['GET', 'POST'])
@login_required
def add_course():
    # Start with no errors and no fields
    errors = None
    fields = None
    # Grab user id. Associates course with user.
    user_id = session['user_id']
    # Get all categories and schools to populate dropdowns
    categories = Category.get_all()
    schools = School.get_all()

    if request.method == 'POST':
        # Grab all form data
        fields = {
            'name': request.form['name'],
            'url': request.form['url'],
            'school': request.form.get('school', ''),
            'category': request.form.get('category', '')
        }
        # Form validation that makes sure no fields are blank
        errors = check_no_blanks(fields=fields)
        if not errors:
            # Check if school already has course by same name
            school_courses = School.get_by_id(fields['school']).courses
            for school_course in school_courses:
                if school_course.name == fields['name']:
                    errors['name_exists'] = True
            # If there are no errors, then create course
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
    # If this is a GET request, or there are errors, show form
    return render_template('add_course.html',
                           fields=fields,
                           categories=categories,
                           schools=schools,
                           errors=errors)


@app.route('/course/<int:id>/edit/', methods=['GET', 'POST'])
@login_required
@user_authorized(Course)
def edit_course(id):
    # Get course from db or 404
    course = Course.get_or_404(id)
    # Start with no errors
    errors = None
    # Get categories and schools to populate dropdowns
    categories = Category.get_all()
    schools = School.get_all()

    if request.method == 'POST':
        fields = {
            'name': request.form['name'],
            'url': request.form['url'],
            'school': request.form.get('school', ''),
            'category': request.form.get('category', '')
        }
        # Validations that checks that no fields are blank
        errors = check_no_blanks(fields=fields)
        if not errors:
            # Check that new course name does not exist already for this school
            school_courses = School.get_by_id(fields['school']).courses
            for school_course in school_courses:
                # If name isn't changed, will exist so allow this
                if school_course.name == fields['name'] and \
                        school_course.id != course.id:
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
    # If it is not a POST request, populate input values from database
    else:
        fields = {
            'name': course.name,
            'url': course.url,
            'school': course.school.id,
            'category': course.category.id
        }
    return render_template(
        'edit_course.html',
        fields=fields,
        errors=errors,
        categories=categories,
        schools=schools
    )


@app.route('/course/<int:id>/delete/', methods=['GET', 'POST'])
@login_required
@user_authorized(Course)
def delete_course(id):
    # Get course from db or 404
    course = Course.get_or_404(id)
    if request.method == 'POST':
        course.delete()
        flash('Course successfully deleted')
        return redirect(url_for('view_all_courses'))
    return render_template('delete_course.html', course=course)


@app.route('/schools/')
def view_all_schools():
    # Get all schools
    schools = School.get_all()
    return render_template('view_all_schools.html', schools=schools)


@app.route('/schools/JSON/')
def schools_json():
    # Get all schools from db
    schools = School.get_all()
    # Create list to store JSON data
    schools_json = []
    for school in schools:
        schools_json.append(
            {
                'id': school.id,
                'name': school.name,
                'url': school.url,
                'courses': [
                    {
                        'id': course.id,
                        'name': course.name,
                        'url': course.url,
                        'school': course.school.name,
                        'category': course.category.name
                    }
                    for course in school.courses
                ]
            }
        )
    return jsonify(schools=schools_json)


@app.route('/school/<int:id>/')
def view_school(id):
    # Get school from db or 404
    school = School.get_or_404(id)
    return render_template('view_school.html', school=school)


@app.route('/school/<int:id>/JSON/')
def view_school_json(id):
    # Get school or 404
    school = School.get_or_404(id)
    # Extract school info
    school_json = {
        'id': school.id,
        'name': school.name,
        'url': school.url,
        'courses': [
            {
                'id': course.id,
                'name': course.name,
                'url': course.url,
                'school': course.school.name,
                'category': course.category.name
            }
            for course in school.courses
        ]
    }
    return jsonify(school_json)


@app.route('/school/add/', methods=['GET', 'POST'])
@login_required
def add_school():
    # Start with no errors and no fields
    errors = None
    fields = None
    # Store user id from session to associate school with user
    user_id = session['user_id']

    if request.method == 'POST':
        fields = {
            'name': request.form['name'],
            'url': request.form['url']
        }
        # Validate form submission by checking no empty fields
        errors = check_no_blanks(fields=fields)
        if not errors:
            # Check that school name does not already exist
            # TODO: this check needs to check by case insensitive
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


@app.route('/school/<int:id>/edit/', methods=['GET', 'POST'])
@login_required
@user_authorized(School)
def edit_school(id):
    # Get school from db or 404
    school = School.get_or_404(id)
    # Start with no errors
    errors = None
    if request.method == 'POST':
        fields = {
            'name': request.form['name'],
            'url': request.form['url']
        }
        # Validations that check that no fields are empty
        errors = check_no_blanks(fields=fields)
        if not errors:
            # Check that school name does not match other school names,
            # except if it is the same instance
            if (School.get_by_name(fields['name']) and
                    School.get_by_name(fields['name']).id != school.id):
                errors['name_exists'] = True
            if not errors:
                school.edit(
                    name=fields['name'],
                    url=fields['url']
                )
                flash('School edited')
                return redirect(url_for('view_school', id=school.id))
    # If it is not a POST rquest, populate field values from database
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
    # Get school from db or 404
    school = School.get_or_404(id)
    if request.method == 'POST':
        school.delete()
        flash('School successfully deleted')
        return redirect(url_for('view_all_schools'))
    return render_template('delete_school.html', school=school)


@app.route('/categories/')
def view_all_categories():
    # Retrieve all categories
    categories = Category.get_all()
    return render_template('view_all_categories.html', categories=categories)


@app.route('/categories/JSON/')
def view_all_categories_json():
    # Retrieve all categories
    categories = Category.get_all()
    # Create empty list for storing JSON data
    categories_json = []
    for category in categories:
        categories_json.append(
            {
                'id': category.id,
                'name': category.name,
                'courses': [
                    {
                        'id': course.id,
                        'name': course.name,
                        'url': course.url,
                        'school': course.school.name,
                        'category': course.category.name
                    }
                    for course in category.courses
                ]
            }
        )
    return jsonify(categories=categories_json)


@app.route('/category/<int:id>/')
def view_category(id):
    # Retrieve category from db of 404
    category = Category.get_or_404(id)
    return render_template('view_category.html', category=category)


@app.route('/category/<int:id>/JSON/')
def view_category_json(id):
    # Retrieve category or 404
    category = Category.get_or_404(id)
    # Prepare category info in JSON format
    category_json = {
        'id': category.id,
        'name': category.name,
        'courses': [
            {
                'id': course.id,
                'name': course.name,
                'url': course.url,
                'school': course.school.name,
                'category': course.category.name
            }
            for course in category.courses
        ]
    }
    return jsonify(category_json)


@app.route('/category/add/', methods=['GET', 'POST'])
@login_required
def add_category():
    # Start with no errors or fields
    errors = None
    fields = None
    # Store user id from session to associate category with user
    user_id = session['user_id']

    if request.method == 'POST':
        fields = {
            'name': request.form['name']
        }
        # Validate form submission by checking no empty fields
        errors = check_no_blanks(fields=fields)
        if not errors:
            # Check that category name does not already exist
            # TODO: this check needs to check by case insensitive
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


@app.route('/category/<int:id>/edit/', methods=['GET', 'POST'])
@login_required
@user_authorized(Category)
def edit_category(id):
    # Retrieve school from db or 404
    category = Category.get_or_404(id)
    # Start with no errors
    errors = None
    if request.method == 'POST':
        fields = {
            'name': request.form['name']
        }
        # Validations that check that no fields are empty
        errors = check_no_blanks(fields=fields)
        if not errors:
            # Check that category name does not match other category names,
            # except if it is the same instance
            if (Category.get_by_name(fields['name']) and
                    Category.get_by_name(fields['name']).id != category.id):
                errors['name_exists'] = True
            else:
                category.edit(
                    name=fields['name']
                )
                flash('Category edited')
                return redirect(url_for('view_category', id=category.id))
    # If it is not a POST rquest, populate field values from database
    else:
        fields = {
            'name': category.name
        }
    return render_template('edit_category.html', fields=fields, errors=errors)


@app.route('/category/<int:id>/delete/', methods=['GET', 'POST'])
@login_required
@user_authorized(Category)
def delete_category(id):
    # Retrieve category of 404
    category = Category.get_or_404(id)
    if request.method == 'POST':
        category.delete()
        flash('Category successfully deleted')
        return redirect(url_for('view_all_categories'))
    return render_template('delete_category.html', category=category)
