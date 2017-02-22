import random, string

from flask import render_template, session, request, make_response
import requests

from course_catalog import app


@app.route('/')
@app.route('/courses/')
def view_all_courses():
    return 'Show all courses'


@app.route('/login/')
def login():
    # Creates and stores an anti-forgery token
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    session['state'] = state
    return render_template('login.html', STATE=state)


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
    pass


@app.route('/register/', methods=['GET', 'POST'])
def register():
    return render_template('register.html')


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
    return 'Show all schools'


@app.route('/school/add/')
def add_school():
    return 'Add a new school'


@app.route('/school/<int:school_id>/')
def view_school(school_id):
    return 'View single school with id ' + str(school_id)


@app.route('/school/<int:school_id>/edit/')
def edit_school(school_id):
    return 'Edit school with id ' + str(school_id)


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
