from course_catalog import app


@app.route('/')
@app.route('/courses/')
def view_all_courses():
    return 'Show all courses'


@app.route('/course/add/')
def add_course():
    return 'Add a new course'


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
