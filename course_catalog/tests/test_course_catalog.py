import os
import course_catalog
import unittest
import tempfile
import flask

class CourseCatalogTestCase(unittest.TestCase):
    def setUp(self):
        self.test_db_path = 'tests/test.db'
        course_catalog.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../' + self.test_db_path
        course_catalog.app.config['TESTING'] = True
        self.app = course_catalog.app.test_client()
        with course_catalog.app.app_context():
            course_catalog.course_catalog.init_db()

    def tearDown(self):
        os.unlink(os.path.abspath(self.test_db_path))

    def test_empty_db(self):
        rv = self.app.get('/')
        assert b'No courses' in rv.data

    def register(self, email, name, password, verify_password):
        return self.app.post('/register/', data=dict(
            email=email,
            name=name,
            password=password,
            verify_password=verify_password,
        ), follow_redirects=True)

    def test_registration_errors(self):
        rv = self.register('by', 'Brandon', '12345', '12345')
        assert b'Please enter a valid email address.' in rv.data
        rv = self.register('by@me.com', 'Brandon', '12', '12')
        assert b'Please enter a valid password, at least 3 characters long.' in rv.data
        rv = self.register('by@me.com', 'Brandon', '12345', '56789')
        assert b'Please re-enter your password correctly.' in rv.data
        rv = self.register('by@me.com', 'Brandon', '12345', '12345')
        assert b'You were successfully registered' in rv.data
        rv = self.register('by@me.com', 'Brandon', '12345', '12345')
        assert b'A user already exists with this email address.' in rv.data

    def login(self, email, password):
        return self.app.post('/login/', data=dict(
            email=email,
            password=password
        ), follow_redirects=True)

    def test_login(self):
        rv = self.register('by@me.com', 'Brandon', '12345', '12345')
        assert b'You were successfully registered' in rv.data
        rv = self.login('by', '12345')
        assert b'Please enter a valid email address.' in rv.data
        rv = self.login('by@me.com', '567')
        assert b'This password is incorrect.' in rv.data
        rv = self.login('random@me.com', '12345')
        assert b'There is no user with this email address.' in rv.data
        rv = self.login('by@me.com', '12345')
        assert b'You were successfully logged in' in rv.data

    def test_registration_and_login_cookies(self):
        with self.app:
            self.app.get('/')
            rv = self.register('by@me.com', 'Brandon', '12345', '12345')
            assert b'You were successfully registered' in rv.data
            assert flask.session['user_id'] == 1
            self.app.get('/logout/')
            assert 'user_id' not in flask.session
            rv = self.login('by@me.com', '12345')
            assert b'You were successfully logged in' in rv.data
            assert flask.session['user_id'] == 1

    def test_login_next(self):
        with self.app:
            self.register('by@me.com', 'Brandon', '12345', '12345')
            self.app.get('/logout/', follow_redirects=True)
            assert 'user_id' not in flask.session
            rv = self.app.get('/school/add/')
            url = rv.headers['Location']
            rv = self.app.post(url, data=dict(
                email='by@me.com',
                password='12345'
            ), follow_redirects=True)
            assert b'Add School' in rv.data
            assert flask.session['user_id'] == 1

    def test_add_school(self):
        self.register('by@me.com', 'Brandon', '12345', '12345')
        rv = self.login('by@me.com', '12345')
        assert b'You were successfully logged in' in rv.data
        rv = self.app.get('/school/add/')
        assert b'Add School' in rv.data
        rv = self.app.post('/school/add/', data=dict(
            name='Brandon Test School',
            url='www.brandonschool.com'
        ), follow_redirects=True)
        assert b'School created' in rv.data
        assert b'Brandon Test School' in rv.data
        assert b'www.brandonschool.com' in rv.data
        assert b'Brandon' in rv.data
        rv = self.app.get('/schools/')
        assert b'Brandon Test School' in rv.data

    def test_add_and_delete_school(self):
        self.register('by2@me.com', 'Brandon', '12345', '12345')
        rv = self.login('by2@me.com', '12345')
        assert b'You were successfully logged in' in rv.data
        rv = self.app.get('/school/add/')
        assert b'Add School' in rv.data
        rv = self.app.post('/school/add/', data=dict(
            name='Udacity',
            url='www.udacity.com'
        ))
        school_url = rv.headers['Location']
        rv = self.app.get(school_url)
        assert b'School created' in rv.data
        assert b'Udacity' in rv.data
        assert b'www.udacity.com' in rv.data
        assert b'Brandon' in rv.data
        rv = self.app.post(school_url + 'delete/', follow_redirects=True)
        assert b'School successfully deleted' in rv.data
        # TODO: check login won't work right now
        # rv = self.app.get(school_url + 'delete/', follow_redirects=True)
        # assert b'There is no school with that id' in rv.data

    def test_categories(self):
        self.register('by3@me.com', 'User Test', '12345', '12345')
        rv = self.app.get('/category/add/')
        assert b'Add Category' in rv.data
        rv = self.app.post('/category/add/', data=dict(
            name='',
        ), follow_redirects=True)
        assert b'Please enter a category name' in rv.data
        rv = self.app.post('/category/add/', data=dict(
            name='Test Category',
        ), follow_redirects=True)
        assert b'Category created' in rv.data
        assert b'Test Category' in rv.data
        assert b'User Test' in rv.data
        rv = self.app.post('/category/add/', data=dict(
            name='Test Category 2',
        ), follow_redirects=True)
        assert b'Test Category 2' in rv.data
        assert b'User Test' in rv.data
        rv = self.app.post('/category/1/edit/', data=dict(
            name='Test Category 1',
        ), follow_redirects=True)
        assert b'Category edited' in rv.data
        assert b'Test Category 1' in rv.data
        assert b'User Test' in rv.data
        rv = self.app.get('/categories/')
        assert b'Test Category 1' in rv.data
        assert b'Test Category 2' in rv.data
        rv = self.app.post('/category/1/delete/', follow_redirects=True)
        assert b'Category successfully deleted' in rv.data
        rv = self.app.get('/categories/')
        assert b'Test Category 1' not in rv.data

if __name__ == '__main__':
    unittest.main()
