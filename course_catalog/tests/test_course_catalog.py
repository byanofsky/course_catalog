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

    def test_registration(self):
        rv = self.register('by@me.com', 'Brandon', '12345', '12345')
        assert b'You were successfully registered' in rv.data
        rv = self.register('by', 'Brandon', '12345', '12345')
        assert b'Please enter a valid email address.' in rv.data
        rv = self.register('by@me.com', 'Brandon', '12345', '12345')
        assert b'A user already exists with this email address.' in rv.data
        rv = self.register('by@me.com', 'Brandon', '12', '12')
        assert b'Please enter a valid password, at least 3 characters long.' in rv.data
        rv = self.register('by@me.com', 'Brandon', '12345', '56789')
        assert b'Please re-enter your password correctly.' in rv.data

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

    def test_logout(self):
        self.register('by@me.com', 'Brandon', '12345', '12345')
        self.login('by@me.com', '12345')
        rv = self.app.get('/school/add/')
        assert b'Add School' in rv.data
        rv = self.app.get('/logout/', follow_redirects=True)
        assert b'You were successfully logged out' in rv.data
        rv = self.app.get('/school/add/', follow_redirects=True)
        assert b'Login' in rv.data

    def test_login_next(self):
        self.register('by@me.com', 'Brandon', '12345', '12345')
        self.app.get('/logout/', follow_redirects=True)

        with course_catalog.app.test_client() as c:
            rv = c.get('/school/add/', follow_redirects=True)
            arg = flask.request.args['next']
            rv = c.post('/login/?next=' + arg, data=dict(
                email='by@me.com',
                password='12345'
            ), follow_redirects=True)
            assert b'Add School' in rv.data

    def test_add_school(self):
        self.register('by@me.com', 'Brandon', '12345', '12345')
        rv = self.login('by@me.com', '12345')
        assert b'You were successfully logged in' in rv.data
        rv = self.app.get('/school/add/')
        assert b'Add School' in rv.data
        rv = self.app.post('/school/add/', data=dict(
            name='Udacity',
            url='www.udacity.com'
        ), follow_redirects=True)
        assert b'School created' in rv.data
        assert b'Udacity' in rv.data
        assert b'www.udacity.com' in rv.data
        assert b'Brandon' in rv.data




if __name__ == '__main__':
    unittest.main()
