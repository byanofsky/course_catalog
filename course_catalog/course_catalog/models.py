from course_catalog import db

# Rename base database model to Base
Base = db.Model


# Helper functions for Base class model
def create(cls, **kw):
    """Create and commit new instances"""
    # New instance
    i = cls(**kw)
    db.session.add(i)
    # Commit instance to db
    db.session.commit()
    # Return instance to access data
    return i


def get_by_id(cls, id):
    """Get an instance by id"""
    return cls.query.get(id)


def get_or_404(cls, id):
    """Get an instance by id. If does not exist, abort(404)"""
    return cls.query.get_or_404(id)


def get_n(cls, n, desc=False):
    """Get 'n' number of instances of a model.

    Args:
        cls (class): The database class.
        n (int): Number of instances to return.
        desc (bool): True shows in descending order. False in ascending.

    Returns:
        (object): An instance of the cls
    """
    if desc:
        return cls.query.order_by(cls.id.desc()).limit(n).all()
    else:
        return cls.query.order_by(cls.id).limit(n).all()


def get_all(cls):
    """Get all instances of class 'cls'."""
    return cls.query.all()


def delete(self):
    """Delete instance from database."""
    db.session.delete(self)
    db.session.commit()


def edit(self, **kw):
    """Edit instance and commit to database."""
    for i in kw:
        setattr(self, i, kw[i])
    db.session.add(self)
    db.session.commit()


# Assign helper functions to Base class model
Base.create = classmethod(create)
Base.get_by_id = classmethod(get_by_id)
Base.get_or_404 = classmethod(get_or_404)
Base.get_n = classmethod(get_n)
Base.get_all = classmethod(get_all)
Base.delete = delete
Base.edit = edit


class User(Base):
    __tablename__ = 'users'
    id = db.Column(db.Integer, db.Sequence('user_id_seq'), primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(120), unique=True, nullable=False)
    pwhash = db.Column(db.String(60), nullable=False)
    facebook_id = db.Column(db.Text)
    google_id = db.Column(db.Text)
    github_id = db.Column(db.Text)

    # TODO: do we need back_populates here?
    courses = db.relationship("Course", back_populates="user")
    schools = db.relationship("School", back_populates="user")
    categories = db.relationship("Category", back_populates="user")

    def __init__(self, name, email, pwhash,
                 facebook_id=None, google_id=None, github_id=None):
        self.name = name
        self.email = email
        self.pwhash = pwhash
        self.facebook_id = facebook_id
        self.google_id = google_id
        self.github_id = github_id

    def __repr__(self):
        return '<User %r>' % (self.name)

    @classmethod
    def get_by_email(cls, email):
        # TODO: shoud this be 'get' vs 'first'
        return cls.query.filter_by(email=email).one_or_none()

    @classmethod
    def get_by_providerid(cls, id, provider):
        # TODO: repetetive code. Get query, then one or none
        if provider == 'facebook':
            return cls.query.filter_by(facebook_id=id).one_or_none()
        elif provider == 'google':
            return cls.query.filter_by(google_id=id).one_or_none()
        elif provider == 'github':
            return cls.query.filter_by(github_id=id).one_or_none()
        else:
            return None


class Course(Base):
    __tablename__ = 'courses'
    id = db.Column(db.Integer, db.Sequence('course_id_seq'), primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    url = db.Column(db.Text)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship("User", back_populates="courses")

    school_id = db.Column(db.Integer, db.ForeignKey('schools.id'))
    school = db.relationship("School", back_populates="courses")

    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'))
    category = db.relationship("Category", back_populates="courses")

    def __init__(self, name, url, user_id, school_id, category_id):
        self.name = name
        self.url = url
        self.user_id = user_id
        self.school_id = school_id
        self.category_id = category_id

    def __repr__(self):
        return '<Course %r>' % (self.name)


class School(Base):
    __tablename__ = 'schools'
    id = db.Column(db.Integer, db.Sequence('school_id_seq'), primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    url = db.Column(db.Text)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship("User", back_populates="schools")

    courses = db.relationship("Course", back_populates="school")

    def __init__(self, name, url, user_id):
        self.name = name
        self.url = url
        self.user_id = user_id

    def __repr__(self):
        return '<School %r>' % (self.name)

    @classmethod
    def get_by_name(cls, name):
        return cls.query.filter_by(name=name).first()

class Category(Base):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, db.Sequence('category_id_seq'), primary_key=True)
    name = db.Column(db.String(50), nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship("User", back_populates="categories")

    courses = db.relationship("Course", back_populates="category")

    def __init__(self, name, user_id):
        self.name = name
        self.user_id = user_id

    def __repr__(self):
        return '<Category %r>' % (self.name)

    @classmethod
    def get_by_name(cls, name):
        return cls.query.filter_by(name=name).first()
