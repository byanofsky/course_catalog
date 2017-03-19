from course_catalog import db

# from database import Base, db_session

# db = SQLAlchemy(app)
db_session = db.session
Base = db.Model
Column = db.Column
Integer = db.Integer
String = db.String
Sequence = db.Sequence
ForeignKey = db.ForeignKey
Text = db.Text
relationship = db.relationship


# Create helper methods for Base class model
def create(cls, **kw):
    instance = cls(**kw)
    db_session.add(instance)
    db_session.commit()
    return instance

def get_by_id(cls, id):
    return cls.query.get(id)

def get_or_404(cls, id):
    return cls.query.get_or_404(id)

def get_all(cls):
    return cls.query.all()

def delete(self):
    db_session.delete(self)
    db_session.commit()

def edit(self, **kw):
    for i in kw:
        setattr(self, i, kw[i])
    db_session.add(self)
    db_session.commit()


# Assign helper methods to Base class model
Base.create = classmethod(create)
Base.get_by_id = classmethod(get_by_id)
Base.get_or_404 = classmethod(get_or_404)
Base.get_all = classmethod(get_all)
Base.delete = delete
Base.edit = edit


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, Sequence('user_id_seq'), primary_key=True)
    name = Column(String(50))
    email = Column(String(120), unique=True, nullable=False)
    pwhash = Column(Text)
    facebook_id = Column(Text)
    google_id = Column(Text)
    github_id = Column(Text)

    courses = relationship("Course", back_populates="user")

    schools = relationship("School", back_populates="user")

    categories = relationship("Category", back_populates="user")

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
        return cls.query.filter_by(email=email).first()

    @classmethod
    def get_by_providerid(cls, id, provider):
        if provider == 'facebook':
            return cls.query.filter_by(facebook_id=id).first()
        elif provider == 'google':
            return cls.query.filter_by(google_id=id).first()
        elif provider == 'github':
            return cls.query.filter_by(github_id=id).first()
        else:
            return None


class Course(Base):
    __tablename__ = 'courses'
    id = Column(Integer, Sequence('course_id_seq'), primary_key=True)
    name = Column(String(50), nullable=False)
    url = Column(Text)

    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship("User", back_populates="courses")

    school_id = Column(Integer, ForeignKey('schools.id'))
    school = relationship("School", back_populates="courses")

    category_id = Column(Integer, ForeignKey('categories.id'))
    category = relationship("Category", back_populates="courses")

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
    id = Column(Integer, Sequence('school_id_seq'), primary_key=True)
    name = Column(String(50), nullable=False, unique=True)
    url = Column(Text)

    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship("User", back_populates="schools")

    courses = relationship("Course", back_populates="school")

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
    id = Column(Integer, Sequence('category_id_seq'), primary_key=True)
    name = Column(String(50), nullable=False)

    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship("User", back_populates="categories")

    courses = relationship("Course", back_populates="category")

    def __init__(self, name, user_id):
        self.name = name
        self.user_id = user_id

    def __repr__(self):
        return '<Category %r>' % (self.name)

    @classmethod
    def get_by_name(cls, name):
        return cls.query.filter_by(name=name).first()
