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

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, Sequence('user_id_seq'), primary_key=True)
    name = Column(String(50))
    email = Column(String(120), unique=True, nullable=False)
    pwhash = Column(Text)

    courses = relationship("Course", back_populates="user")

    schools = relationship("School", back_populates="user")

    def __init__(self, name, email, pwhash):
        self.name = name
        self.email = email
        self.pwhash = pwhash

    def __repr__(self):
        return '<User %r>' % (self.name)

    @classmethod
    def get_by_email(cls, email):
        return cls.query.filter_by(email=email).first()

    @classmethod
    def create(cls, name, email, pwhash):
        user = cls(name, email, pwhash)
        db_session.add(user)
        db_session.commit()
        return user


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

    @classmethod
    def create(cls, name, url, user_id, school_id, category_id):
        course = cls(name, url, user_id, school_id, category_id)
        db_session.add(course)
        db_session.commit()


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

    def edit(self, name, url):
        self.name = name
        self.url = url
        db_session.add(self)
        db_session.commit()

    @classmethod
    def get_by_name(cls, name):
        return cls.query.filter_by(name=name).first()

    @classmethod
    def get_by_id(cls, id):
        return cls.query.filter_by(id=id).first()

    @classmethod
    def get_all(cls):
        return cls.query.all()

    @classmethod
    def create(cls, name, url, user_id):
        school = cls(name, url, user_id)
        db_session.add(school)
        db_session.commit()
        return school

class Category(Base):
    __tablename__ = 'categories'
    id = Column(Integer, Sequence('category_id_seq'), primary_key=True)
    name = Column(String(50), nullable=False)

    courses = relationship("Course", back_populates="category")
