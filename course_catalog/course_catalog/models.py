from sqlalchemy import Column, Integer, String, Sequence, ForeignKey
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, Sequence('user_id_seq'), primary_key=True)
    name = Column(String(50), nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    pwhash = Column(String)

    courses = relationship("Course", back_populates="user")

    def __init__(self, name, email, pwhash):
        self.name = name
        self.email = email
        self.pwhash = pwhash

    def __repr__(self):
        return '<User %r>' % (self.name)


class Course(Base):
    __tablename__ = 'courses'
    id = Column(Integer, Sequence('course_id_seq'), primary_key=True)
    name = Column(String(50), nullable=False)

    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship("User", back_populates="courses")

    school_id = Column(Integer, ForeignKey('schools.id'))
    school = relationship("School", back_populates="courses")

    category_id = Column(Integer, ForeignKey('categories.id'))
    category = relationship("Category", back_populates="courses")

    def __init__(self, name, user_id, school_id, category_id):
        self.name = name
        self.user_id = user_id
        self.school_id = school_id
        self.category_id = category_id

    def __repr__(self):
        return '<Course %r>' % (self.name)


class School(Base):
    __tablename__ = 'schools'
    id = Column(Integer, Sequence('school_id_seq'), primary_key=True)
    name = Column(String(50), nullable=False)

    courses = relationship("Course", back_populates="school")


class Category(Base):
    __tablename__ = 'categories'
    id = Column(Integer, Sequence('category_id_seq'), primary_key=True)
    name = Column(String(50), nullable=False)

    courses = relationship("Course", back_populates="category")
