from setuptools import setup

setup(
    name='course_catalog',
    packages=['course_catalog'],
    include_package_data=True,
    install_requires=[
        'flask',
        'SQLAlchemy',
        'flask_sqlalchemy',
        'flask_bcrypt',
        'requests'
    ],
)
