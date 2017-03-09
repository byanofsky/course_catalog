import re


def valid_email(email):
    return re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)",
                    email)


def valid_password(password):
    return re.match(r"[a-zA-Z0-9]{3,}", password)


def check_registration(fields, user_exists):
    errors = {}
    if user_exists:
        errors['user_exists'] = True
    if not valid_email(fields['email']):
        errors['email'] = True
    if not fields['name']:
        errors['name'] = True
    if not valid_password(fields['password']):
        errors['password'] = True
    if fields['password'] != fields['verify_password']:
        errors['verify_password'] = True
    return errors

def check_login(fields):
    errors = {}
    if not valid_email(fields['email']):
        errors['email'] = True
    if not fields['password']:
        errors['password'] = True
    return errors

def check_no_blanks(fields):
    errors = {}
    for field in fields:
        if fields[field] == '':
            errors[field] = True
    return errors
