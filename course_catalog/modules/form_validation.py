import re


def valid_email(email):
    """Checks that email includes '@' and '.'.

    Args:
        email: String of representation of an email address.

    Returns:
        The email address string if it matches ('True'),
        or 'None' if no match.
    """
    return re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)",
                    email)


def valid_password(password):
    """Checks that a password is at least 3 characters.

    Args:
        password: The string representing the password.

    Returns:
        The password string if it matches ('True'),
        or 'None' if no match.
    """
    return re.match(r"[a-zA-Z0-9]{3,}", password)


def check_registration(fields, user_exists):
    """Checks that all fields in registrtion form are valid.

    Args:
        fields: A dict containing fields from registration form.
        user_exists: A boolean value. True if user exists,
            false if user does not exist.

    Returns:
        A dict of any errors. If no errors, returns an empty dict (False).
    """
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
    """Checks that all fields in login form are valid.

    Args:
        fields: A dict containing fields from login form.

    Returns:
        A dict of any errors. If no errors, returns an empty dict (False).
    """
    errors = {}
    if not valid_email(fields['email']):
        errors['email'] = True
    if not fields['password']:
        errors['password'] = True
    return errors


def check_no_blanks(fields):
    """Checks that no fields are empty.

    Args:
        fields: A dict containing fields from a form.

    Returns:
        A dict of any errors. If no errors, returns an empty dict (False).
    """
    errors = {}
    for field in fields:
        if fields[field] == '':
            errors[field] = True
    return errors
