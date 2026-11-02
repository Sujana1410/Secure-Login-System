"""
security.py
------------
Input validation helpers. Validating and constraining input shape is a
first line of defense (alongside parameterized queries) against
injection and malformed-data attacks.
"""

import re

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_username(username: str):
    if not username or not USERNAME_RE.match(username):
        return False, "Username must be 3-20 characters: letters, numbers, or underscore only."
    return True, ""


def validate_email(email: str):
    if not email or not EMAIL_RE.match(email):
        return False, "Please enter a valid email address."
    return True, ""


def validate_password(password: str):
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[a-z]", password):
        return False, "Password must include a lowercase letter."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include an uppercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must include a number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must include a special character."
    return True, ""


def validate_totp_code(code: str):
    if not code or not code.isdigit() or len(code) != 6:
        return False, "Enter the 6-digit code from your authenticator app."
    return True, ""
