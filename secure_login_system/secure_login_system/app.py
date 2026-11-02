"""
Secure Login System — Flask web app.

Implements:
  - User registration & login with hashed passwords
    (Werkzeug's scrypt-based generate_password_hash/check_password_hash —
    a modern, salted KDF equivalent in strength to bcrypt/Argon2, and
    it ships with Flask so there's nothing extra to install)
  - Input validation + parameterized SQL queries everywhere (see db.py)
    to protect against SQL injection
  - Server-side session management with secure cookie flags and logout
  - Basic brute-force protection (account lockout after repeated
    failed attempts)
  - Lightweight CSRF protection on all POST forms
  - Optional Two-Factor Authentication (TOTP, RFC 6238) — see totp.py
"""

import os
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash

import db
import totp as totp_lib
from security import validate_username, validate_email, validate_password, validate_totp_code

APP_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)

# In production, set SECRET_KEY via an environment variable instead of
# generating a new one on every restart (that would invalidate all
# existing sessions). A random fallback is used here so the app is
# runnable out of the box.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Enable this when serving over HTTPS in production:
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FORCE_HTTPS_COOKIES", "0") == "1"
app.permanent_session_lifetime = timedelta(minutes=30)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


# ---------------------------------------------------------------------
# CSRF protection (lightweight, dependency-free)
# ---------------------------------------------------------------------
def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = get_csrf_token


def csrf_protect():
    token = session.get("csrf_token")
    submitted = request.form.get("csrf_token")
    if not token or not submitted or not secrets.compare_digest(token, submitted):
        abort(400, description="Invalid or missing CSRF token.")


# ---------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def is_locked_out(user_row) -> bool:
    locked_until = user_row["locked_until"]
    if not locked_until:
        return False
    try:
        return datetime.utcnow() < datetime.fromisoformat(locked_until)
    except ValueError:
        return False


# ---------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------
@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        csrf_protect()

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        ok, msg = validate_username(username)
        if not ok:
            flash(msg, "error")
            return render_template("register.html")

        ok, msg = validate_email(email)
        if not ok:
            flash(msg, "error")
            return render_template("register.html")

        ok, msg = validate_password(password)
        if not ok:
            flash(msg, "error")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        # These SELECTs use parameterized queries (db.py) — the raw
        # username/email are never concatenated into SQL text.
        if db.get_user_by_username(username):
            flash("That username is already taken.", "error")
            return render_template("register.html")
        if db.get_user_by_email(email):
            flash("That email is already registered.", "error")
            return render_template("register.html")

        password_hash = generate_password_hash(password)  # scrypt, salted
        db.create_user(username, email, password_hash)

        flash("Account created! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        csrf_protect()

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = db.get_user_by_username(username)

        if not user:
            db.record_login_attempt(username, False, "no such user")
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        if is_locked_out(user):
            flash(
                f"This account is temporarily locked due to repeated failed "
                f"logins. Try again after {LOCKOUT_MINUTES} minutes.",
                "error",
            )
            return render_template("login.html")

        if not check_password_hash(user["password_hash"], password):
            attempts = db.increment_failed_attempts(username)
            db.record_login_attempt(username, False, "bad password")
            if attempts >= MAX_FAILED_ATTEMPTS:
                locked_until = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
                db.set_locked_until(username, locked_until)
                flash(
                    f"Too many failed attempts. Account locked for {LOCKOUT_MINUTES} minutes.",
                    "error",
                )
            else:
                remaining = MAX_FAILED_ATTEMPTS - attempts
                flash(f"Invalid username or password. {remaining} attempt(s) left before lockout.", "error")
            return render_template("login.html")

        # Password correct — reset lockout counters
        db.reset_failed_attempts(username)

        if user["totp_enabled"]:
            # Require the second factor before establishing a full session
            session["pending_user_id"] = user["id"]
            db.record_login_attempt(username, True, "password ok, awaiting 2FA")
            return redirect(url_for("verify_2fa"))

        # No 2FA — log the user in now
        session.clear()
        session.permanent = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        db.record_login_attempt(username, True, "logged in")
        flash(f"Welcome back, {user['username']}!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    pending_id = session.get("pending_user_id")
    if not pending_id:
        return redirect(url_for("login"))

    user = db.get_user_by_id(pending_id)
    if not user or not user["totp_enabled"]:
        session.pop("pending_user_id", None)
        return redirect(url_for("login"))

    if request.method == "POST":
        csrf_protect()
        code = request.form.get("code", "").strip()

        ok, msg = validate_totp_code(code)
        if not ok:
            flash(msg, "error")
            return render_template("verify_2fa.html")

        if totp_lib.verify_totp(user["totp_secret"], code):
            session.pop("pending_user_id", None)
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            db.record_login_attempt(user["username"], True, "2FA verified")
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("dashboard"))
        else:
            db.record_login_attempt(user["username"], False, "bad 2FA code")
            flash("Incorrect code. Please try again.", "error")

    return render_template("verify_2fa.html")


@app.route("/dashboard")
@login_required
def dashboard():
    user = db.get_user_by_id(session["user_id"])
    return render_template("dashboard.html", user=user)


@app.route("/logout", methods=["POST"])
def logout():
    csrf_protect()
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------
# Optional 2FA setup / disable
# ---------------------------------------------------------------------
@app.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    user = db.get_user_by_id(session["user_id"])

    if user["totp_enabled"]:
        flash("Two-factor authentication is already enabled.", "success")
        return redirect(url_for("dashboard"))

    if "pending_totp_secret" not in session:
        session["pending_totp_secret"] = totp_lib.generate_secret()

    secret = session["pending_totp_secret"]
    uri = totp_lib.provisioning_uri(secret, user["username"])

    if request.method == "POST":
        csrf_protect()
        code = request.form.get("code", "").strip()

        ok, msg = validate_totp_code(code)
        if not ok:
            flash(msg, "error")
            return render_template("setup_2fa.html", secret=secret, uri=uri)

        if totp_lib.verify_totp(secret, code):
            db.set_totp_secret(user["id"], secret)
            db.enable_totp(user["id"])
            session.pop("pending_totp_secret", None)
            flash("Two-factor authentication is now enabled on your account.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("That code didn't match. Please check your authenticator app and try again.", "error")

    return render_template("setup_2fa.html", secret=secret, uri=uri)


@app.route("/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    csrf_protect()
    db.disable_totp(session["user_id"])
    flash("Two-factor authentication has been disabled.", "success")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    db.init_db()
    app.run(debug=True, host="0.0.0.0", port=5003)
