# Secure Login System

A Flask web app implementing secure user authentication: registration,
login, session management, and optional Two-Factor Authentication
(2FA) — built with security best practices and **zero external
dependencies beyond Flask** (so there's nothing that can fail to
install).

## Security Features

- **Hashed passwords** — uses Werkzeug's `generate_password_hash` /
  `check_password_hash` (scrypt, salted). Plain-text passwords are
  never stored or logged.
- **SQL injection protection** — every database query uses
  parameterized `?` placeholders (see `db.py`); user input is never
  concatenated into SQL text.
- **Input validation** — username, email, and password format/strength
  are validated server-side (`security.py`) before touching the
  database.
- **Session management** — Flask server-signed sessions with
  `HttpOnly` and `SameSite=Lax` cookies, a 30-minute session lifetime,
  and a full session reset on login/logout.
- **CSRF protection** — every POST form includes a per-session CSRF
  token that's verified on submission.
- **Brute-force protection** — accounts lock for 15 minutes after 5
  failed login attempts.
- **Optional 2FA (TOTP)** — RFC 6238 time-based one-time codes,
  compatible with Google Authenticator, Authy, Microsoft
  Authenticator, etc. Implemented from scratch in `totp.py` using only
  Python's standard library — no `pyotp`/`qrcode` install required.

## Requirements
- Python 3.8+ (Flask is the only dependency)

## Setup & Run

1. Unzip the project and open a terminal in the project folder.
2. (Recommended) Create a virtual environment:
   ```
   python -m venv venv
   venv\Scripts\activate      # Windows
   source venv/bin/activate   # macOS/Linux
   ```
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
4. Run the app:
   ```
   python app.py
   ```
5. Open your browser at:
   ```
   http://127.0.0.1:5003
   ```

The SQLite database (`users.db`) is created automatically on first run.

## Using It

1. **Register** a new account (username, email, password — the form
   enforces length + complexity rules).
2. **Log in** with your credentials.
3. From the **Dashboard**, click **Enable 2FA** to turn on
   two-factor authentication:
   - Add the shown key to an authenticator app via "Enter code
     manually" (or paste the setup URI into any QR-code generator to
     scan it instead).
   - Enter the 6-digit code it produces to confirm and enable 2FA.
4. Log out and log back in — you'll now be prompted for your
   authenticator code after your password.
5. Disable 2FA any time from the Dashboard.

## Project Structure
```
secure_login_system/
├── app.py               # Flask routes: register, login, logout, 2FA, dashboard
├── db.py                # SQLite access layer (parameterized queries only)
├── security.py          # Input validation (username/email/password/2FA code)
├── totp.py               # Dependency-free RFC 6238 TOTP implementation
├── requirements.txt
├── README.md
├── templates/
│   ├── base.html
│   ├── register.html
│   ├── login.html
│   ├── verify_2fa.html
│   ├── setup_2fa.html
│   └── dashboard.html
└── static/
    └── style.css
```

## Notes on Production Use
This is an educational/demo project. Before deploying for real:
- Set a fixed `SECRET_KEY` environment variable (otherwise a new
  random key is generated on every restart, invalidating sessions).
- Set `FORCE_HTTPS_COOKIES=1` and serve over HTTPS so the
  `Secure` cookie flag is honored.
- Consider rate-limiting login attempts by IP in addition to the
  existing per-account lockout.
- Consider adding email verification and a password-reset flow.
