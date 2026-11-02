"""
totp.py
--------
A minimal, dependency-free implementation of TOTP (RFC 6238) for
optional Two-Factor Authentication, so the project has zero install
risk (no pyotp/qrcode required). Compatible with Google Authenticator,
Authy, Microsoft Authenticator, etc.
"""

import base64
import hashlib
import hmac
import os
import struct
import time


def generate_secret(length: int = 20) -> str:
    """Generate a random Base32-encoded secret (the standard TOTP format)."""
    random_bytes = os.urandom(length)
    return base64.b32encode(random_bytes).decode("utf-8")


def _hotp(secret: str, counter: int, digits: int = 6) -> str:
    key = base64.b32decode(secret.upper() + "=" * ((8 - len(secret) % 8) % 8))
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


def get_totp(secret: str, for_time: float = None, interval: int = 30, digits: int = 6) -> str:
    for_time = for_time if for_time is not None else time.time()
    counter = int(for_time // interval)
    return _hotp(secret, counter, digits)


def verify_totp(secret: str, code: str, interval: int = 30, digits: int = 6, window: int = 1) -> bool:
    """Verify a code, allowing +/- `window` time steps to tolerate clock drift."""
    if not code or not code.isdigit():
        return False
    now = time.time()
    for offset in range(-window, window + 1):
        candidate = get_totp(secret, for_time=now + offset * interval, interval=interval, digits=digits)
        if hmac.compare_digest(candidate, code):
            return True
    return False


def provisioning_uri(secret: str, account_name: str, issuer: str = "SecureLoginSystem") -> str:
    """Build the otpauth:// URI that authenticator apps understand.
    Can be turned into a QR code by any QR generator, or the secret can
    be entered manually."""
    label = f"{issuer}:{account_name}"
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={issuer}"
        f"&algorithm=SHA1&digits=6&period=30"
    )
