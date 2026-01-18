import base64
import hashlib
import hmac
import os
from typing import Optional


def _get_admin_user() -> str:
    return os.environ.get("PANEL_ADMIN_USER", "admin")


def _get_admin_hash() -> str:
    return os.environ.get("PANEL_ADMIN_HASH", "")


def pbkdf2_hash(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


def encode_hash(password: str, iterations: int = 200_000) -> str:
    salt = os.urandom(16)
    dk = pbkdf2_hash(password, salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.urlsafe_b64encode(salt).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(dk).decode("ascii").rstrip("="),
    )


def verify(password: str, stored: str) -> bool:
    try:
        algo, it_s, salt_b64, dk_b64 = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(it_s)
        salt = base64.urlsafe_b64decode(salt_b64 + "==")
        dk = base64.urlsafe_b64decode(dk_b64 + "==")
        got = pbkdf2_hash(password, salt, iterations)
        return hmac.compare_digest(got, dk)
    except Exception:
        return False


def authenticate(username: str, password: str) -> bool:
    if username != _get_admin_user():
        return False
    stored = _get_admin_hash()
    if not stored:
        return False
    return verify(password, stored)
