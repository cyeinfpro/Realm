from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass


# A tiny, dependency-free password hashing implementation.
#
# Format:
#   pbkdf2_sha256$<iterations>$<salt_b64url_nopad>$<hash_b64url_nopad>
#
# Notes:
# - PBKDF2-HMAC-SHA256 is available in Python stdlib.
# - No 72-byte password limit (unlike bcrypt).


@dataclass(frozen=True)
class Pbkdf2Config:
    iterations: int = 260_000
    salt_bytes: int = 16
    dklen: int = 32


CFG = Pbkdf2Config()


def _b64u_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64u_nopad_decode(s: str) -> bytes:
    s = s.strip()
    # restore padding
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def hash_password(password: str) -> str:
    if password is None:
        raise ValueError("password is None")
    pw = password.encode("utf-8")
    salt = secrets.token_bytes(CFG.salt_bytes)
    dk = hashlib.pbkdf2_hmac("sha256", pw, salt, CFG.iterations, dklen=CFG.dklen)
    return f"pbkdf2_sha256${CFG.iterations}${_b64u_nopad(salt)}${_b64u_nopad(dk)}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        if not password_hash or "$" not in password_hash:
            return False

        parts = password_hash.split("$")
        if len(parts) != 4:
            return False

        scheme, iters_s, salt_s, hash_s = parts
        if scheme != "pbkdf2_sha256":
            return False

        iters = int(iters_s)
        salt = _b64u_nopad_decode(salt_s)
        expected = _b64u_nopad_decode(hash_s)

        pw = (password or "").encode("utf-8")
        actual = hashlib.pbkdf2_hmac("sha256", pw, salt, iters, dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False
