import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from typing import Optional

CRED_PATH = "/etc/realm-panel/credentials.json"
SECRET_PATH = "/etc/realm-panel/secret.key"


@dataclass
class Credentials:
    username: str
    salt_b64: str
    hash_b64: str
    iterations: int = 120_000


def _pbkdf2(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


def ensure_secret_key() -> str:
    # Allow overriding the session/share secret via env so multiple panel instances
    # behind a load balancer can validate the same cookies & share tokens.
    #
    # Recommended for HA deployments:
    #   export REALM_PANEL_SECRET_KEY='<a stable random string>'
    env_key = (os.getenv("REALM_PANEL_SECRET_KEY") or "").strip()
    if len(env_key) > 10:
        return env_key

    os.makedirs(os.path.dirname(SECRET_PATH), exist_ok=True)
    if os.path.exists(SECRET_PATH) and os.path.getsize(SECRET_PATH) > 10:
        with open(SECRET_PATH, "r", encoding="utf-8") as f:
            return f.read().strip()
    key = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")
    with open(SECRET_PATH, "w", encoding="utf-8") as f:
        f.write(key)
    try:
        os.chmod(SECRET_PATH, 0o600)
    except PermissionError:
        # Non-root deployments might not be able to chmod files created by root.
        pass
    return key


def load_credentials() -> Optional[Credentials]:
    if not os.path.exists(CRED_PATH):
        return None
    try:
        with open(CRED_PATH, "r", encoding="utf-8") as f:
            obj = json.load(f)
        return Credentials(
            username=obj.get("username", "admin"),
            salt_b64=obj["salt_b64"],
            hash_b64=obj["hash_b64"],
            iterations=int(obj.get("iterations", 120_000)),
        )
    except Exception:
        return None


def save_credentials(username: str, password: str, iterations: int = 120_000) -> None:
    # Use unicode character length instead of byte length.
    # Otherwise non-ASCII passwords can be incorrectly rejected.
    if len(password) < 6:
        raise ValueError("Password too short")
    os.makedirs(os.path.dirname(CRED_PATH), exist_ok=True)
    salt = os.urandom(16)
    dk = _pbkdf2(password, salt, iterations)
    obj = {
        "username": username.strip() or "admin",
        "salt_b64": base64.b64encode(salt).decode("utf-8"),
        "hash_b64": base64.b64encode(dk).decode("utf-8"),
        "iterations": iterations,
        "algo": "pbkdf2_sha256",
    }
    with open(CRED_PATH, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    try:
        os.chmod(CRED_PATH, 0o600)
    except PermissionError:
        # Non-root deployments might not be able to chmod files created by root.
        pass


def verify_login(username: str, password: str) -> bool:
    cred = load_credentials()
    if cred is None:
        # 未初始化时不允许登录
        return False
    if username.strip() != cred.username:
        return False
    try:
        salt = base64.b64decode(cred.salt_b64)
        expected = base64.b64decode(cred.hash_b64)
        dk = _pbkdf2(password, salt, cred.iterations)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False
