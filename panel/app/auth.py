from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .db import (
    count_users,
    create_user_record,
    delete_user_record,
    ensure_builtin_roles,
    get_role_by_name,
    get_user_auth_record_by_id,
    get_user_auth_record_by_username,
    list_roles,
    list_users,
    sum_rule_traffic_bytes,
    sum_user_rule_traffic_bytes,
    touch_user_login,
    update_user_record,
)

CRED_PATH = "/etc/realm-panel/credentials.json"
SECRET_PATH = "/etc/realm-panel/secret.key"
DEFAULT_PBKDF2_ITERATIONS = 120_000
_LOGIN_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,48}$")
_ALLOWED_TUNNEL_TYPES = {"direct", "wss", "intranet"}


def _normalize_tunnel_type_name(value: Any) -> str:
    name = str(value or "").strip().lower()
    # Backward compatibility:
    # tcp/normal are historical names in some UI logic; canonicalize to "direct".
    if name in ("tcp", "normal"):
        return "direct"
    return name


@dataclass
class Credentials:
    username: str
    salt_b64: str
    hash_b64: str
    iterations: int = DEFAULT_PBKDF2_ITERATIONS


@dataclass
class AuthUser:
    id: int
    username: str
    role_id: int
    role_name: str
    permissions: frozenset[str] = field(default_factory=frozenset)
    enabled: bool = True
    expires_at: Optional[str] = None
    policy: Dict[str, Any] = field(default_factory=dict)


def _pbkdf2(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))


def _hash_password(password: str, iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> Tuple[str, str, int]:
    if len(password) < 6:
        raise ValueError("Password too short")
    salt = os.urandom(16)
    dk = _pbkdf2(password, salt, iterations)
    return (
        base64.b64encode(salt).decode("utf-8"),
        base64.b64encode(dk).decode("utf-8"),
        int(iterations),
    )


def _verify_password(password: str, salt_b64: str, hash_b64: str, iterations: int) -> bool:
    try:
        salt = base64.b64decode(str(salt_b64 or "").strip())
        expected = base64.b64decode(str(hash_b64 or "").strip())
        got = _pbkdf2(password, salt, int(iterations or DEFAULT_PBKDF2_ITERATIONS))
        return hmac.compare_digest(expected, got)
    except Exception:
        return False


def _normalize_permissions(perms: Iterable[Any]) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    for p in perms:
        name = str(p or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out


def _to_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return bool(default)
    s = str(value).strip().lower()
    if not s:
        return bool(default)
    if s in ("1", "true", "yes", "on", "y"):
        return True
    if s in ("0", "false", "no", "off", "n"):
        return False
    return bool(default)


def _parse_dt(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except Exception:
        return None
    if dt.tzinfo is None:
        try:
            local_tz = datetime.now().astimezone().tzinfo
        except Exception:
            local_tz = timezone.utc
        dt = dt.replace(tzinfo=local_tz or timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize_expires_at(value: Any) -> Optional[str]:
    dt = _parse_dt(value)
    return dt.isoformat() if dt else None


def is_expires_at_expired(expires_at: Any) -> bool:
    dt = _parse_dt(expires_at)
    if dt is None:
        return False
    return datetime.now(timezone.utc) >= dt


def normalize_user_policy(raw_policy: Any) -> Dict[str, Any]:
    p = raw_policy if isinstance(raw_policy, dict) else {}
    out: Dict[str, Any] = {}

    node_ids: List[int] = []
    raw_node_ids = p.get("allowed_node_ids")
    if isinstance(raw_node_ids, str):
        raw_node_ids = [x.strip() for x in raw_node_ids.split(",") if x.strip()]
    if isinstance(raw_node_ids, list):
        seen_nodes: set[int] = set()
        for item in raw_node_ids:
            try:
                nid = int(item)
            except Exception:
                continue
            if nid <= 0 or nid in seen_nodes:
                continue
            seen_nodes.add(nid)
            node_ids.append(nid)
    out["allowed_node_ids"] = node_ids

    tunnel_types: List[str] = []
    has_tunnel_types_key = "allowed_tunnel_types" in p
    if "tunnel_limit_enabled" in p:
        tunnel_limit_enabled = _to_bool(p.get("tunnel_limit_enabled"), default=False)
    else:
        # Backward compatibility:
        # if a legacy policy explicitly persisted allowed_tunnel_types, treat it as an enabled limit.
        tunnel_limit_enabled = bool(has_tunnel_types_key)

    raw_tunnels = p.get("allowed_tunnel_types")
    if isinstance(raw_tunnels, str):
        raw_tunnels = [x.strip() for x in raw_tunnels.split(",") if x.strip()]
    if isinstance(raw_tunnels, list):
        seen_tunnels: set[str] = set()
        for item in raw_tunnels:
            name = _normalize_tunnel_type_name(item)
            if name not in _ALLOWED_TUNNEL_TYPES or name in seen_tunnels:
                continue
            seen_tunnels.add(name)
            tunnel_types.append(name)
    out["tunnel_limit_enabled"] = bool(tunnel_limit_enabled)
    out["allowed_tunnel_types"] = tunnel_types

    try:
        quota = int(float(p.get("max_monthly_traffic_bytes") or 0))
    except Exception:
        quota = 0
    if quota < 0:
        quota = 0
    out["max_monthly_traffic_bytes"] = int(quota)
    return out


def _secret_path_candidates() -> List[str]:
    out: List[str] = []
    seen: set[str] = set()

    def _add(path: Any) -> None:
        p = str(path or "").strip()
        if not p or p in seen:
            return
        seen.add(p)
        out.append(p)

    _add(os.getenv("REALM_PANEL_SECRET_PATH"))
    _add(SECRET_PATH)

    db_path = str(os.getenv("REALM_PANEL_DB") or "").strip()
    if db_path:
        _add(os.path.join(os.path.dirname(db_path), "secret.key"))

    runtime_dir = str(os.getenv("XDG_RUNTIME_DIR") or "").strip()
    if runtime_dir:
        _add(os.path.join(runtime_dir, "realm-panel-secret.key"))

    _add("/tmp/realm-panel-secret.key")
    return out


def ensure_secret_key() -> str:
    # Allow overriding the session/share secret via env so multiple panel instances
    # behind a load balancer can validate the same cookies & share tokens.
    env_key = (os.getenv("REALM_PANEL_SECRET_KEY") or "").strip()
    if len(env_key) > 10:
        return env_key

    candidates = _secret_path_candidates()
    for path in candidates:
        try:
            if os.path.exists(path) and os.path.getsize(path) > 10:
                with open(path, "r", encoding="utf-8") as f:
                    key = f.read().strip()
                if len(key) > 10:
                    return key
        except Exception:
            continue

    key = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")
    for path in candidates:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(key)
            try:
                os.chmod(path, 0o600)
            except PermissionError:
                pass
            return key
        except Exception:
            continue

    # Last resort: keep process alive even if filesystem is read-only.
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
            iterations=int(obj.get("iterations", DEFAULT_PBKDF2_ITERATIONS)),
        )
    except Exception:
        return None


def save_credentials(username: str, password: str, iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> None:
    # Legacy compatibility: keep credentials.json in sync for old deployments/tools.
    if len(password) < 6:
        raise ValueError("Password too short")
    os.makedirs(os.path.dirname(CRED_PATH), exist_ok=True)
    salt = os.urandom(16)
    dk = _pbkdf2(password, salt, iterations)
    obj = {
        "username": (username or "").strip() or "admin",
        "salt_b64": base64.b64encode(salt).decode("utf-8"),
        "hash_b64": base64.b64encode(dk).decode("utf-8"),
        "iterations": int(iterations),
        "algo": "pbkdf2_sha256",
    }
    with open(CRED_PATH, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    try:
        os.chmod(CRED_PATH, 0o600)
    except PermissionError:
        pass


def _auth_user_from_record(record: Dict[str, Any]) -> Optional[AuthUser]:
    if not isinstance(record, dict):
        return None
    role_name = str(record.get("role_name") or "").strip()
    if not role_name:
        return None
    policy = normalize_user_policy(record.get("policy") or {})
    return AuthUser(
        id=int(record.get("id") or 0),
        username=str(record.get("username") or "").strip(),
        role_id=int(record.get("role_id") or 0),
        role_name=role_name,
        permissions=frozenset(_normalize_permissions(record.get("role_permissions") or [])),
        enabled=bool(record.get("enabled") or 0),
        expires_at=str(record.get("expires_at") or "").strip() or None,
        policy=policy,
    )


def _is_user_record_active(record: Dict[str, Any]) -> bool:
    if not isinstance(record, dict):
        return False
    if not bool(record.get("enabled") or 0):
        return False
    expires_at = record.get("expires_at")
    if expires_at and is_expires_at_expired(expires_at):
        return False
    return True


def migrate_legacy_credentials_if_needed() -> None:
    try:
        ensure_builtin_roles()
    except Exception:
        return
    try:
        if count_users() > 0:
            return
    except Exception:
        return
    cred = load_credentials()
    if cred is None:
        return
    role = get_role_by_name("owner")
    if not role:
        return
    username = str(cred.username or "").strip() or "admin"
    exists = get_user_auth_record_by_username(username)
    if exists:
        return
    try:
        create_user_record(
            username=username,
            salt_b64=str(cred.salt_b64 or "").strip(),
            hash_b64=str(cred.hash_b64 or "").strip(),
            iterations=int(cred.iterations or DEFAULT_PBKDF2_ITERATIONS),
            role_id=int(role["id"]),
            enabled=True,
            expires_at=None,
            policy={},
            created_by="legacy-migrator",
        )
    except Exception:
        pass


def has_accounts() -> bool:
    migrate_legacy_credentials_if_needed()
    try:
        return count_users() > 0
    except Exception:
        return load_credentials() is not None


def setup_initial_owner(username: str, password: str) -> AuthUser:
    migrate_legacy_credentials_if_needed()
    if count_users() > 0:
        raise ValueError("账号已初始化")
    role = get_role_by_name("owner")
    if not role:
        ensure_builtin_roles()
        role = get_role_by_name("owner")
    if not role:
        raise RuntimeError("owner 角色不存在")
    uname = str(username or "").strip() or "admin"
    if not _LOGIN_NAME_RE.match(uname):
        raise ValueError("用户名需 3-48 位，仅支持字母/数字/._-")
    salt_b64, hash_b64, iterations = _hash_password(password)
    user_id = create_user_record(
        username=uname,
        salt_b64=salt_b64,
        hash_b64=hash_b64,
        iterations=iterations,
        role_id=int(role["id"]),
        enabled=True,
        expires_at=None,
        policy={},
        created_by="setup",
    )
    try:
        save_credentials(uname, password, iterations=iterations)
    except Exception:
        pass
    user = get_user_by_id(user_id)
    if user is None:
        raise RuntimeError("初始化账号失败")
    return user


def authenticate_user(username: str, password: str) -> Optional[AuthUser]:
    migrate_legacy_credentials_if_needed()
    uname = str(username or "").strip()
    if not uname:
        return None
    rec = get_user_auth_record_by_username(uname)
    if not rec:
        return None
    if not _is_user_record_active(rec):
        return None
    ok = _verify_password(
        password=str(password or ""),
        salt_b64=str(rec.get("salt_b64") or ""),
        hash_b64=str(rec.get("hash_b64") or ""),
        iterations=int(rec.get("iterations") or DEFAULT_PBKDF2_ITERATIONS),
    )
    if not ok:
        return None
    try:
        touch_user_login(int(rec.get("id") or 0))
    except Exception:
        pass
    return _auth_user_from_record(rec)


def verify_login(username: str, password: str) -> bool:
    return authenticate_user(username, password) is not None


def get_user_by_username(username: str) -> Optional[AuthUser]:
    migrate_legacy_credentials_if_needed()
    rec = get_user_auth_record_by_username(username)
    if not rec:
        return None
    if not _is_user_record_active(rec):
        return None
    return _auth_user_from_record(rec)


def get_user_by_id(user_id: int) -> Optional[AuthUser]:
    migrate_legacy_credentials_if_needed()
    rec = get_user_auth_record_by_id(int(user_id))
    if not rec:
        return None
    if not _is_user_record_active(rec):
        return None
    return _auth_user_from_record(rec)


def get_session_user(session_data: Dict[str, Any]) -> Optional[AuthUser]:
    if not isinstance(session_data, dict):
        return None
    try:
        user_id = int(session_data.get("user_id") or 0)
    except Exception:
        user_id = 0
    if user_id > 0:
        user = get_user_by_id(user_id)
        if user:
            return user
    username = str(session_data.get("user") or "").strip()
    if username:
        return get_user_by_username(username)
    return None


def has_permission(user: Optional[AuthUser], permission: str) -> bool:
    if user is None:
        return False
    perm = str(permission or "").strip()
    if not perm:
        return True
    granted = user.permissions
    if "*" in granted:
        return True
    if perm in granted:
        return True
    for g in granted:
        if g.endswith(".*") and perm.startswith(g[:-1]):
            return True
    return False


def _coerce_auth_user(user_or_username: Any) -> Optional[AuthUser]:
    if isinstance(user_or_username, AuthUser):
        return user_or_username
    if isinstance(user_or_username, str):
        name = str(user_or_username or "").strip()
        if not name:
            return None
        return get_user_by_username(name)
    return None


def get_allowed_node_ids_set(user_or_username: Any) -> Optional[set[int]]:
    user = _coerce_auth_user(user_or_username)
    if user is None:
        return set()
    if has_permission(user, "*"):
        return None
    policy = normalize_user_policy(user.policy)
    raw_ids = policy.get("allowed_node_ids")
    if not isinstance(raw_ids, list) or not raw_ids:
        return None
    allowed: set[int] = set()
    for x in raw_ids:
        try:
            nid = int(x)
        except Exception:
            continue
        if nid > 0:
            allowed.add(nid)
    return allowed


def filter_nodes_for_user(user_or_username: Any, nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    allowed = get_allowed_node_ids_set(user_or_username)
    if allowed is None:
        return list(nodes or [])
    out: List[Dict[str, Any]] = []
    for n in (nodes or []):
        try:
            nid = int((n or {}).get("id") or 0)
        except Exception:
            nid = 0
        if nid > 0 and nid in allowed:
            out.append(n)
    return out


def filter_node_ids_for_user(user_or_username: Any, node_ids: List[int]) -> List[int]:
    allowed = get_allowed_node_ids_set(user_or_username)
    out: List[int] = []
    seen: set[int] = set()
    for x in (node_ids or []):
        try:
            nid = int(x)
        except Exception:
            continue
        if nid <= 0 or nid in seen:
            continue
        if allowed is not None and nid not in allowed:
            continue
        seen.add(nid)
        out.append(nid)
    return out


def can_access_node(user_or_username: Any, node_id: int) -> bool:
    try:
        nid = int(node_id or 0)
    except Exception:
        return False
    if nid <= 0:
        return False
    allowed = get_allowed_node_ids_set(user_or_username)
    if allowed is None:
        return True
    return nid in allowed


def is_rule_owner_scoped(user_or_username: Any) -> bool:
    """Whether this user should be restricted to own-created rules only."""
    user = _coerce_auth_user(user_or_username)
    if user is None:
        return False
    # Privileged roles can operate/inspect all rules.
    if has_permission(user, "*"):
        return False
    if has_permission(user, "users.manage"):
        return False
    if has_permission(user, "nodes.write"):
        return False
    return True


def can_access_rule_endpoint(user_or_username: Any, endpoint: Any) -> bool:
    """Check if endpoint is visible/editable for this user under owner-scope rules."""
    user = _coerce_auth_user(user_or_username)
    if user is None:
        return False
    if not is_rule_owner_scoped(user):
        return True
    if not isinstance(endpoint, dict):
        return False

    ex = endpoint.get("extra_config")
    if not isinstance(ex, dict):
        ex = {}

    owner_id = 0
    try:
        owner_id = int(ex.get("owner_user_id") or 0)
    except Exception:
        owner_id = 0
    if owner_id > 0 and owner_id == int(user.id):
        return True

    owner_username = str(ex.get("owner_username") or "").strip()
    if owner_username and owner_username.lower() == str(user.username or "").strip().lower():
        return True

    return False


def stamp_endpoint_owner(endpoint: Any, user_or_username: Any) -> None:
    """Set endpoint owner metadata in extra_config (in-place, best-effort)."""
    user = _coerce_auth_user(user_or_username)
    if user is None or not isinstance(endpoint, dict):
        return
    ex = endpoint.get("extra_config")
    if not isinstance(ex, dict):
        ex = {}
    ex["owner_user_id"] = int(user.id)
    ex["owner_username"] = str(user.username or "").strip()
    endpoint["extra_config"] = ex


def get_monthly_traffic_used_bytes(user: AuthUser, node_ids: Optional[List[int]] = None) -> int:
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    since_ms = now_ms - (30 * 24 * 3600 * 1000)
    # Sub-account usage should follow owned rules history, not whole-machine totals.
    try:
        if int(user.id or 0) > 0 and is_rule_owner_scoped(user):
            return int(sum_user_rule_traffic_bytes(user_id=int(user.id), node_ids=node_ids, since_ts_ms=since_ms))
    except Exception:
        pass
    if node_ids is not None:
        return int(sum_rule_traffic_bytes(node_ids=node_ids, since_ts_ms=since_ms))
    allowed_nodes = user.policy.get("allowed_node_ids")
    if isinstance(allowed_nodes, list) and allowed_nodes:
        return int(sum_rule_traffic_bytes(node_ids=allowed_nodes, since_ts_ms=since_ms))
    return int(sum_rule_traffic_bytes(node_ids=None, since_ts_ms=since_ms))


def check_tunnel_access(
    username: str,
    tunnel_type: str,
    action: str,
    sender_node_id: int,
    receiver_node_id: int,
) -> Tuple[bool, str, Dict[str, Any]]:
    user = get_user_by_username(username)
    if user is None:
        return False, "用户会话无效", {"code": "invalid_user"}
    kind = _normalize_tunnel_type_name(tunnel_type)
    op = str(action or "").strip().lower()
    if kind not in _ALLOWED_TUNNEL_TYPES:
        return False, "不支持的转发方式", {"code": "invalid_tunnel_type"}
    req_perms = ["publish.apply"]
    if kind != "direct":
        req_perms.append(f"sync.{kind}")
    if kind != "direct" and op == "delete":
        req_perms.append("sync.delete")
    missing = [p for p in req_perms if not has_permission(user, p)]
    if missing:
        return False, "当前账号没有该转发操作权限", {"code": "permission_denied", "missing": missing}

    policy = normalize_user_policy(user.policy)
    tunnel_limit_enabled = bool(policy.get("tunnel_limit_enabled"))
    allowed_tunnels = policy.get("allowed_tunnel_types") or []
    if not isinstance(allowed_tunnels, list):
        allowed_tunnels = []
    if tunnel_limit_enabled and kind not in allowed_tunnels:
        return (
            False,
            "该子账户不允许使用此转发方式",
            {
                "code": "tunnel_type_forbidden",
                "allowed_tunnel_types": allowed_tunnels,
                "tunnel_limit_enabled": bool(tunnel_limit_enabled),
            },
        )

    allowed_nodes = policy.get("allowed_node_ids") or []
    if isinstance(allowed_nodes, list) and allowed_nodes:
        if int(sender_node_id) not in allowed_nodes or int(receiver_node_id) not in allowed_nodes:
            return (
                False,
                "该子账户无权使用指定机器",
                {"code": "node_forbidden", "allowed_node_ids": allowed_nodes},
            )

    quota = int(policy.get("max_monthly_traffic_bytes") or 0)
    if quota > 0:
        if isinstance(allowed_nodes, list) and allowed_nodes:
            scope_nodes = allowed_nodes
        else:
            scope_nodes = [int(sender_node_id), int(receiver_node_id)]
        used = get_monthly_traffic_used_bytes(user, node_ids=scope_nodes)
        if used >= quota:
            return (
                False,
                "该子账户月流量额度已用尽",
                {"code": "traffic_quota_exceeded", "used_bytes": int(used), "limit_bytes": int(quota)},
            )
        return True, "", {"used_bytes": int(used), "limit_bytes": int(quota)}
    return True, "", {}


def list_roles_public() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for r in list_roles():
        out.append(
            {
                "id": int(r.get("id") or 0),
                "name": str(r.get("name") or ""),
                "description": str(r.get("description") or ""),
                "permissions": _normalize_permissions(r.get("permissions") or []),
                "builtin": bool(r.get("builtin") or False),
            }
        )
    return out


def _to_public_user(record: Dict[str, Any], include_usage: bool = True) -> Dict[str, Any]:
    policy = normalize_user_policy(record.get("policy") or {})
    max_bytes = int(policy.get("max_monthly_traffic_bytes") or 0)
    traffic_used = 0
    if include_usage and max_bytes > 0:
        try:
            scope_nodes = policy.get("allowed_node_ids")
            if not (isinstance(scope_nodes, list) and scope_nodes):
                scope_nodes = None
            traffic_used = int(
                sum_user_rule_traffic_bytes(
                    user_id=int(record.get("id") or 0),
                    node_ids=scope_nodes,
                    since_ts_ms=int(datetime.now(timezone.utc).timestamp() * 1000) - (30 * 24 * 3600 * 1000),
                )
            )
        except Exception:
            traffic_used = 0
    return {
        "id": int(record.get("id") or 0),
        "username": str(record.get("username") or ""),
        "role_id": int(record.get("role_id") or 0),
        "role_name": str(record.get("role_name") or ""),
        "enabled": bool(record.get("enabled") or 0),
        "expires_at": str(record.get("expires_at") or "").strip() or None,
        "last_login_at": str(record.get("last_login_at") or "").strip() or None,
        "created_at": str(record.get("created_at") or "").strip() or None,
        "policy": policy,
        "traffic_used_bytes_30d": int(traffic_used),
        "traffic_limit_bytes_30d": int(max_bytes),
    }


def list_users_public(include_usage: bool = True) -> List[Dict[str, Any]]:
    rows = list_users(include_disabled=True)
    return [_to_public_user(r, include_usage=include_usage) for r in rows]


def _count_enabled_owner_users() -> int:
    total = 0
    for u in list_users(include_disabled=True):
        if str(u.get("role_name") or "") == "owner" and bool(u.get("enabled") or 0):
            total += 1
    return total


def create_user_account(
    actor: str,
    username: str,
    password: str,
    role_name: str,
    enabled: bool = True,
    expires_at: Optional[str] = None,
    policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    uname = str(username or "").strip()
    if not _LOGIN_NAME_RE.match(uname):
        raise ValueError("用户名需 3-48 位，仅支持字母/数字/._-")
    if get_user_auth_record_by_username(uname):
        raise ValueError("用户名已存在")
    role = get_role_by_name(role_name)
    if not role:
        raise ValueError("角色不存在")
    salt_b64, hash_b64, iterations = _hash_password(password)
    exp = normalize_expires_at(expires_at) if expires_at else None
    if exp and is_expires_at_expired(exp):
        raise ValueError("有效期必须晚于当前时间")
    user_id = create_user_record(
        username=uname,
        salt_b64=salt_b64,
        hash_b64=hash_b64,
        iterations=iterations,
        role_id=int(role["id"]),
        enabled=bool(enabled),
        expires_at=exp,
        policy=normalize_user_policy(policy),
        created_by=str(actor or "").strip(),
    )
    rec = get_user_auth_record_by_id(user_id)
    if not rec:
        raise RuntimeError("创建用户失败")
    return _to_public_user(rec, include_usage=True)


def update_user_account(
    actor: str,
    user_id: int,
    username: Optional[str] = None,
    password: Optional[str] = None,
    role_name: Optional[str] = None,
    enabled: Optional[bool] = None,
    expires_at: Optional[str] = None,
    policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    rec = get_user_auth_record_by_id(int(user_id))
    if not rec:
        raise ValueError("用户不存在")

    role_id: Optional[int] = None
    next_role_name = str(rec.get("role_name") or "")
    if role_name is not None:
        role = get_role_by_name(role_name)
        if not role:
            raise ValueError("角色不存在")
        role_id = int(role["id"])
        next_role_name = str(role.get("name") or "")

    next_enabled = bool(rec.get("enabled") or 0) if enabled is None else bool(enabled)
    if (str(rec.get("role_name") or "") == "owner") and (not next_enabled or next_role_name != "owner"):
        if _count_enabled_owner_users() <= 1:
            raise ValueError("至少要保留一个启用状态的 owner 账号")

    uname: Optional[str] = None
    if username is not None:
        uname = str(username or "").strip()
        if not _LOGIN_NAME_RE.match(uname):
            raise ValueError("用户名需 3-48 位，仅支持字母/数字/._-")
        found = get_user_auth_record_by_username(uname)
        if found and int(found.get("id") or 0) != int(user_id):
            raise ValueError("用户名已存在")

    exp: Optional[str] = None
    if expires_at is not None:
        exp = normalize_expires_at(expires_at) if str(expires_at or "").strip() else ""
        if exp and is_expires_at_expired(exp):
            raise ValueError("有效期必须晚于当前时间")

    kwargs: Dict[str, Any] = {}
    if uname is not None:
        kwargs["username"] = uname
    if role_id is not None:
        kwargs["role_id"] = role_id
    if enabled is not None:
        kwargs["enabled"] = bool(enabled)
    if expires_at is not None:
        kwargs["expires_at"] = exp
    if policy is not None:
        kwargs["policy"] = normalize_user_policy(policy)
    if password is not None and str(password).strip():
        salt_b64, hash_b64, iterations = _hash_password(str(password))
        kwargs["salt_b64"] = salt_b64
        kwargs["hash_b64"] = hash_b64
        kwargs["iterations"] = iterations
    if kwargs:
        update_user_record(int(user_id), **kwargs)
    rec2 = get_user_auth_record_by_id(int(user_id))
    if not rec2:
        raise RuntimeError("更新用户失败")
    return _to_public_user(rec2, include_usage=True)


def delete_user_account(actor: str, user_id: int) -> None:
    rec = get_user_auth_record_by_id(int(user_id))
    if not rec:
        raise ValueError("用户不存在")
    actor_name = str(actor or "").strip()
    if actor_name and actor_name == str(rec.get("username") or "").strip():
        raise ValueError("不能删除当前登录账号")
    if str(rec.get("role_name") or "") == "owner" and bool(rec.get("enabled") or 0):
        if _count_enabled_owner_users() <= 1:
            raise ValueError("至少要保留一个启用状态的 owner 账号")
    deleted = delete_user_record(int(user_id))
    if deleted <= 0:
        raise RuntimeError("删除用户失败")
