import os
import sqlite3
import json
import hashlib
import secrets
import string
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Tuple

def ensure_parent_dir(path: str) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)


def _db_path_candidates() -> List[str]:
    out: List[str] = []
    seen: set[str] = set()

    def _add(path: Any) -> None:
        p = str(path or "").strip()
        if not p or p in seen:
            return
        seen.add(p)
        out.append(p)

    env_db = (os.getenv("REALM_PANEL_DB") or "").strip()
    if env_db:
        _add(env_db)
    else:
        _add("/etc/realm-panel/panel.db")

    runtime_dir = (os.getenv("XDG_RUNTIME_DIR") or "").strip()
    if runtime_dir:
        _add(os.path.join(runtime_dir, "realm-panel", "panel.db"))

    state_home = (os.getenv("XDG_STATE_HOME") or "").strip()
    if state_home:
        _add(os.path.join(state_home, "realm-panel", "panel.db"))

    home = os.path.expanduser("~")
    if home and home != "~":
        _add(os.path.join(home, ".local", "state", "realm-panel", "panel.db"))

    _add("/tmp/realm-panel/panel.db")
    return out


def _is_db_path_usable(path: str) -> bool:
    p = str(path or "").strip()
    if not p:
        return False
    try:
        ensure_parent_dir(p)
    except Exception:
        return False
    try:
        with sqlite3.connect(p) as conn:
            conn.execute("PRAGMA busy_timeout=1000")
        return True
    except Exception:
        return False


def _resolve_default_db_path() -> str:
    candidates = _db_path_candidates()
    for p in candidates:
        if _is_db_path_usable(p):
            return p
    # Last resort: keep process alive with a tmp path even on unusual environments.
    return "/tmp/realm-panel/panel.db"


DEFAULT_DB_PATH = _resolve_default_db_path()

SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  base_url TEXT NOT NULL,
  api_key TEXT NOT NULL,
  verify_tls INTEGER NOT NULL DEFAULT 1,
  -- Mark as "LAN-only" node (for reverse tunnel / intranet penetration)
  is_private INTEGER NOT NULL DEFAULT 0,
  group_name TEXT NOT NULL DEFAULT '默认分组',
  -- Node role and website management
  role TEXT NOT NULL DEFAULT 'normal',
  capabilities_json TEXT NOT NULL DEFAULT '{}',
  website_root_base TEXT NOT NULL DEFAULT '',
  -- Agent push-report state (agent -> panel)
  last_seen_at TEXT,
  last_report_json TEXT,
  -- Desired config stored on panel, delivered to agent on next report
  desired_pool_json TEXT,
  desired_pool_version INTEGER NOT NULL DEFAULT 0,
  agent_ack_version INTEGER NOT NULL DEFAULT 0,

  -- Rule traffic reset (panel -> agent)
  desired_traffic_reset_version INTEGER NOT NULL DEFAULT 0,
  agent_traffic_reset_ack_version INTEGER NOT NULL DEFAULT 0,
  traffic_reset_at TEXT,
  traffic_reset_msg TEXT NOT NULL DEFAULT '',

  -- Agent software update (panel -> agent)
  desired_agent_version TEXT NOT NULL DEFAULT '',
  desired_agent_update_id TEXT NOT NULL DEFAULT '',
  desired_agent_command_id TEXT NOT NULL DEFAULT '',
  agent_reported_version TEXT NOT NULL DEFAULT '',
  agent_capabilities_json TEXT NOT NULL DEFAULT '{}',
  agent_update_state TEXT NOT NULL DEFAULT '',
  agent_update_msg TEXT NOT NULL DEFAULT '',
  agent_update_reason_code TEXT NOT NULL DEFAULT '',
  agent_update_retry_count INTEGER NOT NULL DEFAULT 0,
  agent_update_max_retries INTEGER NOT NULL DEFAULT 0,
  agent_update_next_retry_at TEXT,
  agent_update_delivered_at TEXT,
  agent_update_accepted_at TEXT,
  agent_update_started_at TEXT,
  agent_update_finished_at TEXT,
  agent_update_at TEXT,

  -- Node-level auto-restart policy (panel -> agent)
  auto_restart_enabled INTEGER NOT NULL DEFAULT 1,
  auto_restart_schedule_type TEXT NOT NULL DEFAULT 'daily',
  auto_restart_interval INTEGER NOT NULL DEFAULT 1,
  auto_restart_hour INTEGER NOT NULL DEFAULT 4,
  auto_restart_minute INTEGER NOT NULL DEFAULT 8,
  auto_restart_weekdays_json TEXT NOT NULL DEFAULT '[1,2,3,4,5,6,7]',
  auto_restart_monthdays_json TEXT NOT NULL DEFAULT '[1]',
  desired_auto_restart_policy_version INTEGER NOT NULL DEFAULT 0,
  agent_auto_restart_policy_ack_version INTEGER NOT NULL DEFAULT 0,
  auto_restart_updated_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Group order metadata (pure UI sorting)
CREATE TABLE IF NOT EXISTS group_orders (
  group_name TEXT PRIMARY KEY,
  sort_order INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Website management
CREATE TABLE IF NOT EXISTS sites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  node_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  domains_json TEXT NOT NULL DEFAULT '[]',
  root_path TEXT NOT NULL DEFAULT '',
  proxy_target TEXT NOT NULL DEFAULT '',
  type TEXT NOT NULL DEFAULT 'static',
  web_server TEXT NOT NULL DEFAULT 'nginx',
  nginx_tpl TEXT NOT NULL DEFAULT '',
  https_redirect INTEGER NOT NULL DEFAULT 0,
  gzip_enabled INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'running',
  health_status TEXT NOT NULL DEFAULT '',
  health_code INTEGER NOT NULL DEFAULT 0,
  health_latency_ms INTEGER NOT NULL DEFAULT 0,
  health_error TEXT NOT NULL DEFAULT '',
  health_checked_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS site_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id INTEGER NOT NULL,
  action TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'success',
  actor TEXT NOT NULL DEFAULT '',
  payload_json TEXT NOT NULL DEFAULT '{}',
  result_json TEXT NOT NULL DEFAULT '{}',
  error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_site_events_site_ts ON site_events(site_id, created_at DESC);

CREATE TABLE IF NOT EXISTS site_checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id INTEGER NOT NULL,
  ok INTEGER NOT NULL DEFAULT 0,
  status_code INTEGER NOT NULL DEFAULT 0,
  latency_ms INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT '',
  checked_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_site_checks_site_ts ON site_checks(site_id, checked_at DESC);

CREATE TABLE IF NOT EXISTS site_file_share_revocations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id INTEGER NOT NULL,
  token_sha256 TEXT NOT NULL,
  revoked_by TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  revoked_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(site_id, token_sha256)
);
CREATE INDEX IF NOT EXISTS idx_site_file_share_revocations_site_ts ON site_file_share_revocations(site_id, revoked_at DESC);

CREATE TABLE IF NOT EXISTS site_file_share_short_links (
  code TEXT PRIMARY KEY,
  site_id INTEGER NOT NULL,
  token TEXT NOT NULL,
  token_sha256 TEXT NOT NULL,
  created_by TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_site_file_share_short_links_site_ts ON site_file_share_short_links(site_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_site_file_share_short_links_token ON site_file_share_short_links(token_sha256);

CREATE TABLE IF NOT EXISTS site_file_favorites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id INTEGER NOT NULL,
  owner TEXT NOT NULL DEFAULT '',
  path TEXT NOT NULL,
  is_dir INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(site_id, owner, path)
);
CREATE INDEX IF NOT EXISTS idx_site_file_favorites_owner_updated ON site_file_favorites(owner, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_site_file_favorites_site_owner ON site_file_favorites(site_id, owner, updated_at DESC);

CREATE TABLE IF NOT EXISTS certificates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  node_id INTEGER NOT NULL,
  site_id INTEGER,
  domains_json TEXT NOT NULL DEFAULT '[]',
  issuer TEXT NOT NULL DEFAULT 'letsencrypt',
  challenge TEXT NOT NULL DEFAULT 'http-01',
  status TEXT NOT NULL DEFAULT 'pending',
  not_before TEXT,
  not_after TEXT,
  renew_at TEXT,
  last_error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  node_id INTEGER NOT NULL,
  type TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'queued',
  progress INTEGER NOT NULL DEFAULT 0,
  result_json TEXT NOT NULL DEFAULT '{}',
  error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS netmon_monitors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'ping',
  tcp_port INTEGER NOT NULL DEFAULT 443,
  interval_sec INTEGER NOT NULL DEFAULT 5,
  warn_ms INTEGER NOT NULL DEFAULT 0,
  crit_ms INTEGER NOT NULL DEFAULT 0,
  node_ids_json TEXT NOT NULL DEFAULT '[]',
  enabled INTEGER NOT NULL DEFAULT 1,
  last_run_ts_ms INTEGER NOT NULL DEFAULT 0,
  last_run_msg TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS netmon_samples (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  monitor_id INTEGER NOT NULL,
  node_id INTEGER NOT NULL,
  ts_ms INTEGER NOT NULL,
  ok INTEGER NOT NULL DEFAULT 0,
  latency_ms REAL,
  error TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_netmon_samples_monitor_ts ON netmon_samples(monitor_id, ts_ms);
CREATE INDEX IF NOT EXISTS idx_netmon_samples_monitor_node_ts ON netmon_samples(monitor_id, node_id, ts_ms);

-- Rule traffic/connection history (persistent time-series)
CREATE TABLE IF NOT EXISTS rule_stats_samples (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  node_id INTEGER NOT NULL,
  rule_key TEXT NOT NULL,
  ts_ms INTEGER NOT NULL,
  rx_bytes INTEGER NOT NULL DEFAULT 0,
  tx_bytes INTEGER NOT NULL DEFAULT 0,
  connections_active INTEGER NOT NULL DEFAULT 0,
  connections_total INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_rule_stats_samples_unique ON rule_stats_samples(node_id, rule_key, ts_ms);
CREATE INDEX IF NOT EXISTS idx_rule_stats_samples_node_ts ON rule_stats_samples(node_id, ts_ms);
CREATE INDEX IF NOT EXISTS idx_rule_stats_samples_node_rule_ts ON rule_stats_samples(node_id, rule_key, ts_ms);

-- Rule ownership mapping (for per-subaccount traffic accounting)
CREATE TABLE IF NOT EXISTS rule_owner_map (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  node_id INTEGER NOT NULL,
  rule_key TEXT NOT NULL,
  owner_user_id INTEGER NOT NULL DEFAULT 0,
  owner_username TEXT NOT NULL DEFAULT '',
  first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
  active INTEGER NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_rule_owner_map_unique ON rule_owner_map(node_id, rule_key);
CREATE INDEX IF NOT EXISTS idx_rule_owner_map_owner ON rule_owner_map(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_rule_owner_map_node_owner ON rule_owner_map(node_id, owner_user_id);

-- Auth / RBAC
CREATE TABLE IF NOT EXISTS roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  permissions_json TEXT NOT NULL DEFAULT '[]',
  builtin INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  salt_b64 TEXT NOT NULL,
  hash_b64 TEXT NOT NULL,
  iterations INTEGER NOT NULL DEFAULT 120000,
  role_id INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  expires_at TEXT,
  policy_json TEXT NOT NULL DEFAULT '{}',
  last_login_at TEXT,
  created_by TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(role_id) REFERENCES roles(id)
);
CREATE INDEX IF NOT EXISTS idx_users_role_id ON users(role_id);
CREATE INDEX IF NOT EXISTS idx_users_enabled ON users(enabled);

CREATE TABLE IF NOT EXISTS user_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_sha256 TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL DEFAULT '',
  scopes_json TEXT NOT NULL DEFAULT '[]',
  expires_at TEXT,
  last_used_at TEXT,
  created_by TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_user_tokens_user_id ON user_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_user_tokens_expires_at ON user_tokens(expires_at);

-- Panel runtime settings (editable in UI, not only env vars)
CREATE TABLE IF NOT EXISTS panel_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

BUILTIN_ROLE_DEFS: Dict[str, Dict[str, Any]] = {
    "owner": {
        "description": "系统所有者（全部权限）",
        "permissions": ["*"],
        "builtin": 1,
    },
    "admin": {
        "description": "管理员（不含用户/角色管理）",
        "permissions": [
            "panel.view",
            "nodes.*",
            "publish.apply",
            "groups.write",
            "sync.*",
            "websites.*",
            "cert.manage",
            "files.*",
            "netmon.*",
            "agents.*",
            "backup.manage",
            "restore.manage",
        ],
        "builtin": 1,
    },
    "operator": {
        "description": "运维（节点/发布/网站管理）",
        "permissions": [
            "panel.view",
            "nodes.read",
            "nodes.write",
            "publish.apply",
            "sync.*",
            "websites.*",
            "cert.manage",
            "files.*",
            "netmon.*",
            "agents.read",
            "backup.manage",
        ],
        "builtin": 1,
    },
    "forwarder": {
        "description": "转发操作员（仅转发与发布）",
        "permissions": [
            "panel.view",
            "nodes.read",
            "publish.apply",
            "sync.wss",
            "sync.intranet",
            "sync.delete",
            "sync.job.read",
        ],
        "builtin": 1,
    },
    "viewer": {
        "description": "只读观察员",
        "permissions": [
            "panel.view",
            "nodes.read",
            "websites.read",
            "files.read",
            "netmon.read",
            "agents.read",
            "sync.job.read",
        ],
        "builtin": 1,
    },
}


def _normalize_permissions(perms: Any) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    seq = perms if isinstance(perms, list) else []
    for p in seq:
        name = str(p or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    ensure_parent_dir(db_path)
    with sqlite3.connect(db_path) as conn:
        # Improve concurrent read/write (background collectors, UI requests).
        # Best effort: ignore if the underlying SQLite build/filesystem doesn't support it.
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except Exception:
            pass
        try:
            conn.execute("PRAGMA synchronous=NORMAL")
        except Exception:
            pass
        try:
            conn.execute("PRAGMA busy_timeout=5000")
        except Exception:
            pass
        conn.executescript(SCHEMA)
        conn.commit()


def ensure_db(db_path: str = DEFAULT_DB_PATH) -> None:
    init_db(db_path)
    with connect(db_path) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(nodes)").fetchall()}
        if "verify_tls" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN verify_tls INTEGER NOT NULL DEFAULT 1")
        if "is_private" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN is_private INTEGER NOT NULL DEFAULT 0")
        if "group_name" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN group_name TEXT NOT NULL DEFAULT '默认分组'")
        if "role" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN role TEXT NOT NULL DEFAULT 'normal'")
        if "capabilities_json" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN capabilities_json TEXT NOT NULL DEFAULT '{}'")
        if "website_root_base" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN website_root_base TEXT NOT NULL DEFAULT ''")
        if "last_seen_at" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN last_seen_at TEXT")
        if "last_report_json" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN last_report_json TEXT")
        if "desired_pool_json" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN desired_pool_json TEXT")
        if "desired_pool_version" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN desired_pool_version INTEGER NOT NULL DEFAULT 0")
        if "agent_ack_version" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN agent_ack_version INTEGER NOT NULL DEFAULT 0")

        # Traffic reset related columns (panel -> agent)
        if "desired_traffic_reset_version" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN desired_traffic_reset_version INTEGER NOT NULL DEFAULT 0")
        if "agent_traffic_reset_ack_version" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN agent_traffic_reset_ack_version INTEGER NOT NULL DEFAULT 0")
        if "traffic_reset_at" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN traffic_reset_at TEXT")
        if "traffic_reset_msg" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN traffic_reset_msg TEXT NOT NULL DEFAULT ''")

        # Agent update related columns
        if "desired_agent_version" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN desired_agent_version TEXT NOT NULL DEFAULT ''")
        if "desired_agent_update_id" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN desired_agent_update_id TEXT NOT NULL DEFAULT ''")
        if "desired_agent_command_id" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN desired_agent_command_id TEXT NOT NULL DEFAULT ''")
        if "agent_reported_version" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN agent_reported_version TEXT NOT NULL DEFAULT ''")
        if "agent_capabilities_json" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN agent_capabilities_json TEXT NOT NULL DEFAULT '{}'")
        if "agent_update_state" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN agent_update_state TEXT NOT NULL DEFAULT ''")
        if "agent_update_msg" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN agent_update_msg TEXT NOT NULL DEFAULT ''")
        if "agent_update_reason_code" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN agent_update_reason_code TEXT NOT NULL DEFAULT ''")
        if "agent_update_retry_count" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN agent_update_retry_count INTEGER NOT NULL DEFAULT 0")
        if "agent_update_max_retries" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN agent_update_max_retries INTEGER NOT NULL DEFAULT 0")
        if "agent_update_next_retry_at" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN agent_update_next_retry_at TEXT")
        if "agent_update_delivered_at" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN agent_update_delivered_at TEXT")
        if "agent_update_accepted_at" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN agent_update_accepted_at TEXT")
        if "agent_update_started_at" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN agent_update_started_at TEXT")
        if "agent_update_finished_at" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN agent_update_finished_at TEXT")
        if "agent_update_at" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN agent_update_at TEXT")
        if "auto_restart_enabled" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN auto_restart_enabled INTEGER NOT NULL DEFAULT 1")
        if "auto_restart_schedule_type" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN auto_restart_schedule_type TEXT NOT NULL DEFAULT 'daily'")
        if "auto_restart_interval" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN auto_restart_interval INTEGER NOT NULL DEFAULT 1")
        if "auto_restart_hour" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN auto_restart_hour INTEGER NOT NULL DEFAULT 4")
        if "auto_restart_minute" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN auto_restart_minute INTEGER NOT NULL DEFAULT 8")
        if "auto_restart_weekdays_json" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN auto_restart_weekdays_json TEXT NOT NULL DEFAULT '[1,2,3,4,5,6,7]'")
        if "auto_restart_monthdays_json" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN auto_restart_monthdays_json TEXT NOT NULL DEFAULT '[1]'")
        if "desired_auto_restart_policy_version" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN desired_auto_restart_policy_version INTEGER NOT NULL DEFAULT 0")
        if "agent_auto_restart_policy_ack_version" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN agent_auto_restart_policy_ack_version INTEGER NOT NULL DEFAULT 0")
        if "auto_restart_updated_at" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN auto_restart_updated_at TEXT")


        # NetMon tables migrations (older DBs may miss columns)
        try:
            mcols = {row[1] for row in conn.execute("PRAGMA table_info(netmon_monitors)").fetchall()}
            if mcols:
                if "tcp_port" not in mcols:
                    conn.execute("ALTER TABLE netmon_monitors ADD COLUMN tcp_port INTEGER NOT NULL DEFAULT 443")
                if "interval_sec" not in mcols:
                    conn.execute("ALTER TABLE netmon_monitors ADD COLUMN interval_sec INTEGER NOT NULL DEFAULT 5")
                if "warn_ms" not in mcols:
                    conn.execute("ALTER TABLE netmon_monitors ADD COLUMN warn_ms INTEGER NOT NULL DEFAULT 0")
                if "crit_ms" not in mcols:
                    conn.execute("ALTER TABLE netmon_monitors ADD COLUMN crit_ms INTEGER NOT NULL DEFAULT 0")
                if "node_ids_json" not in mcols:
                    conn.execute("ALTER TABLE netmon_monitors ADD COLUMN node_ids_json TEXT NOT NULL DEFAULT '[]'")
                if "enabled" not in mcols:
                    conn.execute("ALTER TABLE netmon_monitors ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")
                if "last_run_ts_ms" not in mcols:
                    conn.execute("ALTER TABLE netmon_monitors ADD COLUMN last_run_ts_ms INTEGER NOT NULL DEFAULT 0")
                if "last_run_msg" not in mcols:
                    conn.execute("ALTER TABLE netmon_monitors ADD COLUMN last_run_msg TEXT NOT NULL DEFAULT ''")
        except Exception:
            pass

        # Website tables migrations
        try:
            scols = {row[1] for row in conn.execute("PRAGMA table_info(sites)").fetchall()}
            if scols:
                if "proxy_target" not in scols:
                    conn.execute("ALTER TABLE sites ADD COLUMN proxy_target TEXT NOT NULL DEFAULT ''")
                if "nginx_tpl" not in scols:
                    conn.execute("ALTER TABLE sites ADD COLUMN nginx_tpl TEXT NOT NULL DEFAULT ''")
                if "https_redirect" not in scols:
                    conn.execute("ALTER TABLE sites ADD COLUMN https_redirect INTEGER NOT NULL DEFAULT 0")
                if "gzip_enabled" not in scols:
                    conn.execute("ALTER TABLE sites ADD COLUMN gzip_enabled INTEGER NOT NULL DEFAULT 1")
                if "health_status" not in scols:
                    conn.execute("ALTER TABLE sites ADD COLUMN health_status TEXT NOT NULL DEFAULT ''")
                if "health_code" not in scols:
                    conn.execute("ALTER TABLE sites ADD COLUMN health_code INTEGER NOT NULL DEFAULT 0")
                if "health_latency_ms" not in scols:
                    conn.execute("ALTER TABLE sites ADD COLUMN health_latency_ms INTEGER NOT NULL DEFAULT 0")
                if "health_error" not in scols:
                    conn.execute("ALTER TABLE sites ADD COLUMN health_error TEXT NOT NULL DEFAULT ''")
                if "health_checked_at" not in scols:
                    conn.execute("ALTER TABLE sites ADD COLUMN health_checked_at TEXT")
        except Exception:
            pass

        # Site events / checks tables
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS site_events ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "site_id INTEGER NOT NULL,"
                "action TEXT NOT NULL,"
                "status TEXT NOT NULL DEFAULT 'success',"
                "actor TEXT NOT NULL DEFAULT '',"
                "payload_json TEXT NOT NULL DEFAULT '{}',"
                "result_json TEXT NOT NULL DEFAULT '{}',"
                "error TEXT NOT NULL DEFAULT '',"
                "created_at TEXT NOT NULL DEFAULT (datetime('now'))"
                ")"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_site_events_site_ts ON site_events(site_id, created_at DESC)")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS site_checks ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "site_id INTEGER NOT NULL,"
                "ok INTEGER NOT NULL DEFAULT 0,"
                "status_code INTEGER NOT NULL DEFAULT 0,"
                "latency_ms INTEGER NOT NULL DEFAULT 0,"
                "error TEXT NOT NULL DEFAULT '',"
                "checked_at TEXT NOT NULL DEFAULT (datetime('now'))"
                ")"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_site_checks_site_ts ON site_checks(site_id, checked_at DESC)")
        except Exception:
            pass
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS site_file_favorites ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "site_id INTEGER NOT NULL,"
                "owner TEXT NOT NULL DEFAULT '',"
                "path TEXT NOT NULL,"
                "is_dir INTEGER NOT NULL DEFAULT 0,"
                "created_at TEXT NOT NULL DEFAULT (datetime('now')),"
                "updated_at TEXT NOT NULL DEFAULT (datetime('now')),"
                "UNIQUE(site_id, owner, path)"
                ")"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_site_file_favorites_owner_updated "
                "ON site_file_favorites(owner, updated_at DESC)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_site_file_favorites_site_owner "
                "ON site_file_favorites(site_id, owner, updated_at DESC)"
            )
            fcols = {row[1] for row in conn.execute("PRAGMA table_info(site_file_favorites)").fetchall()}
            if fcols:
                if "is_dir" not in fcols:
                    conn.execute("ALTER TABLE site_file_favorites ADD COLUMN is_dir INTEGER NOT NULL DEFAULT 0")
                if "updated_at" not in fcols:
                    conn.execute("ALTER TABLE site_file_favorites ADD COLUMN updated_at TEXT")
        except Exception:
            pass

        # NetMon indexes (best effort)
        try:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_netmon_samples_monitor_ts ON netmon_samples(monitor_id, ts_ms)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_netmon_samples_monitor_node_ts ON netmon_samples(monitor_id, node_id, ts_ms)")
        except Exception:
            pass

        # Rule stats history indexes (best effort)
        try:
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_rule_stats_samples_unique ON rule_stats_samples(node_id, rule_key, ts_ms)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_rule_stats_samples_node_ts ON rule_stats_samples(node_id, ts_ms)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_rule_stats_samples_node_rule_ts ON rule_stats_samples(node_id, rule_key, ts_ms)"
            )
        except Exception:
            pass
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS rule_owner_map ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "node_id INTEGER NOT NULL,"
                "rule_key TEXT NOT NULL,"
                "owner_user_id INTEGER NOT NULL DEFAULT 0,"
                "owner_username TEXT NOT NULL DEFAULT '',"
                "first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),"
                "last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),"
                "active INTEGER NOT NULL DEFAULT 1"
                ")"
            )
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_rule_owner_map_unique ON rule_owner_map(node_id, rule_key)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rule_owner_map_owner ON rule_owner_map(owner_user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rule_owner_map_node_owner ON rule_owner_map(node_id, owner_user_id)")
        except Exception:
            pass

        # Auth/RBAC tables migrations
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS roles ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "name TEXT NOT NULL UNIQUE,"
                "description TEXT NOT NULL DEFAULT '',"
                "permissions_json TEXT NOT NULL DEFAULT '[]',"
                "builtin INTEGER NOT NULL DEFAULT 0,"
                "created_at TEXT NOT NULL DEFAULT (datetime('now')),"
                "updated_at TEXT NOT NULL DEFAULT (datetime('now'))"
                ")"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name)")
        except Exception:
            pass
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS users ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "username TEXT NOT NULL UNIQUE,"
                "salt_b64 TEXT NOT NULL,"
                "hash_b64 TEXT NOT NULL,"
                "iterations INTEGER NOT NULL DEFAULT 120000,"
                "role_id INTEGER NOT NULL,"
                "enabled INTEGER NOT NULL DEFAULT 1,"
                "expires_at TEXT,"
                "policy_json TEXT NOT NULL DEFAULT '{}',"
                "last_login_at TEXT,"
                "created_by TEXT NOT NULL DEFAULT '',"
                "created_at TEXT NOT NULL DEFAULT (datetime('now')),"
                "updated_at TEXT NOT NULL DEFAULT (datetime('now')),"
                "FOREIGN KEY(role_id) REFERENCES roles(id)"
                ")"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_role_id ON users(role_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_enabled ON users(enabled)")
            ucols = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
            if ucols:
                if "policy_json" not in ucols:
                    conn.execute("ALTER TABLE users ADD COLUMN policy_json TEXT NOT NULL DEFAULT '{}'")
                if "expires_at" not in ucols:
                    conn.execute("ALTER TABLE users ADD COLUMN expires_at TEXT")
                if "enabled" not in ucols:
                    conn.execute("ALTER TABLE users ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")
                if "last_login_at" not in ucols:
                    conn.execute("ALTER TABLE users ADD COLUMN last_login_at TEXT")
        except Exception:
            pass
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS user_tokens ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "user_id INTEGER NOT NULL,"
                "token_sha256 TEXT NOT NULL UNIQUE,"
                "name TEXT NOT NULL DEFAULT '',"
                "scopes_json TEXT NOT NULL DEFAULT '[]',"
                "expires_at TEXT,"
                "last_used_at TEXT,"
                "created_by TEXT NOT NULL DEFAULT '',"
                "created_at TEXT NOT NULL DEFAULT (datetime('now')),"
                "revoked_at TEXT,"
                "FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE"
                ")"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_user_tokens_user_id ON user_tokens(user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_user_tokens_expires_at ON user_tokens(expires_at)")
        except Exception:
            pass
        try:
            _ensure_builtin_roles_conn(conn)
        except Exception:
            pass
        conn.commit()


def set_agent_rollout_all(
    desired_version: str,
    update_id: str,
    state: str = "queued",
    msg: str = "",
    max_retries: int = 4,
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    """Set desired agent version for all nodes, returns affected row count."""
    ver = (desired_version or "").strip()
    uid = (update_id or "").strip()
    st = (state or "").strip()
    m = (msg or "").strip()
    retries = max(1, int(max_retries or 1))
    with connect(db_path) as conn:
        cur = conn.execute(
            "UPDATE nodes SET "
            "desired_agent_version=?, desired_agent_update_id=?, desired_agent_command_id='', "
            "agent_update_state=?, agent_update_msg=?, agent_update_reason_code='', "
            "agent_update_retry_count=0, agent_update_max_retries=?, agent_update_next_retry_at=NULL, "
            "agent_update_delivered_at=NULL, agent_update_accepted_at=NULL, agent_update_started_at=NULL, "
            "agent_update_finished_at=NULL, agent_update_at=datetime('now')",
            (ver, uid, st, m, retries),
        )
        conn.commit()
        return int(cur.rowcount or 0)


def update_agent_status(
    node_id: int,
    agent_reported_version: Optional[str] = None,
    state: Optional[str] = None,
    msg: Optional[str] = None,
    reason_code: Optional[str] = None,
    extra_updates: Optional[Dict[str, Any]] = None,
    touch_update_at: Optional[bool] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> None:
    fields: List[str] = []
    vals: List[Any] = []
    if agent_reported_version is not None:
        fields.append("agent_reported_version=?")
        vals.append(str(agent_reported_version))
    if state is not None:
        fields.append("agent_update_state=?")
        vals.append(str(state))
    if msg is not None:
        fields.append("agent_update_msg=?")
        vals.append(str(msg))
    if reason_code is not None:
        fields.append("agent_update_reason_code=?")
        vals.append(str(reason_code))

    if isinstance(extra_updates, dict):
        _allowed_extra = {
            "desired_agent_command_id",
            "agent_capabilities_json",
            "agent_update_retry_count",
            "agent_update_max_retries",
            "agent_update_next_retry_at",
            "agent_update_delivered_at",
            "agent_update_accepted_at",
            "agent_update_started_at",
            "agent_update_finished_at",
        }
        for k, v in extra_updates.items():
            col = str(k or "").strip()
            if not col:
                continue
            if col not in _allowed_extra:
                raise ValueError(f"invalid extra update column: {col}")
            fields.append(f"{col}=?")
            vals.append(v)

    if touch_update_at is None:
        touch_update_at = bool(state is not None or msg is not None or reason_code is not None)
    if touch_update_at:
        fields.append("agent_update_at=datetime('now')")

    if not fields:
        return
    vals.append(int(node_id))
    with connect(db_path) as conn:
        # Whitelist validation to avoid accidental SQL injection if this code is modified.
        _allowed = {
            "agent_reported_version",
            "agent_update_state",
            "agent_update_msg",
            "agent_update_reason_code",
            "agent_update_retry_count",
            "agent_update_max_retries",
            "agent_update_next_retry_at",
            "agent_update_delivered_at",
            "agent_update_accepted_at",
            "agent_update_started_at",
            "agent_update_finished_at",
            "desired_agent_command_id",
            "agent_capabilities_json",
            "agent_update_at",
        }
        for _f in fields:
            _col = str(_f).split('=', 1)[0].strip()
            if _col not in _allowed:
                raise ValueError(f"invalid update column: {_col}")
        conn.execute(f"UPDATE nodes SET {', '.join(fields)} WHERE id=?", tuple(vals))
        conn.commit()


def update_node_report(
    node_id: int,
    report_json: str,
    last_seen_at: str,
    agent_ack_version: Optional[int] = None,
    traffic_ack_version: Optional[int] = None,
    auto_restart_ack_version: Optional[int] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> None:
    """Persist last report from an agent (push mode)."""
    with connect(db_path) as conn:
        fields = ['last_seen_at=?', 'last_report_json=?']
        vals = [last_seen_at, report_json]

        if agent_ack_version is not None:
            fields.append('agent_ack_version=?')
            vals.append(int(agent_ack_version))

        if traffic_ack_version is not None:
            fields.append('agent_traffic_reset_ack_version=?')
            vals.append(int(traffic_ack_version))

        if auto_restart_ack_version is not None:
            fields.append('agent_auto_restart_policy_ack_version=?')
            vals.append(int(auto_restart_ack_version))

        vals.append(int(node_id))
        conn.execute(
            f"UPDATE nodes SET {', '.join(fields)} WHERE id=?",
            tuple(vals),
        )
        conn.commit()


def get_last_report(node_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    with connect(db_path) as conn:
        row = conn.execute("SELECT last_report_json FROM nodes WHERE id=?", (int(node_id),)).fetchone()
    if not row:
        return None
    raw = row["last_report_json"]
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def set_node_auto_restart_policy(
    node_id: int,
    *,
    enabled: bool,
    schedule_type: str,
    interval: int,
    hour: int,
    minute: int,
    weekdays: List[int],
    monthdays: List[int],
    db_path: str = DEFAULT_DB_PATH,
) -> Tuple[int, Dict[str, Any]]:
    st = str(schedule_type or "daily").strip().lower()
    if st not in ("daily", "weekly", "monthly"):
        st = "daily"
    itv = int(interval or 1)
    if itv < 1:
        itv = 1
    if itv > 365:
        itv = 365
    hh = int(hour or 0)
    if hh < 0:
        hh = 0
    if hh > 23:
        hh = 23
    mm = int(minute or 0)
    if mm < 0:
        mm = 0
    if mm > 59:
        mm = 59
    wds = _norm_int_seq(weekdays, 1, 7)
    if not wds:
        wds = [1, 2, 3, 4, 5, 6, 7]
    mds = _norm_int_seq(monthdays, 1, 31)
    if not mds:
        mds = [1]
    wj = json.dumps(wds, ensure_ascii=False, separators=(",", ":"))
    mj = json.dumps(mds, ensure_ascii=False, separators=(",", ":"))

    with connect(db_path) as conn:
        try:
            row = conn.execute(
                "UPDATE nodes SET "
                "auto_restart_enabled=?, auto_restart_schedule_type=?, auto_restart_interval=?, "
                "auto_restart_hour=?, auto_restart_minute=?, "
                "auto_restart_weekdays_json=?, auto_restart_monthdays_json=?, "
                "desired_auto_restart_policy_version=desired_auto_restart_policy_version+1, "
                "auto_restart_updated_at=datetime('now') "
                "WHERE id=? RETURNING desired_auto_restart_policy_version",
                (1 if enabled else 0, st, itv, hh, mm, wj, mj, int(node_id)),
            ).fetchone()
            conn.commit()
            new_ver = int(row[0]) if row else 0
        except sqlite3.OperationalError:
            try:
                conn.execute("BEGIN IMMEDIATE")
            except Exception:
                pass
            row2 = conn.execute(
                "SELECT desired_auto_restart_policy_version FROM nodes WHERE id=?",
                (int(node_id),),
            ).fetchone()
            cur_ver = int(row2[0]) if row2 else 0
            new_ver = cur_ver + 1
            conn.execute(
                "UPDATE nodes SET "
                "auto_restart_enabled=?, auto_restart_schedule_type=?, auto_restart_interval=?, "
                "auto_restart_hour=?, auto_restart_minute=?, "
                "auto_restart_weekdays_json=?, auto_restart_monthdays_json=?, "
                "desired_auto_restart_policy_version=?, "
                "auto_restart_updated_at=datetime('now') "
                "WHERE id=?",
                (1 if enabled else 0, st, itv, hh, mm, wj, mj, new_ver, int(node_id)),
            )
            conn.commit()

    policy = {
        "enabled": bool(enabled),
        "schedule_type": st,
        "interval": int(itv),
        "hour": int(hh),
        "minute": int(mm),
        "weekdays": list(wds),
        "monthdays": list(mds),
        "version": int(new_ver),
    }
    return int(new_ver), policy


def set_desired_pool(
    node_id: int,
    pool: Dict[str, Any],
    db_path: str = DEFAULT_DB_PATH,
) -> Tuple[int, Dict[str, Any]]:
    """Set desired pool and bump version. Returns (new_version, pool).

    IMPORTANT: desired_pool_version must be bumped atomically.
    Old implementation (SELECT then UPDATE) can lose updates under concurrent requests.

    We prefer SQLite RETURNING (>=3.35). If not available, we fall back to
    BEGIN IMMEDIATE to serialize writers.
    """
    payload = json.dumps(pool, ensure_ascii=False)
    with connect(db_path) as conn:
        # Fast path for newer SQLite: use RETURNING to get our own bumped version.
        try:
            row = conn.execute(
                "UPDATE nodes SET desired_pool_json=?, desired_pool_version=desired_pool_version+1 WHERE id=? RETURNING desired_pool_version",
                (payload, int(node_id)),
            ).fetchone()
            conn.commit()
            new_ver = int(row[0]) if row else 0
            return new_ver, pool
        except sqlite3.OperationalError:
            # Compatibility path for older SQLite: lock then read+write.
            try:
                conn.execute("BEGIN IMMEDIATE")
            except Exception:
                pass
            row = conn.execute(
                "SELECT desired_pool_version FROM nodes WHERE id=?",
                (int(node_id),),
            ).fetchone()
            cur_ver = int(row[0]) if row else 0
            new_ver = cur_ver + 1
            conn.execute(
                "UPDATE nodes SET desired_pool_json=?, desired_pool_version=? WHERE id=?",
                (payload, new_ver, int(node_id)),
            )
            conn.commit()
            return new_ver, pool


def set_desired_pool_exact(
    node_id: int,
    pool: Dict[str, Any],
    version: int,
    db_path: str = DEFAULT_DB_PATH,
) -> Tuple[int, Dict[str, Any]]:
    """Set desired pool with an explicit version (no auto increment).

    Used to realign panel desired version to agent ack version after panel migration,
    so that subsequent edits will produce versions greater than agent ack.
    Returns (version, pool).
    """
    ver = max(0, int(version or 0))
    payload = json.dumps(pool, ensure_ascii=False)
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE nodes SET desired_pool_json=?, desired_pool_version=? WHERE id=?",
            (payload, ver, int(node_id)),
        )
        conn.commit()
    return ver, pool


def set_desired_pool_version_exact(
    node_id: int,
    version: int,
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    """Set desired_pool_version without changing desired_pool_json."""
    ver = max(0, int(version or 0))
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE nodes SET desired_pool_version=? WHERE id=?",
            (ver, int(node_id)),
        )
        conn.commit()
    return ver


def bump_traffic_reset_version(
    node_id: int,
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    """Bump desired_traffic_reset_version atomically and return new version.

    This is used to queue a 'reset_traffic' command via agent push-report,
    so panel can reset nodes that are not directly reachable.
    """
    with connect(db_path) as conn:
        # Prefer RETURNING when available (SQLite >=3.35)
        try:
            row = conn.execute(
                "UPDATE nodes SET desired_traffic_reset_version=desired_traffic_reset_version+1, traffic_reset_at=datetime('now') WHERE id=? RETURNING desired_traffic_reset_version",
                (int(node_id),),
            ).fetchone()
            conn.commit()
            return int(row[0]) if row else 0
        except sqlite3.OperationalError:
            try:
                conn.execute('BEGIN IMMEDIATE')
            except Exception:
                pass
            row = conn.execute(
                'SELECT desired_traffic_reset_version FROM nodes WHERE id=?',
                (int(node_id),),
            ).fetchone()
            cur_ver = int(row[0]) if row else 0
            new_ver = cur_ver + 1
            conn.execute(
                "UPDATE nodes SET desired_traffic_reset_version=?, traffic_reset_at=datetime('now') WHERE id=?",
                (new_ver, int(node_id)),
            )
            conn.commit()
            return int(new_ver)


def get_desired_pool(node_id: int, db_path: str = DEFAULT_DB_PATH) -> Tuple[int, Optional[Dict[str, Any]]]:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT desired_pool_version, desired_pool_json FROM nodes WHERE id=?",
            (int(node_id),),
        ).fetchone()
    if not row:
        return 0, None
    ver = int(row["desired_pool_version"] or 0)
    raw = row["desired_pool_json"]
    if not raw:
        return ver, None
    try:
        return ver, json.loads(raw)
    except Exception:
        return ver, None


@contextmanager
def connect(db_path: str = DEFAULT_DB_PATH):
    ensure_parent_dir(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    # Best-effort PRAGMAs for better concurrency / less "database is locked" in background sampling.
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except Exception:
        pass
    try:
        conn.execute("PRAGMA synchronous=NORMAL")
    except Exception:
        pass
    try:
        conn.execute("PRAGMA busy_timeout=5000")
    except Exception:
        pass
    try:
        conn.execute("PRAGMA foreign_keys=ON")
    except Exception:
        pass
    try:
        yield conn
    finally:
        conn.close()


def _json_loads(raw: str, default: Any) -> Any:
    try:
        return json.loads(raw) if raw else default
    except Exception:
        return default


def _norm_int_seq(raw: Any, lo: int, hi: int) -> List[int]:
    out: List[int] = []
    seen: set[int] = set()
    seq = raw if isinstance(raw, list) else []
    for x in seq:
        try:
            v = int(x)
        except Exception:
            continue
        if v < int(lo) or v > int(hi):
            continue
        if v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def _node_auto_restart_policy_from_row_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    def _to_int(v: Any, default: int) -> int:
        try:
            return int(v)
        except Exception:
            try:
                return int(float(str(v).strip()))
            except Exception:
                return int(default)

    schedule_type = str(d.get("auto_restart_schedule_type") or "daily").strip().lower()
    if schedule_type not in ("daily", "weekly", "monthly"):
        schedule_type = "daily"
    interval = _to_int(d.get("auto_restart_interval"), 1)
    if interval < 1:
        interval = 1
    if interval > 365:
        interval = 365
    hour = _to_int(d.get("auto_restart_hour"), 4)
    if hour < 0:
        hour = 0
    if hour > 23:
        hour = 23
    minute = _to_int(d.get("auto_restart_minute"), 8)
    if minute < 0:
        minute = 0
    if minute > 59:
        minute = 59

    weekdays = _norm_int_seq(_json_loads(str(d.get("auto_restart_weekdays_json") or "[]"), []), 1, 7)
    if not weekdays:
        weekdays = [1, 2, 3, 4, 5, 6, 7]

    monthdays = _norm_int_seq(_json_loads(str(d.get("auto_restart_monthdays_json") or "[]"), []), 1, 31)
    if not monthdays:
        monthdays = [1]

    return {
        "enabled": bool(_to_int(d.get("auto_restart_enabled"), 0)),
        "schedule_type": schedule_type,
        "interval": int(interval),
        "hour": int(hour),
        "minute": int(minute),
        "weekdays": weekdays,
        "monthdays": monthdays,
        "desired_version": _to_int(d.get("desired_auto_restart_policy_version"), 0),
        "ack_version": _to_int(d.get("agent_auto_restart_policy_ack_version"), 0),
        "updated_at": str(d.get("auto_restart_updated_at") or ""),
    }


def node_auto_restart_policy_from_row(row: Dict[str, Any]) -> Dict[str, Any]:
    d = dict(row or {})
    return _node_auto_restart_policy_from_row_dict(d)


def _parse_node_row(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    caps = _json_loads(str(d.get("capabilities_json") or "{}"), {})
    if not isinstance(caps, dict):
        caps = {}
    d["capabilities"] = caps
    agent_caps = _json_loads(str(d.get("agent_capabilities_json") or "{}"), {})
    if not isinstance(agent_caps, dict):
        agent_caps = {}
    d["agent_capabilities"] = agent_caps
    d["auto_restart_policy"] = _node_auto_restart_policy_from_row_dict(d)
    return d


def list_nodes(db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    # Performance: avoid loading giant JSON columns (last_report_json / desired_pool_json)
    # for list pages and background workers. Those payloads should be fetched on-demand
    # via get_last_report()/get_desired_pool() by node id.
    sql = (
        "SELECT "
        "id, name, base_url, api_key, verify_tls, is_private, group_name, role, "
        "capabilities_json, website_root_base, "
        "last_seen_at, desired_pool_version, agent_ack_version, "
        "desired_traffic_reset_version, agent_traffic_reset_ack_version, "
        "traffic_reset_at, traffic_reset_msg, "
        "desired_agent_version, desired_agent_update_id, desired_agent_command_id, "
        "agent_reported_version, agent_capabilities_json, "
        "agent_update_state, agent_update_msg, agent_update_reason_code, "
        "agent_update_retry_count, agent_update_max_retries, agent_update_next_retry_at, "
        "agent_update_delivered_at, agent_update_accepted_at, agent_update_started_at, agent_update_finished_at, "
        "agent_update_at, "
        "auto_restart_enabled, auto_restart_schedule_type, auto_restart_interval, "
        "auto_restart_hour, auto_restart_minute, auto_restart_weekdays_json, auto_restart_monthdays_json, "
        "desired_auto_restart_policy_version, agent_auto_restart_policy_ack_version, auto_restart_updated_at, "
        "created_at "
        "FROM nodes ORDER BY id DESC"
    )
    with connect(db_path) as conn:
        rows = conn.execute(sql).fetchall()
    return [_parse_node_row(r) for r in rows]


def get_group_orders(db_path: str = DEFAULT_DB_PATH) -> Dict[str, int]:
    """Return mapping group_name -> sort_order."""
    with connect(db_path) as conn:
        rows = conn.execute("SELECT group_name, sort_order FROM group_orders").fetchall()
    out: Dict[str, int] = {}
    for r in rows:
        try:
            out[str(r["group_name"]) or ""] = int(r["sort_order"])
        except Exception:
            continue
    return out


def upsert_group_order(group_name: str, sort_order: int, db_path: str = DEFAULT_DB_PATH) -> None:
    name = (group_name or "").strip() or "默认分组"
    order = int(sort_order or 0)
    with connect(db_path) as conn:
        # Update first for compatibility with older sqlite versions.
        cur = conn.execute(
            "UPDATE group_orders SET sort_order=?, updated_at=datetime('now') WHERE group_name=?",
            (order, name),
        )
        if cur.rowcount == 0:
            conn.execute(
                "INSERT INTO group_orders(group_name, sort_order, updated_at) VALUES(?,?,datetime('now'))",
                (name, order),
            )
        conn.commit()


def get_panel_setting(key: str, default: Optional[str] = None, db_path: str = DEFAULT_DB_PATH) -> Optional[str]:
    k = (key or "").strip()
    if not k:
        return default
    with connect(db_path) as conn:
        row = conn.execute("SELECT value FROM panel_settings WHERE key=? LIMIT 1", (k,)).fetchone()
    if not row:
        return default
    try:
        return str(row["value"] or "")
    except Exception:
        return default


def set_panel_setting(key: str, value: Optional[str], db_path: str = DEFAULT_DB_PATH) -> None:
    k = (key or "").strip()
    if not k:
        return
    v = "" if value is None else str(value)
    with connect(db_path) as conn:
        cur = conn.execute(
            "UPDATE panel_settings SET value=?, updated_at=datetime('now') WHERE key=?",
            (v, k),
        )
        if int(cur.rowcount or 0) <= 0:
            conn.execute(
                "INSERT INTO panel_settings(key, value, updated_at) VALUES(?,?,datetime('now'))",
                (k, v),
            )
        conn.commit()


def list_panel_settings(db_path: str = DEFAULT_DB_PATH) -> Dict[str, str]:
    with connect(db_path) as conn:
        rows = conn.execute("SELECT key, value FROM panel_settings ORDER BY key ASC").fetchall()
    out: Dict[str, str] = {}
    for r in rows:
        try:
            k = str(r["key"] or "").strip()
        except Exception:
            k = ""
        if not k:
            continue
        try:
            out[k] = str(r["value"] or "")
        except Exception:
            out[k] = ""
    return out


def get_node(node_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
    return _parse_node_row(row) if row else None


def get_node_runtime(node_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Get node runtime metadata without loading large JSON blobs."""
    sql = (
        "SELECT "
        "id, name, base_url, api_key, verify_tls, is_private, group_name, role, "
        "capabilities_json, website_root_base, "
        "last_seen_at, desired_pool_version, agent_ack_version, "
        "desired_traffic_reset_version, agent_traffic_reset_ack_version, "
        "traffic_reset_at, traffic_reset_msg, "
        "desired_agent_version, desired_agent_update_id, desired_agent_command_id, "
        "agent_reported_version, agent_capabilities_json, "
        "agent_update_state, agent_update_msg, agent_update_reason_code, "
        "agent_update_retry_count, agent_update_max_retries, agent_update_next_retry_at, "
        "agent_update_delivered_at, agent_update_accepted_at, agent_update_started_at, agent_update_finished_at, "
        "agent_update_at, "
        "auto_restart_enabled, auto_restart_schedule_type, auto_restart_interval, "
        "auto_restart_hour, auto_restart_minute, auto_restart_weekdays_json, auto_restart_monthdays_json, "
        "desired_auto_restart_policy_version, agent_auto_restart_policy_ack_version, auto_restart_updated_at, "
        "created_at, "
        "CASE WHEN COALESCE(desired_pool_json, '') <> '' THEN 1 ELSE 0 END AS desired_pool_present "
        "FROM nodes WHERE id=?"
    )
    with connect(db_path) as conn:
        row = conn.execute(sql, (int(node_id),)).fetchone()
    return _parse_node_row(row) if row else None


def get_node_by_api_key(api_key: str, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    api_key = (api_key or "").strip()
    if not api_key:
        return None
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM nodes WHERE api_key=?", (api_key,)).fetchone()
    return _parse_node_row(row) if row else None


def get_node_by_base_url(base_url: str, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    base_url = (base_url or "").strip().rstrip('/')
    if not base_url:
        return None
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM nodes WHERE base_url=?", (base_url,)).fetchone()
    return _parse_node_row(row) if row else None


def update_node_basic(
    node_id: int,
    name: str,
    base_url: str,
    api_key: str,
    verify_tls: bool = True,
    is_private: bool = False,
    group_name: str = '默认分组',
    role: Optional[str] = None,
    capabilities: Optional[Dict[str, Any]] = None,
    website_root_base: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> None:
    """Update basic node fields without touching reports/pools."""
    fields = [
        "name=?",
        "base_url=?",
        "api_key=?",
        "verify_tls=?",
        "is_private=?",
        "group_name=?",
    ]
    params: List[Any] = [
        (name or "").strip(),
        (base_url or "").strip().rstrip('/'),
        (api_key or "").strip(),
        1 if verify_tls else 0,
        1 if is_private else 0,
        (group_name or '默认分组').strip() or '默认分组',
    ]

    if role is not None:
        role_val = (role or "").strip().lower() or "normal"
        if role_val not in ("normal", "website"):
            role_val = "normal"
        fields.append("role=?")
        params.append(role_val)

    if capabilities is not None:
        try:
            caps_json = json.dumps(capabilities or {}, ensure_ascii=False)
        except Exception:
            caps_json = "{}"
        fields.append("capabilities_json=?")
        params.append(caps_json)

    if website_root_base is not None:
        fields.append("website_root_base=?")
        params.append((website_root_base or "").strip())

    with connect(db_path) as conn:
        sql = f"UPDATE nodes SET {', '.join(fields)} WHERE id=?"
        params.append(int(node_id))
        conn.execute(sql, params)
        conn.commit()


def add_node(
    name: str,
    base_url: str,
    api_key: str,
    verify_tls: bool = True,
    is_private: bool = False,
    group_name: str = '默认分组',
    role: str = 'normal',
    capabilities: Optional[Dict[str, Any]] = None,
    website_root_base: str = '',
    preferred_id: Optional[int] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    role_val = (role or "").strip().lower() or "normal"
    if role_val not in ("normal", "website"):
        role_val = "normal"
    try:
        caps_json = json.dumps(capabilities or {}, ensure_ascii=False)
    except Exception:
        caps_json = "{}"
    pref_id = 0
    try:
        pref_id = int(preferred_id or 0)
    except Exception:
        pref_id = 0
    with connect(db_path) as conn:
        if pref_id > 0:
            cur = conn.execute(
                "INSERT INTO nodes(id, name, base_url, api_key, verify_tls, is_private, group_name, role, capabilities_json, website_root_base) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    int(pref_id),
                    name.strip(),
                    base_url.strip().rstrip('/'),
                    api_key.strip(),
                    1 if verify_tls else 0,
                    1 if is_private else 0,
                    (group_name or '默认分组').strip() or '默认分组',
                    role_val,
                    caps_json,
                    (website_root_base or "").strip(),
                ),
            )
        else:
            cur = conn.execute(
                "INSERT INTO nodes(name, base_url, api_key, verify_tls, is_private, group_name, role, capabilities_json, website_root_base) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    name.strip(),
                    base_url.strip().rstrip('/'),
                    api_key.strip(),
                    1 if verify_tls else 0,
                    1 if is_private else 0,
                    (group_name or '默认分组').strip() or '默认分组',
                    role_val,
                    caps_json,
                    (website_root_base or "").strip(),
                ),
            )
        conn.commit()
        if pref_id > 0:
            return int(pref_id)
        return int(cur.lastrowid)


def delete_node(node_id: int, db_path: str = DEFAULT_DB_PATH) -> None:
    with connect(db_path) as conn:
        conn.execute("DELETE FROM nodes WHERE id=?", (node_id,))
        conn.commit()


# =========================
# NetMon: monitor definitions + samples
# =========================

def _netmon_json_loads(raw: str) -> Any:
    try:
        return json.loads(raw) if raw else None
    except Exception:
        return None


def _netmon_json_dumps(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False)
    except Exception:
        return "[]"


def list_netmon_monitors(db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Return all NetMon monitors (newest first).

    Fields:
      - node_ids: parsed list[int]
    """
    with connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM netmon_monitors ORDER BY id DESC").fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        node_ids = _netmon_json_loads(str(d.get("node_ids_json") or "[]"))
        if not isinstance(node_ids, list):
            node_ids = []
        cleaned: List[int] = []
        for x in node_ids:
            try:
                nid = int(x)
            except Exception:
                continue
            if nid > 0 and nid not in cleaned:
                cleaned.append(nid)
        d["node_ids"] = cleaned
        out.append(d)
    return out


def get_netmon_monitor(monitor_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM netmon_monitors WHERE id=?", (int(monitor_id),)).fetchone()
    if not row:
        return None
    d = dict(row)
    node_ids = _netmon_json_loads(str(d.get("node_ids_json") or "[]"))
    if not isinstance(node_ids, list):
        node_ids = []
    cleaned: List[int] = []
    for x in node_ids:
        try:
            nid = int(x)
        except Exception:
            continue
        if nid > 0 and nid not in cleaned:
            cleaned.append(nid)
    d["node_ids"] = cleaned
    return d


def add_netmon_monitor(
    target: str,
    mode: str,
    tcp_port: int,
    interval_sec: int,
    node_ids: List[int],
    warn_ms: int = 0,
    crit_ms: int = 0,
    enabled: bool = True,
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    t = (target or "").strip()
    m = (mode or "ping").strip().lower() or "ping"
    if m not in ("ping", "tcping"):
        m = "ping"
    try:
        tp = int(tcp_port)
    except Exception:
        tp = 443
    if tp < 1 or tp > 65535:
        tp = 443
    try:
        itv = int(interval_sec)
    except Exception:
        itv = 5
    if itv < 1:
        itv = 1
    if itv > 3600:
        itv = 3600

    try:
        wm = int(warn_ms)
    except Exception:
        wm = 0
    if wm < 0:
        wm = 0
    if wm > 600000:
        wm = 600000

    try:
        cm = int(crit_ms)
    except Exception:
        cm = 0
    if cm < 0:
        cm = 0
    if cm > 600000:
        cm = 600000

    # Ensure warn <= crit when both set
    if wm > 0 and cm > 0 and wm > cm:
        wm, cm = cm, wm

    cleaned: List[int] = []
    for x in node_ids or []:
        try:
            nid = int(x)
        except Exception:
            continue
        if nid > 0 and nid not in cleaned:
            cleaned.append(nid)

    node_ids_json = json.dumps(cleaned, ensure_ascii=False)

    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO netmon_monitors(target, mode, tcp_port, interval_sec, warn_ms, crit_ms, node_ids_json, enabled, updated_at) VALUES(?,?,?,?,?,?,?,?,datetime('now'))",
            (t, m, tp, itv, wm, cm, node_ids_json, 1 if enabled else 0),
        )
        conn.commit()
        return int(cur.lastrowid)


def update_netmon_monitor(
    monitor_id: int,
    target: Optional[str] = None,
    mode: Optional[str] = None,
    tcp_port: Optional[int] = None,
    interval_sec: Optional[int] = None,
    node_ids: Optional[List[int]] = None,
    warn_ms: Optional[int] = None,
    crit_ms: Optional[int] = None,
    enabled: Optional[bool] = None,
    last_run_ts_ms: Optional[int] = None,
    last_run_msg: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> None:
    fields: List[str] = []
    vals: List[Any] = []

    if target is not None:
        fields.append("target=?")
        vals.append((target or "").strip())
    if mode is not None:
        m = (mode or "ping").strip().lower() or "ping"
        if m not in ("ping", "tcping"):
            m = "ping"
        fields.append("mode=?")
        vals.append(m)
    if tcp_port is not None:
        try:
            tp = int(tcp_port)
        except Exception:
            tp = 443
        if tp < 1 or tp > 65535:
            tp = 443
        fields.append("tcp_port=?")
        vals.append(tp)
    if interval_sec is not None:
        try:
            itv = int(interval_sec)
        except Exception:
            itv = 5
        if itv < 1:
            itv = 1
        if itv > 3600:
            itv = 3600
        fields.append("interval_sec=?")
        vals.append(itv)
    wm_set = None
    cm_set = None

    if warn_ms is not None:
        try:
            wm = int(warn_ms)
        except Exception:
            wm = 0
        if wm < 0:
            wm = 0
        if wm > 600000:
            wm = 600000
        wm_set = wm

    if crit_ms is not None:
        try:
            cm = int(crit_ms)
        except Exception:
            cm = 0
        if cm < 0:
            cm = 0
        if cm > 600000:
            cm = 600000
        cm_set = cm

    # Ensure warn <= crit when both are provided and both enabled
    if wm_set is not None and cm_set is not None and wm_set > 0 and cm_set > 0 and wm_set > cm_set:
        wm_set, cm_set = cm_set, wm_set

    if wm_set is not None:
        fields.append("warn_ms=?")
        vals.append(wm_set)

    if cm_set is not None:
        fields.append("crit_ms=?")
        vals.append(cm_set)

    if node_ids is not None:
        cleaned: List[int] = []
        for x in node_ids or []:
            try:
                nid = int(x)
            except Exception:
                continue
            if nid > 0 and nid not in cleaned:
                cleaned.append(nid)
        fields.append("node_ids_json=?")
        vals.append(json.dumps(cleaned, ensure_ascii=False))
    if enabled is not None:
        fields.append("enabled=?")
        vals.append(1 if enabled else 0)
    if last_run_ts_ms is not None:
        try:
            ts = int(last_run_ts_ms)
        except Exception:
            ts = 0
        fields.append("last_run_ts_ms=?")
        vals.append(ts)
    if last_run_msg is not None:
        fields.append("last_run_msg=?")
        vals.append(str(last_run_msg or ""))

    if not fields:
        return

    # Whitelist validation to avoid accidental SQL injection if this code is modified.
    _allowed_netmon = {
        'target',
        'mode',
        'tcp_port',
        'interval_sec',
        'warn_ms',
        'crit_ms',
        'node_ids_json',
        'enabled',
        'last_run_ts_ms',
        'last_run_msg',
        'updated_at',
    }
    for _f in fields:
        _col = str(_f).split('=', 1)[0].strip()
        if _col not in _allowed_netmon:
            raise ValueError(f"invalid update column: {_col}")

    fields.append("updated_at=datetime('now')")
    with connect(db_path) as conn:
        conn.execute(
            f"UPDATE netmon_monitors SET {', '.join(fields)} WHERE id=?",
            tuple(vals + [int(monitor_id)]),
        )
        conn.commit()


def delete_netmon_monitor(monitor_id: int, db_path: str = DEFAULT_DB_PATH) -> None:
    mid = int(monitor_id)
    with connect(db_path) as conn:
        conn.execute("DELETE FROM netmon_samples WHERE monitor_id=?", (mid,))
        conn.execute("DELETE FROM netmon_monitors WHERE id=?", (mid,))
        conn.commit()


def insert_netmon_samples(
    rows: List[Tuple[int, int, int, int, Optional[float], Optional[str]]],
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    """Insert samples. Returns inserted row count."""
    if not rows:
        return 0
    with connect(db_path) as conn:
        conn.executemany(
            "INSERT INTO netmon_samples(monitor_id, node_id, ts_ms, ok, latency_ms, error) VALUES(?,?,?,?,?,?)",
            rows,
        )
        conn.commit()
    return len(rows)


def list_netmon_samples(
    monitor_ids: List[int],
    since_ts_ms: int,
    db_path: str = DEFAULT_DB_PATH,
) -> List[Dict[str, Any]]:
    mids = []
    for x in monitor_ids or []:
        try:
            mid = int(x)
        except Exception:
            continue
        if mid > 0 and mid not in mids:
            mids.append(mid)
    if not mids:
        return []
    try:
        since = int(since_ts_ms)
    except Exception:
        since = 0

    # Build dynamic IN clause safely
    placeholders = ",".join(["?"] * len(mids))
    sql = f"SELECT monitor_id, node_id, ts_ms, ok, latency_ms, error FROM netmon_samples WHERE monitor_id IN ({placeholders}) AND ts_ms>=? ORDER BY ts_ms ASC"
    with connect(db_path) as conn:
        rows = conn.execute(sql, tuple(mids + [since])).fetchall()
    return [dict(r) for r in rows]


def list_netmon_samples_range(
    monitor_id: int,
    from_ts_ms: int,
    to_ts_ms: int,
    limit: int = 60000,
    db_path: str = DEFAULT_DB_PATH,
) -> List[Dict[str, Any]]:
    """Return raw samples for a single monitor within [from, to].

    Used for "event detail" diagnosis modal.

    Notes:
      - We keep it raw (no rollup) to preserve details.
      - A hard LIMIT is applied as a safety net.
    """
    try:
        mid = int(monitor_id)
    except Exception:
        mid = 0
    if mid <= 0:
        return []
    try:
        f = int(from_ts_ms)
    except Exception:
        f = 0
    try:
        t = int(to_ts_ms)
    except Exception:
        t = 0
    if f <= 0 or t <= 0 or t <= f:
        return []
    try:
        lim = int(limit)
    except Exception:
        lim = 60000
    if lim < 1000:
        lim = 1000
    if lim > 200000:
        lim = 200000

    sql = """
        SELECT monitor_id, node_id, ts_ms, ok, latency_ms, error
        FROM netmon_samples
        WHERE monitor_id=? AND ts_ms>=? AND ts_ms<=?
        ORDER BY ts_ms ASC
        LIMIT ?
    """
    with connect(db_path) as conn:
        rows = conn.execute(sql, (mid, f, t, lim)).fetchall()
    return [dict(r) for r in rows]


def list_netmon_samples_rollup(
    monitor_ids: List[int],
    since_ts_ms: int,
    bucket_ms: int,
    db_path: str = DEFAULT_DB_PATH,
) -> List[Dict[str, Any]]:
    """Return rolled-up samples aggregated by time buckets.

    This is used for large time windows to reduce payload size and
    improve chart performance.

    Returns rows:
      - monitor_id
      - node_id
      - bucket_ts_ms (integer, bucket start)
      - cnt (total samples in bucket)
      - ok_cnt
      - fail_cnt
      - avg_latency_ms (avg of ok samples)
      - max_latency_ms (max of ok samples)
      - error (an arbitrary error string from failed samples)
    """
    mids: List[int] = []
    for x in monitor_ids or []:
        try:
            mid = int(x)
        except Exception:
            continue
        if mid > 0 and mid not in mids:
            mids.append(mid)
    if not mids:
        return []

    try:
        since = int(since_ts_ms)
    except Exception:
        since = 0

    try:
        bms = int(bucket_ms)
    except Exception:
        bms = 0
    if bms <= 0:
        # fallback to raw listing
        return list_netmon_samples(mids, since, db_path=db_path)
    if bms < 1000:
        bms = 1000
    if bms > 24 * 3600 * 1000:
        bms = 24 * 3600 * 1000

    placeholders = ",".join(["?"] * len(mids))
    # Use integer modulo to avoid float precision issues.
    sql = f"""
        SELECT
            monitor_id,
            node_id,
            (ts_ms - (ts_ms % ?)) AS bucket_ts_ms,
            COUNT(*) AS cnt,
            SUM(ok) AS ok_cnt,
            SUM(CASE WHEN ok=0 THEN 1 ELSE 0 END) AS fail_cnt,
            AVG(CASE WHEN ok=1 THEN latency_ms END) AS avg_latency_ms,
            MAX(CASE WHEN ok=1 THEN latency_ms END) AS max_latency_ms,
            MAX(CASE WHEN ok=0 THEN error END) AS error
        FROM netmon_samples
        WHERE monitor_id IN ({placeholders}) AND ts_ms >= ?
        GROUP BY monitor_id, node_id, bucket_ts_ms
        ORDER BY bucket_ts_ms ASC
    """

    with connect(db_path) as conn:
        rows = conn.execute(sql, tuple([bms] + mids + [since])).fetchall()
    return [dict(r) for r in rows]


def prune_netmon_samples(before_ts_ms: int, db_path: str = DEFAULT_DB_PATH) -> int:
    try:
        cutoff = int(before_ts_ms)
    except Exception:
        cutoff = 0
    if cutoff <= 0:
        return 0
    with connect(db_path) as conn:
        cur = conn.execute("DELETE FROM netmon_samples WHERE ts_ms < ?", (cutoff,))
        conn.commit()
        return int(cur.rowcount or 0)


# ---------------- Rule stats history (persistent time-series) ----------------


def insert_rule_stats_samples(
    rows: List[Tuple[int, str, int, int, int, int, int]],
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    """Insert rule stats history rows.

    Each row is:
      (node_id, rule_key, ts_ms, rx_bytes, tx_bytes, connections_active, connections_total)

    Uses INSERT OR IGNORE to avoid duplicates (unique index: node_id+rule_key+ts_ms).
    Returns best-effort inserted count.
    """
    if not rows:
        return 0
    with connect(db_path) as conn:
        before = int(conn.total_changes or 0)
        conn.executemany(
            "INSERT OR IGNORE INTO rule_stats_samples(node_id, rule_key, ts_ms, rx_bytes, tx_bytes, connections_active, connections_total) VALUES(?,?,?,?,?,?,?)",
            rows,
        )
        conn.commit()
        after = int(conn.total_changes or 0)
        inserted = after - before
        # sqlite3.total_changes is best-effort; never return negative.
        return int(inserted if inserted > 0 else 0)


def list_rule_stats_series(
    node_id: int,
    rule_key: str,
    from_ts_ms: int,
    to_ts_ms: int,
    limit: int = 8000,
    include_prev: bool = True,
    db_path: str = DEFAULT_DB_PATH,
) -> List[Dict[str, Any]]:
    """List rule stats samples for a single node+rule within [from, to].

    If include_prev=True, returns one extra sample immediately before `from_ts_ms`
    (when available), so the frontend can compute rate at the window boundary.
    """
    try:
        nid = int(node_id)
    except Exception:
        nid = 0
    if nid <= 0:
        return []

    key = str(rule_key or "").strip() or "__all__"

    try:
        f = int(from_ts_ms)
    except Exception:
        f = 0
    try:
        t = int(to_ts_ms)
    except Exception:
        t = 0
    if f <= 0 or t <= 0 or t <= f:
        return []

    try:
        lim = int(limit)
    except Exception:
        lim = 8000
    if lim < 200:
        lim = 200
    if lim > 200000:
        lim = 200000

    prev: List[sqlite3.Row] = []
    if include_prev:
        sql_prev = """
            SELECT ts_ms, rx_bytes, tx_bytes, connections_active, connections_total
            FROM rule_stats_samples
            WHERE node_id=? AND rule_key=? AND ts_ms < ?
            ORDER BY ts_ms DESC
            LIMIT 1
        """
        with connect(db_path) as conn:
            prev = conn.execute(sql_prev, (nid, key, f)).fetchall()

    sql = """
        SELECT ts_ms, rx_bytes, tx_bytes, connections_active, connections_total
        FROM rule_stats_samples
        WHERE node_id=? AND rule_key=? AND ts_ms>=? AND ts_ms<=?
        ORDER BY ts_ms ASC
        LIMIT ?
    """
    with connect(db_path) as conn:
        rows = conn.execute(sql, (nid, key, f, t, lim)).fetchall()

    out: List[Dict[str, Any]] = []
    if prev:
        out.append(dict(prev[0]))
    for r in rows:
        out.append(dict(r))

    # Deduplicate potential overlap between prev and first row.
    if len(out) >= 2:
        try:
            if int(out[0].get("ts_ms") or 0) == int(out[1].get("ts_ms") or 0):
                out.pop(0)
        except Exception:
            pass

    return out


def clear_rule_stats_samples(
    node_id: int,
    rule_key: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    """Clear stats history.

    - If rule_key is None: delete all history for the node.
    - If rule_key is provided: delete only that series (node_id+rule_key).
    """
    try:
        nid = int(node_id)
    except Exception:
        nid = 0
    if nid <= 0:
        return 0

    key = str(rule_key or "").strip() if rule_key is not None else None
    with connect(db_path) as conn:
        if key is None:
            cur = conn.execute("DELETE FROM rule_stats_samples WHERE node_id=?", (nid,))
        else:
            cur = conn.execute(
                "DELETE FROM rule_stats_samples WHERE node_id=? AND rule_key=?",
                (nid, key),
            )
        conn.commit()
        return int(cur.rowcount or 0)


def prune_rule_stats_samples(before_ts_ms: int, db_path: str = DEFAULT_DB_PATH) -> int:
    """Prune history rows older than cutoff timestamp."""
    try:
        cutoff = int(before_ts_ms)
    except Exception:
        cutoff = 0
    if cutoff <= 0:
        return 0
    with connect(db_path) as conn:
        cur = conn.execute("DELETE FROM rule_stats_samples WHERE ts_ms < ?", (cutoff,))
        conn.commit()
        return int(cur.rowcount or 0)


# =========================
# Website Management: sites / certificates / tasks
# =========================

def _json_dumps(obj: Any, default: str = "[]") -> str:
    try:
        return json.dumps(obj, ensure_ascii=False)
    except Exception:
        return default


def list_sites(node_id: Optional[int] = None, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    sql = "SELECT * FROM sites"
    params: Tuple[Any, ...] = ()
    if node_id is not None:
        sql += " WHERE node_id=?"
        params = (int(node_id),)
    sql += " ORDER BY id DESC"
    with connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        domains = _json_loads(str(d.get("domains_json") or "[]"), [])
        if not isinstance(domains, list):
            domains = []
        d["domains"] = domains
        d["https_redirect"] = bool(d.get("https_redirect") or 0)
        d["gzip_enabled"] = bool(d.get("gzip_enabled") or 0)
        d["health_status"] = str(d.get("health_status") or "").strip()
        d["health_code"] = int(d.get("health_code") or 0)
        d["health_latency_ms"] = int(d.get("health_latency_ms") or 0)
        d["health_error"] = str(d.get("health_error") or "").strip()
        out.append(d)
    return out


def get_site(site_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM sites WHERE id=?", (int(site_id),)).fetchone()
    if not row:
        return None
    d = dict(row)
    domains = _json_loads(str(d.get("domains_json") or "[]"), [])
    if not isinstance(domains, list):
        domains = []
    d["domains"] = domains
    d["https_redirect"] = bool(d.get("https_redirect") or 0)
    d["gzip_enabled"] = bool(d.get("gzip_enabled") or 0)
    d["health_status"] = str(d.get("health_status") or "").strip()
    d["health_code"] = int(d.get("health_code") or 0)
    d["health_latency_ms"] = int(d.get("health_latency_ms") or 0)
    d["health_error"] = str(d.get("health_error") or "").strip()
    return d


def add_site(
    node_id: int,
    name: str,
    domains: List[str],
    root_path: str,
    proxy_target: str,
    site_type: str,
    web_server: str = "nginx",
    nginx_tpl: str = "",
    https_redirect: bool = False,
    gzip_enabled: bool = True,
    status: str = "running",
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    payload = _json_dumps(domains or [])
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO sites(node_id, name, domains_json, root_path, proxy_target, type, web_server, nginx_tpl, https_redirect, gzip_enabled, status, created_at, updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'))",
            (
                int(node_id),
                (name or "").strip(),
                payload,
                (root_path or "").strip(),
                (proxy_target or "").strip(),
                (site_type or "static").strip(),
                (web_server or "nginx").strip(),
                (nginx_tpl or "").strip(),
                1 if https_redirect else 0,
                1 if gzip_enabled else 0,
                (status or "running").strip(),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def update_site(
    site_id: int,
    name: Optional[str] = None,
    domains: Optional[List[str]] = None,
    root_path: Optional[str] = None,
    proxy_target: Optional[str] = None,
    site_type: Optional[str] = None,
    web_server: Optional[str] = None,
    nginx_tpl: Optional[str] = None,
    https_redirect: Optional[bool] = None,
    gzip_enabled: Optional[bool] = None,
    status: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> None:
    fields: List[str] = []
    params: List[Any] = []
    if name is not None:
        fields.append("name=?")
        params.append((name or "").strip())
    if domains is not None:
        fields.append("domains_json=?")
        params.append(_json_dumps(domains or []))
    if root_path is not None:
        fields.append("root_path=?")
        params.append((root_path or "").strip())
    if proxy_target is not None:
        fields.append("proxy_target=?")
        params.append((proxy_target or "").strip())
    if site_type is not None:
        fields.append("type=?")
        params.append((site_type or "").strip())
    if web_server is not None:
        fields.append("web_server=?")
        params.append((web_server or "").strip())
    if nginx_tpl is not None:
        fields.append("nginx_tpl=?")
        params.append((nginx_tpl or "").strip())
    if https_redirect is not None:
        fields.append("https_redirect=?")
        params.append(1 if https_redirect else 0)
    if gzip_enabled is not None:
        fields.append("gzip_enabled=?")
        params.append(1 if gzip_enabled else 0)
    if status is not None:
        fields.append("status=?")
        params.append((status or "").strip())
    if not fields:
        return
    fields.append("updated_at=datetime('now')")
    with connect(db_path) as conn:
        conn.execute(
            f"UPDATE sites SET {', '.join(fields)} WHERE id=?",
            (*params, int(site_id)),
        )
        conn.commit()


def update_site_health(
    site_id: int,
    health_status: str,
    health_code: int = 0,
    health_latency_ms: int = 0,
    health_error: str = "",
    health_checked_at: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> None:
    fields = [
        "health_status=?",
        "health_code=?",
        "health_latency_ms=?",
        "health_error=?",
    ]
    params: List[Any] = [
        (health_status or "").strip(),
        int(health_code or 0),
        int(health_latency_ms or 0),
        (health_error or "").strip(),
    ]
    if health_checked_at is not None:
        fields.append("health_checked_at=?")
        params.append(health_checked_at)
    else:
        fields.append("health_checked_at=datetime('now')")
    with connect(db_path) as conn:
        conn.execute(
            f"UPDATE sites SET {', '.join(fields)} WHERE id=?",
            (*params, int(site_id)),
        )
        conn.commit()


def add_site_event(
    site_id: int,
    action: str,
    status: str = "success",
    actor: str = "",
    payload: Optional[Dict[str, Any]] = None,
    result: Optional[Dict[str, Any]] = None,
    error: str = "",
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO site_events(site_id, action, status, actor, payload_json, result_json, error, created_at) "
            "VALUES(?,?,?,?,?,?,?,datetime('now'))",
            (
                int(site_id),
                (action or "").strip(),
                (status or "success").strip(),
                (actor or "").strip(),
                _json_dumps(payload or {}, default="{}"),
                _json_dumps(result or {}, default="{}"),
                (error or "").strip(),
            ),
        )
        conn.commit()
        return int(cur.lastrowid or 0)


def list_site_events(site_id: int, limit: int = 100, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM site_events WHERE site_id=? ORDER BY id DESC LIMIT ?",
            (int(site_id), int(limit)),
        ).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        d["payload"] = _json_loads(str(d.get("payload_json") or "{}"), {})
        d["result"] = _json_loads(str(d.get("result_json") or "{}"), {})
        out.append(d)
    return out


def add_site_check(
    site_id: int,
    ok: bool,
    status_code: int = 0,
    latency_ms: int = 0,
    error: str = "",
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO site_checks(site_id, ok, status_code, latency_ms, error, checked_at) "
            "VALUES(?,?,?,?,?,datetime('now'))",
            (int(site_id), 1 if ok else 0, int(status_code or 0), int(latency_ms or 0), (error or "").strip()),
        )
        conn.commit()
        return int(cur.lastrowid or 0)


def list_site_checks(site_id: int, limit: int = 60, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM site_checks WHERE site_id=? ORDER BY id DESC LIMIT ?",
            (int(site_id), int(limit)),
        ).fetchall()
    return [dict(r) for r in rows]


def _normalize_site_file_favorite_owner(owner: Any) -> str:
    return str(owner or "").strip()


def _normalize_site_file_favorite_path(path: Any) -> str:
    text = str(path or "").replace("\\", "/").strip().lstrip("/")
    if not text:
        return ""
    segs: List[str] = []
    for seg in text.split("/"):
        p = str(seg or "").strip()
        if not p or p == ".":
            continue
        if p == "..":
            continue
        segs.append(p)
    return "/".join(segs)


def upsert_site_file_favorite(
    site_id: int,
    owner: str,
    path: str,
    is_dir: bool = False,
    db_path: str = DEFAULT_DB_PATH,
) -> Dict[str, Any]:
    owner_key = _normalize_site_file_favorite_owner(owner)
    rel_path = _normalize_site_file_favorite_path(path)
    if not owner_key:
        raise ValueError("owner 不能为空")
    if not rel_path:
        raise ValueError("path 不能为空")

    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT id, site_id, owner, path, is_dir, created_at, updated_at "
            "FROM site_file_favorites WHERE site_id=? AND owner=? AND path=? LIMIT 1",
            (int(site_id), owner_key, rel_path),
        ).fetchone()
        if row:
            keep_dir = bool(row["is_dir"]) or bool(is_dir)
            conn.execute(
                "UPDATE site_file_favorites SET is_dir=?, updated_at=datetime('now') WHERE id=?",
                (1 if keep_dir else 0, int(row["id"])),
            )
            ret = conn.execute(
                "SELECT id, site_id, owner, path, is_dir, created_at, updated_at "
                "FROM site_file_favorites WHERE id=? LIMIT 1",
                (int(row["id"]),),
            ).fetchone()
        else:
            cur = conn.execute(
                "INSERT INTO site_file_favorites(site_id, owner, path, is_dir, created_at, updated_at) "
                "VALUES(?,?,?,?,datetime('now'),datetime('now'))",
                (int(site_id), owner_key, rel_path, 1 if is_dir else 0),
            )
            ret = conn.execute(
                "SELECT id, site_id, owner, path, is_dir, created_at, updated_at "
                "FROM site_file_favorites WHERE id=? LIMIT 1",
                (int(cur.lastrowid or 0),),
            ).fetchone()
        conn.commit()
    if not ret:
        return {
            "id": 0,
            "site_id": int(site_id),
            "owner": owner_key,
            "path": rel_path,
            "is_dir": bool(is_dir),
            "created_at": "",
            "updated_at": "",
        }
    out = dict(ret)
    out["is_dir"] = bool(out.get("is_dir") or 0)
    return out


def delete_site_file_favorite(
    site_id: int,
    owner: str,
    path: str,
    db_path: str = DEFAULT_DB_PATH,
) -> bool:
    owner_key = _normalize_site_file_favorite_owner(owner)
    rel_path = _normalize_site_file_favorite_path(path)
    if not owner_key or not rel_path:
        return False
    with connect(db_path) as conn:
        cur = conn.execute(
            "DELETE FROM site_file_favorites WHERE site_id=? AND owner=? AND path=?",
            (int(site_id), owner_key, rel_path),
        )
        conn.commit()
        return int(cur.rowcount or 0) > 0


def list_site_file_favorites(
    owner: str,
    site_id: Optional[int] = None,
    limit: int = 200,
    db_path: str = DEFAULT_DB_PATH,
) -> List[Dict[str, Any]]:
    owner_key = _normalize_site_file_favorite_owner(owner)
    if not owner_key:
        return []
    n = int(limit or 200)
    if n < 1:
        n = 1
    if n > 1000:
        n = 1000
    params: List[Any] = [owner_key]
    sql = (
        "SELECT id, site_id, owner, path, is_dir, created_at, updated_at "
        "FROM site_file_favorites WHERE owner=?"
    )
    if site_id is not None:
        sql += " AND site_id=?"
        params.append(int(site_id))
    sql += " ORDER BY updated_at DESC, id DESC LIMIT ?"
    params.append(int(n))
    with connect(db_path) as conn:
        rows = conn.execute(sql, tuple(params)).fetchall()
    out: List[Dict[str, Any]] = []
    for row in rows:
        d = dict(row)
        d["is_dir"] = bool(d.get("is_dir") or 0)
        out.append(d)
    return out


def delete_site_file_favorites(site_id: int, db_path: str = DEFAULT_DB_PATH) -> int:
    with connect(db_path) as conn:
        cur = conn.execute("DELETE FROM site_file_favorites WHERE site_id=?", (int(site_id),))
        conn.commit()
        return int(cur.rowcount or 0)


def revoke_site_file_share_token(
    site_id: int,
    token_sha256: str,
    revoked_by: str = "",
    reason: str = "",
    db_path: str = DEFAULT_DB_PATH,
) -> bool:
    digest = (token_sha256 or "").strip().lower()
    if not digest:
        return False
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT OR IGNORE INTO site_file_share_revocations(site_id, token_sha256, revoked_by, reason, revoked_at) "
            "VALUES(?,?,?,?,datetime('now'))",
            (int(site_id), digest, (revoked_by or "").strip(), (reason or "").strip()),
        )
        conn.commit()
        return int(cur.rowcount or 0) > 0


def is_site_file_share_token_revoked(site_id: int, token_sha256: str, db_path: str = DEFAULT_DB_PATH) -> bool:
    digest = (token_sha256 or "").strip().lower()
    if not digest:
        return False
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT 1 FROM site_file_share_revocations WHERE site_id=? AND token_sha256=? LIMIT 1",
            (int(site_id), digest),
        ).fetchone()
    return bool(row)


def delete_site_file_share_short_links(
    site_id: int,
    token_sha256: str = "",
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    digest = (token_sha256 or "").strip().lower()
    with connect(db_path) as conn:
        if digest:
            cur = conn.execute(
                "DELETE FROM site_file_share_short_links WHERE site_id=? AND token_sha256=?",
                (int(site_id), digest),
            )
        else:
            cur = conn.execute(
                "DELETE FROM site_file_share_short_links "
                "WHERE site_id=? "
                "AND token_sha256 IN (SELECT token_sha256 FROM site_file_share_revocations WHERE site_id=?)",
                (int(site_id), int(site_id)),
            )
        conn.commit()
        return int(cur.rowcount or 0)


def _new_share_short_code(length: int = 8) -> str:
    n = int(length or 8)
    if n < 6:
        n = 6
    if n > 24:
        n = 24
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def create_site_file_share_short_link(
    site_id: int,
    token: str,
    created_by: str = "",
    db_path: str = DEFAULT_DB_PATH,
) -> str:
    raw_token = (token or "").strip()
    if not raw_token:
        raise ValueError("token 不能为空")
    digest = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    with connect(db_path) as conn:
        # Reuse existing short code for the same site+token to keep links stable.
        row = conn.execute(
            "SELECT code FROM site_file_share_short_links WHERE site_id=? AND token_sha256=? ORDER BY created_at DESC LIMIT 1",
            (int(site_id), digest),
        ).fetchone()
        if row and row["code"]:
            return str(row["code"])
        for _ in range(12):
            code = _new_share_short_code(8)
            try:
                conn.execute(
                    "INSERT INTO site_file_share_short_links(code, site_id, token, token_sha256, created_by, created_at) "
                    "VALUES(?,?,?,?,?,datetime('now'))",
                    (code, int(site_id), raw_token, digest, (created_by or "").strip()),
                )
                conn.commit()
                return code
            except sqlite3.IntegrityError:
                continue
    raise RuntimeError("短链生成失败，请重试")


def get_site_file_share_short_link(code: str, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    key = str(code or "").strip()
    if not key:
        return None
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT code, site_id, token, token_sha256, created_by, created_at FROM site_file_share_short_links WHERE code=? LIMIT 1",
            (key,),
        ).fetchone()
    return dict(row) if row else None


def list_site_file_share_short_links(
    site_id: int,
    limit: int = 100,
    db_path: str = DEFAULT_DB_PATH,
) -> List[Dict[str, Any]]:
    n = int(limit or 100)
    if n < 1:
        n = 1
    if n > 500:
        n = 500
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT s.code, s.site_id, s.token, s.token_sha256, s.created_by, s.created_at, "
            "r.revoked_at, r.revoked_by, r.reason "
            "FROM site_file_share_short_links s "
            "LEFT JOIN site_file_share_revocations r "
            "ON r.site_id=s.site_id AND r.token_sha256=s.token_sha256 "
            "WHERE s.site_id=? "
            "ORDER BY s.created_at DESC "
            "LIMIT ?",
            (int(site_id), int(n)),
        ).fetchall()
    return [dict(r) for r in rows]


def prune_site_checks(days: int = 7, db_path: str = DEFAULT_DB_PATH) -> int:
    try:
        d = int(days)
    except Exception:
        d = 7
    if d < 1:
        d = 1
    if d > 365:
        d = 365
    cutoff = f"-{d} days"
    with connect(db_path) as conn:
        cur = conn.execute("DELETE FROM site_checks WHERE checked_at < datetime('now', ?)", (cutoff,))
        conn.commit()
        return int(cur.rowcount or 0)


def delete_site(site_id: int, db_path: str = DEFAULT_DB_PATH) -> None:
    with connect(db_path) as conn:
        conn.execute("DELETE FROM site_file_favorites WHERE site_id=?", (int(site_id),))
        conn.execute("DELETE FROM sites WHERE id=?", (int(site_id),))
        conn.commit()


def delete_site_events(site_id: int, db_path: str = DEFAULT_DB_PATH) -> int:
    with connect(db_path) as conn:
        cur = conn.execute("DELETE FROM site_events WHERE site_id=?", (int(site_id),))
        conn.commit()
        return int(cur.rowcount or 0)


def delete_site_checks(site_id: int, db_path: str = DEFAULT_DB_PATH) -> int:
    with connect(db_path) as conn:
        cur = conn.execute("DELETE FROM site_checks WHERE site_id=?", (int(site_id),))
        conn.commit()
        return int(cur.rowcount or 0)


def delete_sites_by_node(node_id: int, db_path: str = DEFAULT_DB_PATH) -> int:
    with connect(db_path) as conn:
        # collect site ids for cleanup
        rows = conn.execute("SELECT id FROM sites WHERE node_id=?", (int(node_id),)).fetchall()
        for r in rows:
            try:
                sid = int(r["id"])
            except Exception:
                continue
            conn.execute("DELETE FROM site_events WHERE site_id=?", (sid,))
            conn.execute("DELETE FROM site_checks WHERE site_id=?", (sid,))
            conn.execute("DELETE FROM site_file_favorites WHERE site_id=?", (sid,))
        cur = conn.execute("DELETE FROM sites WHERE node_id=?", (int(node_id),))
        conn.commit()
        return int(cur.rowcount or 0)


def list_certificates(
    site_id: Optional[int] = None,
    node_id: Optional[int] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> List[Dict[str, Any]]:
    sql = "SELECT * FROM certificates"
    params: List[Any] = []
    clauses: List[str] = []
    if site_id is not None:
        clauses.append("site_id=?")
        params.append(int(site_id))
    if node_id is not None:
        clauses.append("node_id=?")
        params.append(int(node_id))
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id DESC"
    with connect(db_path) as conn:
        rows = conn.execute(sql, tuple(params)).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        domains = _json_loads(str(d.get("domains_json") or "[]"), [])
        if not isinstance(domains, list):
            domains = []
        d["domains"] = domains
        out.append(d)
    return out


def add_certificate(
    node_id: int,
    site_id: Optional[int],
    domains: List[str],
    issuer: str = "letsencrypt",
    challenge: str = "http-01",
    status: str = "pending",
    not_before: Optional[str] = None,
    not_after: Optional[str] = None,
    renew_at: Optional[str] = None,
    last_error: str = "",
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO certificates(node_id, site_id, domains_json, issuer, challenge, status, "
            "not_before, not_after, renew_at, last_error, created_at, updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'))",
            (
                int(node_id),
                int(site_id) if site_id is not None else None,
                _json_dumps(domains or []),
                (issuer or "letsencrypt").strip(),
                (challenge or "http-01").strip(),
                (status or "pending").strip(),
                not_before,
                not_after,
                renew_at,
                (last_error or "").strip(),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def update_certificate(
    cert_id: int,
    domains: Optional[List[str]] = None,
    status: Optional[str] = None,
    not_before: Optional[str] = None,
    not_after: Optional[str] = None,
    renew_at: Optional[str] = None,
    last_error: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> None:
    fields: List[str] = []
    params: List[Any] = []
    if domains is not None:
        # keep original ordering, remove duplicates
        uniq: List[str] = []
        seen = set()
        for d in (domains or []):
            ds = str(d or "").strip()
            if not ds or ds in seen:
                continue
            seen.add(ds)
            uniq.append(ds)
        fields.append("domains_json=?")
        params.append(json.dumps(uniq, ensure_ascii=False))
    if status is not None:
        fields.append("status=?")
        params.append((status or "").strip())
    if not_before is not None:
        fields.append("not_before=?")
        params.append(not_before)
    if not_after is not None:
        fields.append("not_after=?")
        params.append(not_after)
    if renew_at is not None:
        fields.append("renew_at=?")
        params.append(renew_at)
    if last_error is not None:
        fields.append("last_error=?")
        params.append((last_error or "").strip())
    if not fields:
        return
    fields.append("updated_at=datetime('now')")
    with connect(db_path) as conn:
        conn.execute(
            f"UPDATE certificates SET {', '.join(fields)} WHERE id=?",
            (*params, int(cert_id)),
        )
        conn.commit()


def delete_certificate(cert_id: int, db_path: str = DEFAULT_DB_PATH) -> None:
    with connect(db_path) as conn:
        conn.execute("DELETE FROM certificates WHERE id=?", (int(cert_id),))
        conn.commit()


def delete_certificates_by_site(site_id: int, db_path: str = DEFAULT_DB_PATH) -> int:
    with connect(db_path) as conn:
        cur = conn.execute("DELETE FROM certificates WHERE site_id=?", (int(site_id),))
        conn.commit()
        return int(cur.rowcount or 0)


def delete_certificates_by_node(node_id: int, db_path: str = DEFAULT_DB_PATH) -> int:
    with connect(db_path) as conn:
        cur = conn.execute("DELETE FROM certificates WHERE node_id=?", (int(node_id),))
        conn.commit()
        return int(cur.rowcount or 0)


def list_tasks(
    node_id: Optional[int] = None,
    status: Optional[str] = None,
    limit: int = 50,
    db_path: str = DEFAULT_DB_PATH,
) -> List[Dict[str, Any]]:
    sql = "SELECT * FROM tasks"
    params: List[Any] = []
    clauses: List[str] = []
    if node_id is not None:
        clauses.append("node_id=?")
        params.append(int(node_id))
    if status is not None:
        clauses.append("status=?")
        params.append((status or "").strip())
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(int(limit))
    with connect(db_path) as conn:
        rows = conn.execute(sql, tuple(params)).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        d["payload"] = _json_loads(str(d.get("payload_json") or "{}"), {})
        d["result"] = _json_loads(str(d.get("result_json") or "{}"), {})
        out.append(d)
    return out


def get_task(task_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM tasks WHERE id=?", (int(task_id),)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["payload"] = _json_loads(str(d.get("payload_json") or "{}"), {})
    d["result"] = _json_loads(str(d.get("result_json") or "{}"), {})
    return d


def add_task(
    node_id: int,
    task_type: str,
    payload: Optional[Dict[str, Any]] = None,
    status: str = "queued",
    progress: int = 0,
    result: Optional[Dict[str, Any]] = None,
    error: str = "",
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO tasks(node_id, type, payload_json, status, progress, result_json, error, created_at, updated_at) "
            "VALUES(?,?,?,?,?,?,?,datetime('now'),datetime('now'))",
            (
                int(node_id),
                (task_type or "").strip(),
                _json_dumps(payload or {}, "{}"),
                (status or "queued").strip(),
                int(progress or 0),
                _json_dumps(result or {}, "{}"),
                (error or "").strip(),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def update_task(
    task_id: int,
    status: Optional[str] = None,
    progress: Optional[int] = None,
    result: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> None:
    fields: List[str] = []
    params: List[Any] = []
    if status is not None:
        fields.append("status=?")
        params.append((status or "").strip())
    if progress is not None:
        fields.append("progress=?")
        params.append(int(progress))
    if result is not None:
        fields.append("result_json=?")
        params.append(_json_dumps(result or {}, "{}"))
    if error is not None:
        fields.append("error=?")
        params.append((error or "").strip())
    if not fields:
        return
    fields.append("updated_at=datetime('now')")
    with connect(db_path) as conn:
        conn.execute(
            f"UPDATE tasks SET {', '.join(fields)} WHERE id=?",
            (*params, int(task_id)),
        )
        conn.commit()


# =========================
# Auth / RBAC
# =========================

def _ensure_builtin_roles_conn(conn: sqlite3.Connection) -> None:
    for name, info in BUILTIN_ROLE_DEFS.items():
        desc = str(info.get("description") or "").strip()
        perms = _normalize_permissions(info.get("permissions") or [])
        perms_json = json.dumps(perms, ensure_ascii=False)
        builtin = 1 if bool(info.get("builtin")) else 0
        row = conn.execute("SELECT id, builtin FROM roles WHERE name=?", (name,)).fetchone()
        if row:
            role_id = int(row["id"])
            is_builtin = int(row["builtin"] or 0) == 1
            if is_builtin:
                conn.execute(
                    "UPDATE roles SET description=?, permissions_json=?, builtin=?, updated_at=datetime('now') WHERE id=?",
                    (desc, perms_json, builtin, role_id),
                )
            continue
        conn.execute(
            "INSERT INTO roles(name, description, permissions_json, builtin, created_at, updated_at) "
            "VALUES(?,?,?,?,datetime('now'),datetime('now'))",
            (name, desc, perms_json, builtin),
        )


def ensure_builtin_roles(db_path: str = DEFAULT_DB_PATH) -> None:
    with connect(db_path) as conn:
        _ensure_builtin_roles_conn(conn)
        conn.commit()


def _parse_role_row(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    perms = _json_loads(str(d.get("permissions_json") or "[]"), [])
    if not isinstance(perms, list):
        perms = []
    d["permissions"] = _normalize_permissions(perms)
    d["builtin"] = bool(d.get("builtin") or 0)
    return d


def list_roles(db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM roles ORDER BY builtin DESC, id ASC").fetchall()
    return [_parse_role_row(r) for r in rows]


def get_role_by_id(role_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM roles WHERE id=?", (int(role_id),)).fetchone()
    return _parse_role_row(row) if row else None


def get_role_by_name(name: str, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    role_name = str(name or "").strip()
    if not role_name:
        return None
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM roles WHERE name=?", (role_name,)).fetchone()
    return _parse_role_row(row) if row else None


def upsert_role(
    name: str,
    permissions: List[str],
    description: str = "",
    builtin: bool = False,
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    role_name = str(name or "").strip()
    if not role_name:
        raise ValueError("role name required")
    perms = _normalize_permissions(permissions or [])
    payload = json.dumps(perms, ensure_ascii=False)
    desc = str(description or "").strip()
    builtin_flag = 1 if bool(builtin) else 0
    with connect(db_path) as conn:
        row = conn.execute("SELECT id FROM roles WHERE name=?", (role_name,)).fetchone()
        if row:
            role_id = int(row["id"])
            conn.execute(
                "UPDATE roles SET description=?, permissions_json=?, builtin=?, updated_at=datetime('now') WHERE id=?",
                (desc, payload, builtin_flag, role_id),
            )
            conn.commit()
            return role_id
        cur = conn.execute(
            "INSERT INTO roles(name, description, permissions_json, builtin, created_at, updated_at) "
            "VALUES(?,?,?,?,datetime('now'),datetime('now'))",
            (role_name, desc, payload, builtin_flag),
        )
        conn.commit()
        return int(cur.lastrowid)


def count_users(enabled_only: bool = False, db_path: str = DEFAULT_DB_PATH) -> int:
    sql = "SELECT COUNT(1) FROM users"
    params: Tuple[Any, ...] = ()
    if enabled_only:
        sql += " WHERE enabled=1"
    with connect(db_path) as conn:
        row = conn.execute(sql, params).fetchone()
    return int(row[0] if row else 0)


def _parse_user_row(row: sqlite3.Row, include_secret: bool = False) -> Dict[str, Any]:
    d = dict(row)
    policy = _json_loads(str(d.get("policy_json") or "{}"), {})
    if not isinstance(policy, dict):
        policy = {}
    d["policy"] = policy
    role_perms = _json_loads(str(d.get("role_permissions_json") or "[]"), [])
    if not isinstance(role_perms, list):
        role_perms = []
    d["role_permissions"] = _normalize_permissions(role_perms)
    d["enabled"] = bool(d.get("enabled") or 0)
    if not include_secret:
        d.pop("salt_b64", None)
        d.pop("hash_b64", None)
        d.pop("iterations", None)
    return d


def list_users(include_disabled: bool = True, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    sql = (
        "SELECT u.*, r.name AS role_name, r.permissions_json AS role_permissions_json "
        "FROM users u LEFT JOIN roles r ON r.id=u.role_id"
    )
    params: List[Any] = []
    if not include_disabled:
        sql += " WHERE u.enabled=1"
    sql += " ORDER BY u.id ASC"
    with connect(db_path) as conn:
        rows = conn.execute(sql, tuple(params)).fetchall()
    return [_parse_user_row(r, include_secret=False) for r in rows]


def get_user_auth_record_by_username(username: str, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    name = str(username or "").strip()
    if not name:
        return None
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT u.*, r.name AS role_name, r.permissions_json AS role_permissions_json "
            "FROM users u LEFT JOIN roles r ON r.id=u.role_id WHERE u.username=?",
            (name,),
        ).fetchone()
    return _parse_user_row(row, include_secret=True) if row else None


def get_user_auth_record_by_id(user_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT u.*, r.name AS role_name, r.permissions_json AS role_permissions_json "
            "FROM users u LEFT JOIN roles r ON r.id=u.role_id WHERE u.id=?",
            (int(user_id),),
        ).fetchone()
    return _parse_user_row(row, include_secret=True) if row else None


def create_user_record(
    username: str,
    salt_b64: str,
    hash_b64: str,
    iterations: int,
    role_id: int,
    enabled: bool = True,
    expires_at: Optional[str] = None,
    policy: Optional[Dict[str, Any]] = None,
    created_by: str = "",
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    uname = str(username or "").strip()
    if not uname:
        raise ValueError("username required")
    payload = _json_dumps(policy or {}, "{}")
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO users("
            "username, salt_b64, hash_b64, iterations, role_id, enabled, expires_at, "
            "policy_json, created_by, created_at, updated_at"
            ") VALUES(?,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'))",
            (
                uname,
                str(salt_b64 or "").strip(),
                str(hash_b64 or "").strip(),
                int(iterations or 120000),
                int(role_id),
                1 if bool(enabled) else 0,
                str(expires_at or "").strip() or None,
                payload,
                str(created_by or "").strip(),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def update_user_record(
    user_id: int,
    username: Optional[str] = None,
    salt_b64: Optional[str] = None,
    hash_b64: Optional[str] = None,
    iterations: Optional[int] = None,
    role_id: Optional[int] = None,
    enabled: Optional[bool] = None,
    expires_at: Optional[str] = None,
    policy: Optional[Dict[str, Any]] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> None:
    fields: List[str] = []
    params: List[Any] = []
    if username is not None:
        fields.append("username=?")
        params.append(str(username or "").strip())
    if salt_b64 is not None:
        fields.append("salt_b64=?")
        params.append(str(salt_b64 or "").strip())
    if hash_b64 is not None:
        fields.append("hash_b64=?")
        params.append(str(hash_b64 or "").strip())
    if iterations is not None:
        fields.append("iterations=?")
        params.append(int(iterations or 120000))
    if role_id is not None:
        fields.append("role_id=?")
        params.append(int(role_id))
    if enabled is not None:
        fields.append("enabled=?")
        params.append(1 if bool(enabled) else 0)
    if expires_at is not None:
        fields.append("expires_at=?")
        params.append(str(expires_at or "").strip() or None)
    if policy is not None:
        fields.append("policy_json=?")
        params.append(_json_dumps(policy or {}, "{}"))
    if not fields:
        return
    fields.append("updated_at=datetime('now')")
    params.append(int(user_id))
    with connect(db_path) as conn:
        conn.execute(
            f"UPDATE users SET {', '.join(fields)} WHERE id=?",
            tuple(params),
        )
        conn.commit()


def delete_user_record(user_id: int, db_path: str = DEFAULT_DB_PATH) -> int:
    with connect(db_path) as conn:
        cur = conn.execute("DELETE FROM users WHERE id=?", (int(user_id),))
        conn.commit()
        return int(cur.rowcount or 0)


def touch_user_login(user_id: int, db_path: str = DEFAULT_DB_PATH) -> None:
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE users SET last_login_at=datetime('now'), updated_at=datetime('now') WHERE id=?",
            (int(user_id),),
        )
        conn.commit()


def upsert_rule_owner_map(
    node_id: int,
    pool: Dict[str, Any],
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    """Upsert node rule ownership map from pool endpoints.

    rule_key aligns with stats history key (currently endpoint.listen).
    The mapping is intentionally retained even when rules are later deleted,
    so historical traffic accounting for sub-accounts does not rollback.
    """
    try:
        nid = int(node_id)
    except Exception:
        nid = 0
    if nid <= 0 or not isinstance(pool, dict):
        return 0

    eps = pool.get("endpoints")
    if not isinstance(eps, list):
        return 0

    rows: List[Tuple[int, str, int, str]] = []
    seen: set[str] = set()
    for ep in eps:
        if not isinstance(ep, dict):
            continue
        key = str(ep.get("listen") or "").strip()
        if not key or key in seen:
            continue
        seen.add(key)

        ex = ep.get("extra_config")
        if not isinstance(ex, dict):
            ex = {}
        try:
            owner_user_id = int(ex.get("owner_user_id") or 0)
        except Exception:
            owner_user_id = 0
        owner_username = str(ex.get("owner_username") or "").strip()
        if owner_user_id <= 0 and (not owner_username):
            continue
        rows.append((nid, key, max(0, owner_user_id), owner_username))

    if not rows:
        return 0

    affected = 0
    with connect(db_path) as conn:
        for nid0, key, uid, uname in rows:
            cur = conn.execute(
                "SELECT id, owner_user_id, owner_username FROM rule_owner_map WHERE node_id=? AND rule_key=? LIMIT 1",
                (nid0, key),
            )
            ex = cur.fetchone()
            if ex:
                try:
                    ex_uid = int(ex["owner_user_id"] or 0)
                except Exception:
                    ex_uid = 0
                ex_uname = str(ex["owner_username"] or "").strip()
                if ex_uid == int(uid) and ex_uname == str(uname or "").strip():
                    conn.execute(
                        "UPDATE rule_owner_map SET last_seen_at=datetime('now'), active=1 WHERE id=?",
                        (int(ex["id"]),),
                    )
                else:
                    conn.execute(
                        "UPDATE rule_owner_map "
                        "SET owner_user_id=?, owner_username=?, last_seen_at=datetime('now'), active=1 "
                        "WHERE id=?",
                        (int(uid), str(uname or "").strip(), int(ex["id"])),
                    )
                affected += 1
                continue
            conn.execute(
                "INSERT INTO rule_owner_map("
                "node_id, rule_key, owner_user_id, owner_username, first_seen_at, last_seen_at, active"
                ") VALUES(?,?,?,?,datetime('now'),datetime('now'),1)",
                (int(nid0), str(key), int(uid), str(uname or "").strip()),
            )
            affected += 1
        conn.commit()
    return int(affected)


def sum_user_rule_traffic_bytes(
    user_id: int,
    node_ids: Optional[List[int]] = None,
    since_ts_ms: Optional[int] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    """Sum rule traffic deltas for one user from owned rules history.

    Computation:
    - resolve owned (node_id, rule_key) from rule_owner_map
    - for each key, read samples in window and accumulate positive deltas
      against previous sample (counter reset => take current as delta)
    """
    try:
        uid = int(user_id)
    except Exception:
        uid = 0
    if uid <= 0:
        return 0

    cutoff = int(since_ts_ms or 0)
    scoped_nodes: Optional[set[int]] = None
    if node_ids is not None:
        scoped_nodes = set()
        for nid in node_ids:
            try:
                v = int(nid)
            except Exception:
                continue
            if v > 0:
                scoped_nodes.add(v)
        if not scoped_nodes:
            return 0

    total = 0
    with connect(db_path) as conn:
        sql = "SELECT node_id, rule_key FROM rule_owner_map WHERE owner_user_id=?"
        params: List[Any] = [uid]
        if scoped_nodes is not None:
            marks = ",".join("?" for _ in scoped_nodes)
            sql += f" AND node_id IN ({marks})"
            params.extend(sorted(list(scoped_nodes)))
        keys = conn.execute(sql, tuple(params)).fetchall()

        for row in keys:
            try:
                nid = int(row["node_id"] or 0)
            except Exception:
                nid = 0
            key = str(row["rule_key"] or "").strip()
            if nid <= 0 or not key:
                continue

            prev_total: Optional[int] = None
            if cutoff > 0:
                r0 = conn.execute(
                    "SELECT rx_bytes, tx_bytes FROM rule_stats_samples "
                    "WHERE node_id=? AND rule_key=? AND ts_ms<? "
                    "ORDER BY ts_ms DESC LIMIT 1",
                    (nid, key, cutoff),
                ).fetchone()
                if r0:
                    try:
                        prev_total = int(r0["rx_bytes"] or 0) + int(r0["tx_bytes"] or 0)
                    except Exception:
                        prev_total = None

                rows = conn.execute(
                    "SELECT rx_bytes, tx_bytes FROM rule_stats_samples "
                    "WHERE node_id=? AND rule_key=? AND ts_ms>=? "
                    "ORDER BY ts_ms ASC",
                    (nid, key, cutoff),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT rx_bytes, tx_bytes FROM rule_stats_samples "
                    "WHERE node_id=? AND rule_key=? "
                    "ORDER BY ts_ms ASC",
                    (nid, key),
                ).fetchall()

            for r in rows:
                try:
                    cur_total = int(r["rx_bytes"] or 0) + int(r["tx_bytes"] or 0)
                except Exception:
                    cur_total = 0
                if cur_total < 0:
                    cur_total = 0
                if prev_total is None:
                    prev_total = cur_total
                    continue
                if cur_total >= prev_total:
                    delta = cur_total - prev_total
                else:
                    # Counter reset/restart: treat current as new incremental bytes.
                    delta = cur_total
                if delta > 0:
                    total += int(delta)
                prev_total = cur_total
    return int(total)


def sum_rule_traffic_bytes(
    node_ids: Optional[List[int]] = None,
    since_ts_ms: Optional[int] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    sql = "SELECT COALESCE(SUM(rx_bytes + tx_bytes), 0) FROM rule_stats_samples WHERE 1=1"
    params: List[Any] = []
    cutoff = int(since_ts_ms or 0)
    if cutoff > 0:
        sql += " AND ts_ms>=?"
        params.append(cutoff)
    if node_ids is not None:
        ids: List[int] = []
        for nid in node_ids:
            try:
                val = int(nid)
            except Exception:
                continue
            if val > 0:
                ids.append(val)
        if not ids:
            return 0
        marks = ",".join("?" for _ in ids)
        sql += f" AND node_id IN ({marks})"
        params.extend(ids)
    with connect(db_path) as conn:
        row = conn.execute(sql, tuple(params)).fetchone()
    try:
        return int(row[0] or 0) if row else 0
    except Exception:
        return 0


def create_user_token_record(
    user_id: int,
    token_sha256: str,
    name: str = "",
    scopes: Optional[List[str]] = None,
    expires_at: Optional[str] = None,
    created_by: str = "",
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO user_tokens("
            "user_id, token_sha256, name, scopes_json, expires_at, created_by, created_at"
            ") VALUES(?,?,?,?,?,?,datetime('now'))",
            (
                int(user_id),
                str(token_sha256 or "").strip(),
                str(name or "").strip(),
                _json_dumps(_normalize_permissions(scopes or []), "[]"),
                str(expires_at or "").strip() or None,
                str(created_by or "").strip(),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)


def list_user_tokens(user_id: int, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id, user_id, name, scopes_json, expires_at, last_used_at, created_by, created_at, revoked_at "
            "FROM user_tokens WHERE user_id=? ORDER BY id DESC",
            (int(user_id),),
        ).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        scopes = _json_loads(str(d.get("scopes_json") or "[]"), [])
        if not isinstance(scopes, list):
            scopes = []
        d["scopes"] = _normalize_permissions(scopes)
        out.append(d)
    return out


def revoke_user_token(token_id: int, db_path: str = DEFAULT_DB_PATH) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            "UPDATE user_tokens SET revoked_at=datetime('now') WHERE id=? AND revoked_at IS NULL",
            (int(token_id),),
        )
        conn.commit()
        return int(cur.rowcount or 0)


def touch_user_token(token_sha256: str, db_path: str = DEFAULT_DB_PATH) -> None:
    digest = str(token_sha256 or "").strip()
    if not digest:
        return
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE user_tokens SET last_used_at=datetime('now') WHERE token_sha256=?",
            (digest,),
        )
        conn.commit()


def get_user_token_by_sha256(token_sha256: str, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    digest = str(token_sha256 or "").strip()
    if not digest:
        return None
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM user_tokens WHERE token_sha256=?",
            (digest,),
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    scopes = _json_loads(str(d.get("scopes_json") or "[]"), [])
    if not isinstance(scopes, list):
        scopes = []
    d["scopes"] = _normalize_permissions(scopes)
    return d
