import os
import sqlite3
import json
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_DB_PATH = os.getenv("REALM_PANEL_DB", "/etc/realm-panel/panel.db")

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
  agent_reported_version TEXT NOT NULL DEFAULT '',
  agent_update_state TEXT NOT NULL DEFAULT '',
  agent_update_msg TEXT NOT NULL DEFAULT '',
  agent_update_at TEXT,
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
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

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
"""


def ensure_parent_dir(path: str) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)


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
        if "agent_reported_version" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN agent_reported_version TEXT NOT NULL DEFAULT ''")
        if "agent_update_state" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN agent_update_state TEXT NOT NULL DEFAULT ''")
        if "agent_update_msg" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN agent_update_msg TEXT NOT NULL DEFAULT ''")
        if "agent_update_at" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN agent_update_at TEXT")


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
        conn.commit()


def set_agent_rollout_all(
    desired_version: str,
    update_id: str,
    state: str = "queued",
    msg: str = "",
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    """Set desired agent version for all nodes, returns affected row count."""
    ver = (desired_version or "").strip()
    uid = (update_id or "").strip()
    st = (state or "").strip()
    m = (msg or "").strip()
    with connect(db_path) as conn:
        cur = conn.execute(
            "UPDATE nodes SET desired_agent_version=?, desired_agent_update_id=?, agent_update_state=?, agent_update_msg=?, agent_update_at=datetime('now')",
            (ver, uid, st, m),
        )
        conn.commit()
        return int(cur.rowcount or 0)


def update_agent_status(
    node_id: int,
    agent_reported_version: Optional[str] = None,
    state: Optional[str] = None,
    msg: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> None:
    fields = []
    vals = []
    if agent_reported_version is not None:
        fields.append("agent_reported_version=?")
        vals.append(str(agent_reported_version))
    if state is not None:
        fields.append("agent_update_state=?")
        vals.append(str(state))
        fields.append("agent_update_at=datetime('now')")
    if msg is not None:
        fields.append("agent_update_msg=?")
        vals.append(str(msg))
        fields.append("agent_update_at=datetime('now')")
    if not fields:
        return
    vals.append(int(node_id))
    with connect(db_path) as conn:
        # Whitelist validation to avoid accidental SQL injection if this code is modified.
        _allowed = {'agent_reported_version', 'agent_update_state', 'agent_update_msg', 'agent_update_at'}
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

        vals.append(int(node_id))
        conn.execute(
            f"UPDATE nodes SET {', '.join(fields)} WHERE id=?",
            tuple(vals),
        )
        conn.commit()


def get_last_report(node_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    node = get_node(node_id, db_path=db_path)
    if not node:
        return None
    raw = node.get("last_report_json")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


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
    node = get_node(node_id, db_path=db_path)
    if not node:
        return 0, None
    ver = int(node.get("desired_pool_version") or 0)
    raw = node.get("desired_pool_json")
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


def _parse_node_row(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    caps = _json_loads(str(d.get("capabilities_json") or "{}"), {})
    if not isinstance(caps, dict):
        caps = {}
    d["capabilities"] = caps
    return d


def list_nodes(db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM nodes ORDER BY id DESC").fetchall()
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


def get_node(node_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
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
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    role_val = (role or "").strip().lower() or "normal"
    if role_val not in ("normal", "website"):
        role_val = "normal"
    try:
        caps_json = json.dumps(capabilities or {}, ensure_ascii=False)
    except Exception:
        caps_json = "{}"
    with connect(db_path) as conn:
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


def delete_site(site_id: int, db_path: str = DEFAULT_DB_PATH) -> None:
    with connect(db_path) as conn:
        conn.execute("DELETE FROM sites WHERE id=?", (int(site_id),))
        conn.commit()


def delete_sites_by_node(node_id: int, db_path: str = DEFAULT_DB_PATH) -> int:
    with connect(db_path) as conn:
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
    status: Optional[str] = None,
    not_before: Optional[str] = None,
    not_after: Optional[str] = None,
    renew_at: Optional[str] = None,
    last_error: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> None:
    fields: List[str] = []
    params: List[Any] = []
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
