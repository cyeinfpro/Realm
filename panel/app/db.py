import os
import sqlite3
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_DB_PATH = os.getenv("REALM_PANEL_DB", "/etc/realm-panel/panel.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  base_url TEXT NOT NULL,
  api_key TEXT NOT NULL,
  verify_tls INTEGER NOT NULL DEFAULT 0,
  -- Mark as "LAN-only" node (for reverse tunnel / intranet penetration)
  is_private INTEGER NOT NULL DEFAULT 0,
  group_name TEXT NOT NULL DEFAULT '默认分组',
  -- Agent push-report state (agent -> panel)
  last_seen_at TEXT,
  last_report_json TEXT,
  -- Desired config stored on panel, delivered to agent on next report
  desired_pool_json TEXT,
  desired_pool_version INTEGER NOT NULL DEFAULT 0,
  agent_ack_version INTEGER NOT NULL DEFAULT 0,

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
"""


def ensure_parent_dir(path: str) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    ensure_parent_dir(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(SCHEMA)
        conn.commit()


def ensure_db(db_path: str = DEFAULT_DB_PATH) -> None:
    init_db(db_path)
    with connect(db_path) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(nodes)").fetchall()}
        if "verify_tls" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN verify_tls INTEGER NOT NULL DEFAULT 0")
        if "is_private" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN is_private INTEGER NOT NULL DEFAULT 0")
        if "group_name" not in columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN group_name TEXT NOT NULL DEFAULT '默认分组'")
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
    agent_reported_version: str | None = None,
    state: str | None = None,
    msg: str | None = None,
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
        conn.execute(f"UPDATE nodes SET {', '.join(fields)} WHERE id=?", tuple(vals))
        conn.commit()


def update_node_report(
    node_id: int,
    report_json: str,
    last_seen_at: str,
    agent_ack_version: Optional[int] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> None:
    """Persist last report from an agent (push mode)."""
    with connect(db_path) as conn:
        if agent_ack_version is None:
            conn.execute(
                "UPDATE nodes SET last_seen_at=?, last_report_json=? WHERE id=?",
                (last_seen_at, report_json, node_id),
            )
        else:
            conn.execute(
                "UPDATE nodes SET last_seen_at=?, last_report_json=?, agent_ack_version=? WHERE id=?",
                (last_seen_at, report_json, int(agent_ack_version), node_id),
            )
        conn.commit()


def get_last_report(node_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    import json

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
    import json

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
    import json

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


def get_desired_pool(node_id: int, db_path: str = DEFAULT_DB_PATH) -> Tuple[int, Optional[Dict[str, Any]]]:
    import json

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
    try:
        yield conn
    finally:
        conn.close()


def list_nodes(db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM nodes ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


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
    return dict(row) if row else None


def get_node_by_api_key(api_key: str, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    api_key = (api_key or "").strip()
    if not api_key:
        return None
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM nodes WHERE api_key=?", (api_key,)).fetchone()
    return dict(row) if row else None


def get_node_by_base_url(base_url: str, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    base_url = (base_url or "").strip().rstrip('/')
    if not base_url:
        return None
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM nodes WHERE base_url=?", (base_url,)).fetchone()
    return dict(row) if row else None


def update_node_basic(
    node_id: int,
    name: str,
    base_url: str,
    api_key: str,
    verify_tls: bool = False,
    is_private: bool = False,
    group_name: str = '默认分组',
    db_path: str = DEFAULT_DB_PATH,
) -> None:
    """Update basic node fields without touching reports/pools."""
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE nodes SET name=?, base_url=?, api_key=?, verify_tls=?, is_private=?, group_name=? WHERE id=?",
            (
                (name or "").strip(),
                (base_url or "").strip().rstrip('/'),
                (api_key or "").strip(),
                1 if verify_tls else 0,
                1 if is_private else 0,
                (group_name or '默认分组').strip() or '默认分组',
                int(node_id),
            ),
        )
        conn.commit()


def add_node(
    name: str,
    base_url: str,
    api_key: str,
    verify_tls: bool = False,
    is_private: bool = False,
    group_name: str = '默认分组',
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO nodes(name, base_url, api_key, verify_tls, is_private, group_name) VALUES(?,?,?,?,?,?)",
            (name.strip(), base_url.strip().rstrip('/'), api_key.strip(), 1 if verify_tls else 0, 1 if is_private else 0, (group_name or '默认分组').strip() or '默认分组'),
        )
        conn.commit()
        return int(cur.lastrowid)


def delete_node(node_id: int, db_path: str = DEFAULT_DB_PATH) -> None:
    with connect(db_path) as conn:
        conn.execute("DELETE FROM nodes WHERE id=?", (node_id,))
        conn.commit()
