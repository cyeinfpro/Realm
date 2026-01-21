import os
import sqlite3
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_DB_PATH = "/etc/realm-panel/panel.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  base_url TEXT NOT NULL,
  api_key TEXT NOT NULL,
  verify_tls INTEGER NOT NULL DEFAULT 0,
  -- Agent push-report state (agent -> panel)
  last_seen_at TEXT,
  last_report_json TEXT,
  -- Desired config stored on panel, delivered to agent on next report
  desired_pool_json TEXT,
  desired_pool_version INTEGER NOT NULL DEFAULT 0,
  agent_ack_version INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
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
    """Set desired pool and bump version. Returns (new_version, pool)."""
    import json

    payload = json.dumps(pool, ensure_ascii=False)
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT desired_pool_version FROM nodes WHERE id=?",
            (node_id,),
        ).fetchone()
        cur_ver = int(row[0]) if row else 0
        new_ver = cur_ver + 1
        conn.execute(
            "UPDATE nodes SET desired_pool_json=?, desired_pool_version=? WHERE id=?",
            (payload, new_ver, node_id),
        )
        conn.commit()
        return new_ver, pool


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


def add_node(
    name: str,
    base_url: str,
    api_key: str,
    verify_tls: bool = False,
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO nodes(name, base_url, api_key, verify_tls) VALUES(?,?,?,?)",
            (name.strip(), base_url.strip().rstrip('/'), api_key.strip(), 1 if verify_tls else 0),
        )
        conn.commit()
        return int(cur.lastrowid)


def delete_node(node_id: int, db_path: str = DEFAULT_DB_PATH) -> None:
    with connect(db_path) as conn:
        conn.execute("DELETE FROM nodes WHERE id=?", (node_id,))
        conn.commit()
