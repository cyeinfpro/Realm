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


def add_node(name: str, base_url: str, api_key: str, db_path: str = DEFAULT_DB_PATH) -> int:
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO nodes(name, base_url, api_key) VALUES(?,?,?)",
            (name.strip(), base_url.strip().rstrip('/'), api_key.strip()),
        )
        conn.commit()
        return int(cur.lastrowid)


def delete_node(node_id: int, db_path: str = DEFAULT_DB_PATH) -> None:
    with connect(db_path) as conn:
        conn.execute("DELETE FROM nodes WHERE id=?", (node_id,))
        conn.commit()
