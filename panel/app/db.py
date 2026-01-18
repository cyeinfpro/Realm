import os
import sqlite3
import time
from typing import Any, Dict, List, Optional


def _db_path() -> str:
    return os.environ.get("PANEL_DB", "/opt/realm-panel/data/panel.db")


def connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(_db_path()), exist_ok=True)
    conn = sqlite3.connect(_db_path())
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS nodes(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            base_url TEXT NOT NULL,
            api_key TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def list_nodes() -> List[Dict[str, Any]]:
    conn = connect()
    rows = conn.execute("SELECT * FROM nodes ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_node(node_id: int) -> Optional[Dict[str, Any]]:
    conn = connect()
    row = conn.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def add_node(name: str, base_url: str, api_key: str) -> Dict[str, Any]:
    conn = connect()
    ts = int(time.time())
    cur = conn.execute(
        "INSERT INTO nodes(name, base_url, api_key, created_at) VALUES(?,?,?,?)",
        (name, base_url.rstrip("/"), api_key, ts),
    )
    conn.commit()
    node_id = cur.lastrowid
    conn.close()
    return get_node(int(node_id))  # type: ignore


def update_node(node_id: int, name: str, base_url: str, api_key: str) -> Dict[str, Any]:
    conn = connect()
    conn.execute(
        "UPDATE nodes SET name=?, base_url=?, api_key=? WHERE id=?",
        (name, base_url.rstrip("/"), api_key, node_id),
    )
    conn.commit()
    conn.close()
    n = get_node(node_id)
    if not n:
        raise KeyError("node not found")
    return n


def delete_node(node_id: int) -> None:
    conn = connect()
    conn.execute("DELETE FROM nodes WHERE id=?", (node_id,))
    conn.commit()
    conn.close()
