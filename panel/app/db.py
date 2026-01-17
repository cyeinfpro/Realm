from __future__ import annotations

import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Tuple

DB_PATH = os.getenv("REALM_PANEL_DB", "/etc/realm-panel/panel.db")


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _connect() as conn:
        c = conn.cursor()
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS agents (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              api_url TEXT NOT NULL,
              token TEXT NOT NULL,
              verify_tls INTEGER NOT NULL DEFAULT 0,
              added_at INTEGER NOT NULL,
              last_seen INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS pair_codes (
              code TEXT PRIMARY KEY,
              created_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              used INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        conn.commit()


def now() -> int:
    return int(time.time())


def create_pair_code(ttl_seconds: int = 600) -> Dict[str, Any]:
    import secrets

    init_db()
    code = f"{secrets.randbelow(1000000):06d}"
    created_at = now()
    expires_at = created_at + ttl_seconds
    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO pair_codes(code, created_at, expires_at, used) VALUES(?,?,?,0)",
            (code, created_at, expires_at),
        )
        conn.commit()
    return {"code": code, "created_at": created_at, "expires_at": expires_at, "used": 0}


def list_pair_codes(limit: int = 25) -> List[Dict[str, Any]]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT code, created_at, expires_at, used FROM pair_codes ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def claim_pair_code(code: str) -> bool:
    init_db()
    t = now()
    with _connect() as conn:
        row = conn.execute(
            "SELECT code, expires_at, used FROM pair_codes WHERE code=?", (code,)
        ).fetchone()
        if not row:
            return False
        if int(row["used"]) == 1:
            return False
        if int(row["expires_at"]) < t:
            return False
        conn.execute("UPDATE pair_codes SET used=1 WHERE code=?", (code,))
        conn.commit()
    return True


def upsert_agent(agent_id: str, name: str, api_url: str, token: str, verify_tls: bool = False) -> None:
    init_db()
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO agents(id, name, api_url, token, verify_tls, added_at, last_seen)
            VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
              name=excluded.name,
              api_url=excluded.api_url,
              token=excluded.token,
              verify_tls=excluded.verify_tls
            """,
            (agent_id, name, api_url, token, 1 if verify_tls else 0, now(), now()),
        )
        conn.commit()


def update_last_seen(agent_id: str, ts: int) -> None:
    init_db()
    with _connect() as conn:
        conn.execute("UPDATE agents SET last_seen=? WHERE id=?", (ts, agent_id))
        conn.commit()


def get_agent(agent_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, name, api_url, token, verify_tls, added_at, last_seen FROM agents WHERE id=?",
            (agent_id,),
        ).fetchone()
    return dict(row) if row else None


def list_agents() -> List[Dict[str, Any]]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, name, api_url, token, verify_tls, added_at, last_seen FROM agents ORDER BY added_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def delete_agent(agent_id: str) -> None:
    init_db()
    with _connect() as conn:
        conn.execute("DELETE FROM agents WHERE id=?", (agent_id,))
        conn.commit()
