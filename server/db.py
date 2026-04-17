import sqlite3
from typing import List, Optional, Set


def get_connection(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str) -> None:
    with get_connection(db_path) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS peers (
                id          INTEGER  PRIMARY KEY AUTOINCREMENT,
                name        TEXT     NOT NULL,
                private_key TEXT     NOT NULL,
                public_key  TEXT     NOT NULL,
                ip_address  TEXT     NOT NULL UNIQUE,
                created_at  TEXT     NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_peers_name ON peers(name);
        """)


def add_peer(
    db_path: str,
    name: str,
    private_key: str,
    public_key: str,
    ip_address: str,
) -> int:
    with get_connection(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO peers (name, private_key, public_key, ip_address) VALUES (?, ?, ?, ?)",
            (name, private_key, public_key, ip_address),
        )
        return cur.lastrowid


def get_peer(db_path: str, peer_id: int) -> Optional[sqlite3.Row]:
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM peers WHERE id = ?", (peer_id,)).fetchone()
        return row


def list_peers(db_path: str) -> List[sqlite3.Row]:
    with get_connection(db_path) as conn:
        return conn.execute("SELECT * FROM peers ORDER BY id").fetchall()


def delete_peer(db_path: str, peer_id: int) -> bool:
    with get_connection(db_path) as conn:
        cur = conn.execute("DELETE FROM peers WHERE id = ?", (peer_id,))
        return cur.rowcount > 0


def ip_addresses_in_use(db_path: str) -> Set[str]:
    with get_connection(db_path) as conn:
        rows = conn.execute("SELECT ip_address FROM peers").fetchall()
        return {row["ip_address"] for row in rows}
