import sqlite3
from pathlib import Path

DB = Path("tmp/usbay.db")


def get_conn():
    DB.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db():
    with get_conn() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS nonces (
            nonce TEXT PRIMARY KEY,
            timestamp INTEGER NOT NULL
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            action TEXT,
            decision TEXT,
            hash_prev TEXT,
            hash_current TEXT
        )
        """)


def nonce_exists(nonce):
    with get_conn() as conn:
        cur = conn.execute(
            "SELECT 1 FROM nonces WHERE nonce = ?",
            (nonce,)
        )
        return cur.fetchone() is not None


def store_nonce(nonce, timestamp):
    with get_conn() as conn:
        try:
            conn.execute(
                "INSERT INTO nonces (nonce, timestamp) VALUES (?, ?)",
                (nonce, int(timestamp))
            )
            return True
        except sqlite3.IntegrityError:
            return False


class NonceStore:
    def exists(self, nonce: str) -> bool:
        return nonce_exists(nonce)

    def store(self, nonce: str, ts: int) -> bool:
        return store_nonce(nonce, ts)

    def contains(self, nonce: str) -> bool:
        return self.exists(nonce)

    def add(self, nonce: str) -> bool:
        import time

        return self.store(nonce, int(time.time()))
