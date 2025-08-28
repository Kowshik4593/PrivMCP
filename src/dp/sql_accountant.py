"""SQLite-backed DP accountant for simple persistent epsilon accounting.

This small implementation stores per-principal consumed epsilon and enforces
per-principal budgets when requested. It's intentionally minimal and uses
SQLite from the standard library for portability.
"""
import sqlite3
from threading import Lock
from typing import Optional
from pathlib import Path


class SQLiteDPAccountant:
    def __init__(self, db_path: str | Path):
        self._db_path = str(db_path)
        self._lock = Lock()
        self._ensure_db()

    def _ensure_db(self):
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS dp_account (
                    principal TEXT PRIMARY KEY,
                    consumed REAL NOT NULL DEFAULT 0.0,
                    updated_ts INTEGER
                )
                """
            )
            conn.commit()

    def get_consumed(self, principal: str) -> float:
        with self._lock, sqlite3.connect(self._db_path) as conn:
            cur = conn.execute("SELECT consumed FROM dp_account WHERE principal = ?", (principal,))
            row = cur.fetchone()
            return float(row[0]) if row else 0.0

    def charge(self, principal: str, epsilon: float, budget: Optional[float] = None) -> bool:
        """Attempt to charge epsilon for principal. If budget provided, enforce it.

        Returns True if charge applied, False if it would exceed budget.
        """
        if epsilon <= 0:
            return True
        with self._lock, sqlite3.connect(self._db_path) as conn:
            cur = conn.execute("SELECT consumed FROM dp_account WHERE principal = ?", (principal,))
            row = cur.fetchone()
            current = float(row[0]) if row else 0.0
            new = current + float(epsilon)
            if budget is not None and new > float(budget):
                return False
            if row:
                conn.execute("UPDATE dp_account SET consumed = ?, updated_ts = strftime('%s','now') WHERE principal = ?", (new, principal))
            else:
                conn.execute("INSERT INTO dp_account(principal, consumed, updated_ts) VALUES (?, ?, strftime('%s','now'))", (principal, new))
            conn.commit()
            return True
