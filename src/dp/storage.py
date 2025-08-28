# src/dp/storage.py
from __future__ import annotations
import os, sqlite3, time
from typing import Optional

class ProofStore:
    """
    Persist proofs either in a sqlite file (sqlite:///path.db) or a directory of JSON files.
    """
    def __init__(self, url_or_path: str):
        self.kind = "dir"
        self.path = url_or_path
        if url_or_path.startswith("sqlite:///"):
            self.kind = "sqlite"
            self.path = url_or_path[len("sqlite:///"):]
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            self._init_sqlite(self.path)
        else:
            os.makedirs(url_or_path, exist_ok=True)

    def _init_sqlite(self, path: str):
        con = sqlite3.connect(path)
        cur = con.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS dp_proofs(
            request_id TEXT PRIMARY KEY,
            proof_json TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        """)
        con.commit(); con.close()

    def save(self, request_id: str, proof_json: str):
        ts = int(time.time())
        if self.kind == "sqlite":
            con = sqlite3.connect(self.path)
            cur = con.cursor()
            cur.execute("INSERT OR REPLACE INTO dp_proofs(request_id,proof_json,created_at) VALUES(?,?,?)",
                        (request_id, proof_json, ts))
            con.commit(); con.close()
        else:
            fp = os.path.join(self.path, f"{request_id}.json")
            with open(fp, "w", encoding="utf-8") as f:
                f.write(proof_json)

    def get(self, request_id: str) -> Optional[str]:
        if self.kind == "sqlite":
            con = sqlite3.connect(self.path)
            cur = con.cursor()
            cur.execute("SELECT proof_json FROM dp_proofs WHERE request_id=?", (request_id,))
            row = cur.fetchone()
            con.close()
            return row[0] if row else None
        fp = os.path.join(self.path, f"{request_id}.json")
        if not os.path.exists(fp):
            return None
        with open(fp, "r", encoding="utf-8") as f:
            return f.read()
