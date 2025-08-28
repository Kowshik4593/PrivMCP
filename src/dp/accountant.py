"""Simple in-memory DP accountant for tracking consumed epsilon per principal.

This is intentionally lightweight for the PoC: it stores per-user cumulative epsilon
and provides helpers to request/charge epsilon. In production this should be
replaced with a persistent, auditable accountant (Redis/DB) and rate-limited.
"""
from threading import Lock
from typing import Dict


class DPAccountant:
    def __init__(self):
        self._lock = Lock()
        self._consumed: Dict[str, float] = {}

    def get_consumed(self, principal: str) -> float:
        with self._lock:
            return float(self._consumed.get(principal, 0.0))

    def charge(self, principal: str, epsilon: float) -> bool:
        """Charge epsilon to a principal. Returns True if success.

        This simple implementation always allows spending, but records it.
        Production should enforce budgets and rate limits.
        """
        if epsilon <= 0:
            return True
        with self._lock:
            self._consumed[principal] = self._consumed.get(principal, 0.0) + float(epsilon)
        return True


# Global singleton for module-level usage
_accountant = DPAccountant()


def get_accountant() -> DPAccountant:
    # If settings request a sqlite-backed accountant, lazily swap it.
    try:
        from src.config import get_settings
        settings = get_settings()
        db = getattr(settings, "DP_ACCOUNTANT_DB", None)
        if db:
            # Lazily import the sqlite-backed implementation
            from src.dp.sql_accountant import SQLiteDPAccountant
            return SQLiteDPAccountant(db)
    except Exception:
        pass
    return _accountant
