from threading import Lock
from typing import Any, Dict


class IdempotencyStore:
    def __init__(self):
        self._lock = Lock()
        self._store: Dict[str, Any] = {}

    def get(self, key: str):
        with self._lock:
            return self._store.get(key)

    def set(self, key: str, value: Any):
        with self._lock:
            self._store[key] = value


_store = IdempotencyStore()


def get_cached_response(key: str):
    return _store.get(key)


def cache_response(key: str, value: Any):
    _store.set(key, value)
