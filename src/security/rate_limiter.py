import time
from threading import Lock
from typing import Dict


class RoleRateLimiter:
    def __init__(self):
        self._lock = Lock()
        # track {role: (tokens, last_ts)}
        self._state: Dict[int, tuple[float, float]] = {}

    def allow(self, role: int, rpm: int) -> bool:
        now = time.time()
        with self._lock:
            tokens, last = self._state.get(role, (float(rpm), now))
            # replenish tokens
            elapsed = now - last
            tokens = min(float(rpm), tokens + (elapsed * (rpm / 60.0)))
            if tokens >= 1.0:
                tokens -= 1.0
                self._state[role] = (tokens, now)
                return True
            else:
                self._state[role] = (tokens, now)
                return False


_limiter = RoleRateLimiter()


def allow_request_for_role(role: int, rpm: int) -> bool:
    return _limiter.allow(role, rpm)
