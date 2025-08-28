import time
from src.security.redis_client import r

def allow(role: int, key: str, capacity: int, refill_per_sec: float) -> bool:
    """
    Token bucket: capacity, refill rate. Key is composed by caller (e.g., f"rl:{role}:{user}").
    """
    now = time.time()
    pipe = r().pipeline()
    # Ensure fields exist
    pipe.hsetnx(key, "tokens", capacity)
    pipe.hsetnx(key, "ts", now)
    pipe.hmget(key, "tokens", "ts")
    res = pipe.execute()[-1]
    tokens, ts = res
    tokens = float(tokens); ts = float(ts)
    # refill
    tokens = min(capacity, tokens + (now - ts) * refill_per_sec)
    if tokens < 1.0:
        r().hmset(key, {"tokens": tokens, "ts": now})
        return False
    tokens -= 1.0
    r().hmset(key, {"tokens": tokens, "ts": now})
    r().expire(key, 3600)
    return True
