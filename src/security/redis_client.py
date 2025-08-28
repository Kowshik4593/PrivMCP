import redis
from src.config import settings

_redis = redis.Redis.from_url(getattr(settings, "REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)

def r():
    return _redis
