import json, hashlib
from src.security.redis_client import r
from src.config import settings

def cache_key(query_hash: str, policy_version: str, model_version: str) -> str:
    return f"res:{hashlib.sha256(f'{query_hash}:{policy_version}:{model_version}'.encode()).hexdigest()}"

def get(k: str):
    v = r().get(k)
    return None if v is None else json.loads(v)

def set_(k: str, obj: dict, ttl: int | None = None):
    r().set(k, json.dumps(obj), ex=ttl or settings.CACHE_TTL_SEC)
