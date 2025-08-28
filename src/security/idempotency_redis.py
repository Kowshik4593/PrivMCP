import json
from src.security.redis_client import r
from src.config import settings

def get_or_set(request_id: str, response_obj: dict) -> tuple[dict, bool]:
    key = f"idem:{request_id}"
    prev = r().get(key)
    if prev is not None:
        return json.loads(prev), True
    r().set(key, json.dumps(response_obj), ex=600, nx=True)
    return response_obj, False
