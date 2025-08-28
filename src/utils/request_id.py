from contextvars import ContextVar
from typing import Optional
import uuid

# Context variable to hold the current request id
_request_id: ContextVar[Optional[str]] = ContextVar("request_id", default=None)


def new_request_id() -> str:
    rid = str(uuid.uuid4())
    _request_id.set(rid)
    return rid


def set_request_id(rid: str) -> None:
    _request_id.set(rid)


def get_request_id() -> Optional[str]:
    return _request_id.get()
