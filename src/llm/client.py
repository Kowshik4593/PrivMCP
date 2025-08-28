"""Guarded LLM client utilities.

Provides:
- call_llm_guarded(prompt, timeout=None, model=None): guarded LLM call using shared session + retries.
- prompt_hash(prompt): sha256 hex of prompt (for logging/audit keys only).
"""

import hashlib
import json
import time
from typing import Any, Dict, Optional

import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.config import get_settings


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


class ExternalServiceError(Exception):
    pass


_settings = get_settings()

# Configure timeouts/retries based on debug flag
_is_debug = bool(os.getenv("DEBUG", "0") == "1")
LLM_TIMEOUT = float(getattr(_settings, "GROQ_TIMEOUT_SEC", 15))
RETRIES = 1 if _is_debug else 2
BACKOFF = 0.2 if _is_debug else 0.5

# Shared session with retries
_session = requests.Session()
_session.mount(
    "https://",
    HTTPAdapter(max_retries=Retry(total=RETRIES, backoff_factor=BACKOFF, status_forcelist=[502, 503, 504])),
)


def call_llm_guarded(prompt: str, *, timeout: Optional[float] = None, model: Optional[str] = None, max_retries: int = 2) -> str:
    """Guarded LLM call with prompt hashing, timeout, and retry semantics.

    Callers MUST ensure redaction/safety gates have passed before invoking this.
    """
    base = str(_settings.GROQ_BASE_URL).rstrip("/")
    url = f"{base}/chat/completions"
    req_timeout = float(timeout or _settings.GROQ_TIMEOUT_SEC)

    payload: Dict[str, Any] = {
        "model": model or getattr(_settings, "GROQ_MODEL", "gpt-4o"),
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "max_tokens": 800,
    }

    headers = {"Content-Type": "application/json"}
    if getattr(_settings, "GROQ_API_KEY", None):
        headers["Authorization"] = f"Bearer {_settings.GROQ_API_KEY}"

    # Simple retry loop for transient errors
    last_err = None
    for attempt in range(1, max_retries + 1):
        try:
            resp = _session.post(url, headers=headers, json=payload, timeout=req_timeout)
            resp.raise_for_status()
            data = resp.json()
            choices = data.get("choices") or []
            if not choices:
                raise ExternalServiceError("LLM response missing choices")
            content = choices[0].get("message", {}).get("content", "")
            return content or ""
        except requests.Timeout as te:
            last_err = ExternalServiceError(f"LLM timeout after {req_timeout}s: {te}")
            time.sleep(0.5 * attempt)
        except requests.RequestException as re:
            last_err = ExternalServiceError(f"LLM request error: {re}")
            time.sleep(0.5 * attempt)
        except Exception as e:
            last_err = ExternalServiceError(f"LLM error: {e}")
            time.sleep(0.5 * attempt)

    raise last_err or ExternalServiceError("LLM unknown error")


def prompt_hash(prompt: str) -> str:
    return _sha256(prompt)
