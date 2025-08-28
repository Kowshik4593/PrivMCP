"""Simple RBAC/ABAC policy module with versioning.

Provides a tiny policy evaluation function used by the service layer.
Also provides a lightweight fast-fail safety gate for obvious exfil/injection patterns.
"""
import re
from typing import Tuple

POLICY_VERSION = "2025-08-26-v1"


# Simple patterns that should never be processed (exfil, injections, shells)
_BLOCK_PATTERNS = [
    r"\b(drop\s+table|truncate\s+table|delete\s+from)\b",
    r"\b(curl|wget|Invoke-WebRequest|powershell\s+-enc)\b",
    r"\b(pastebin\.|transfer\.sh|ngrok\.io|discordapp\.com/api/webhooks)\b",
    r"\b(base64\s+-d|certutil\s+-decode)\b",
]

_BLOCK_RE = re.compile("|".join(_BLOCK_PATTERNS), re.IGNORECASE)


def is_query_safe(text: str) -> Tuple[bool, str]:
    """Return (safe, reason). Fast-fail on simple regex matches indicating dangerous payloads.

    This is deliberately simple and conservative: it should be cheap to evaluate and
    block obviously dangerous instructions before they reach networked backends.
    """
    if not text:
        return True, ""
    if _BLOCK_RE.search(text):
        return False, "Blocked by safety policy: potentially dangerous instructions detected."
    return True, ""


def check_access(user_role: int, min_role: int) -> Tuple[bool, str]:
    """Return (allowed, reason). Current policy: role must be >= min_role."""
    if user_role >= min_role:
        return True, f"role>={min_role}"
    return False, f"role<{min_role}"


# Optional policy-as-code bundle loader. If a bundle path is configured we load it
import json, hashlib
from pathlib import Path
from src.config import get_settings

_settings = get_settings()
_POLICY = {}
_POLICY_SHA256 = "0" * 64
_BUNDLE_PATH = getattr(_settings, "POLICY_BUNDLE_PATH", None)
if _BUNDLE_PATH:
    try:
        _POLICY = json.loads(Path(_BUNDLE_PATH).read_text(encoding="utf-8"))
        _POLICY_BYTES = json.dumps(_POLICY, sort_keys=True).encode()
        _POLICY_SHA256 = hashlib.sha256(_POLICY_BYTES).hexdigest()
    except Exception:
        _POLICY = {}
        _POLICY_SHA256 = "0" * 64

def policy() -> dict:
    return _POLICY

def current_policy_version() -> str:
    v = _POLICY.get("version", POLICY_VERSION)
    return f"{v}@{_POLICY_SHA256[:12]}"
