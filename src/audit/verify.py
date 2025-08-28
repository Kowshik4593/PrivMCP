from __future__ import annotations
import hashlib, hmac, json, os
from typing import Any, Dict, List, Optional, Tuple, Iterator, Iterable
import pathlib
from datetime import datetime, timezone
import json, os, pathlib
from typing import Iterable, List, Dict, Any, Optional

ZERO = "0" * 64

def _canonical_json(d: Dict[str, Any]) -> str:
    # Stable, minimal JSON for hashing
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def _compute_entry_hash(prev_hash: str, entry_wo_hash: Dict[str, Any]) -> str:
    material = (prev_hash or ZERO) + _canonical_json(entry_wo_hash)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()

def _verify_hmac(entry_hash: str, entry: Dict[str, Any], hmac_key: Optional[str]) -> bool:
    sig = entry.get("hmac")
    if not sig:
        return True  # nothing to verify
    if not hmac_key:
        return False
    expect = hmac.new(hmac_key.encode("utf-8"), entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expect, sig)

def verify_records(records: List[Dict[str, Any]], hmac_key: Optional[str] = None) -> Dict[str, Any]:
    if not records:
        return {"ok": True, "verified": True, "length": 0, "tip": None}

    prev = ZERO
    for i, raw in enumerate(records):
        # recompute hash on a copy with entry_hash removed
        e = dict(raw)
        saved_hash = e.pop("entry_hash", "")
        if not saved_hash:
            return {"ok": True, "verified": False, "fail_index": i, "reason": "missing entry_hash"}

        if e.get("prev_hash") != prev:
            return {
                "ok": True, "verified": False, "fail_index": i,
                "reason": "prev_hash mismatch", "expected_prev": prev, "found_prev": e.get("prev_hash"),
            }

        computed = _compute_entry_hash(prev, e)
        if computed != saved_hash:
            return {"ok": True, "verified": False, "fail_index": i, "reason": "entry_hash mismatch"}

        if not _verify_hmac(computed, raw, hmac_key):
            return {"ok": True, "verified": False, "fail_index": i, "reason": "bad hmac"}

        prev = saved_hash

    return {"ok": True, "verified": True, "length": len(records), "tip": prev}

def _read_jsonl(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out

def verify_file(path: str, hmac_key: Optional[str] = None) -> Dict[str, Any]:
    if not path or not os.path.exists(path):
        return {"ok": False, "verified": False, "error": "not_found", "path": path}
    return verify_records(_read_jsonl(path), hmac_key=hmac_key)
def _parse_iso_utc(s: str) -> datetime:
    # accepts '...Z' or '+00:00'
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _to_utc(dt: datetime) -> datetime:
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def iter_audit_range(
    start_utc: datetime,
    end_utc: datetime,
    *,
    limit: Optional[int] = 100000,
    newest_first: bool = True,
) -> Iterable[Dict[str, Any]]:
    """Yield audit entries whose timestamp is within [start_utc, end_utc].
    Returns the newest entries first by default and applies limit after sorting.
    """
    # Resolve path from settings or env (your existing logic preserved)
    try:
        from src.config import get_settings as _get_settings
        s = _get_settings()
        audit_path = getattr(s, "AUDIT_LOG_PATH", None)
    except Exception:
        audit_path = None
    if not audit_path:
        audit_path = os.getenv("PRIVMCP_AUDIT_LOG_PATH", "./audit.jsonl")

    p = pathlib.Path(audit_path)
    if not p.exists():
        return []

    matched: List[Dict[str, Any]] = []
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            ts = rec.get("timestamp")
            if not ts or not isinstance(ts, str):
                continue
            try:
                ts_dt = _parse_iso_utc(ts)
            except Exception:
                continue
            if start_utc <= ts_dt <= end_utc:
                matched.append(rec)

    # Sort and slice
    matched.sort(key=lambda r: _parse_iso_utc(r["timestamp"]), reverse=newest_first)
    if limit and limit > 0 and len(matched) > limit:
        matched = matched[:limit]
    return matched


def get_verifier():
    """Return a simple verifier object with method verify(sig_bytes, payload)->bool
    or None if no public key configured.
    """
    try:
        from src.config import get_settings
        s = get_settings()
        pub_path = getattr(s, "AUDIT_PUBKEY_PATH", None)
        if not pub_path:
            return None
        from pathlib import Path
        pem = Path(pub_path).read_bytes()
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding
        public_key = serialization.load_pem_public_key(pem)

        class _Verifier:
            def __init__(self, key):
                self._key = key

            def verify(self, sig: bytes, payload: bytes) -> bool:
                try:
                    if hasattr(self._key, 'verifier'):
                        # older API
                        self._key.verify(sig, payload)
                        return True
                    # ECDSA vs RSA detection
                    if isinstance(self._key, ec.EllipticCurvePublicKey):
                        self._key.verify(sig, payload, ec.ECDSA(hashes.SHA256()))
                        return True
                    else:
                        self._key.verify(sig, payload, padding.PKCS1v15(), hashes.SHA256())
                        return True
                except Exception:
                    return False

        return _Verifier(public_key)
    except Exception:
        return None
