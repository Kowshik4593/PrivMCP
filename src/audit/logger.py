"""
src/audit/logger.py
Append-only, tamper-evident audit logger.

Each entry is a JSON object with these fields (minimal):
 - timestamp, user, role, query_hash, dp_hash, zkp_hash, allowed
 - prev_hash: hex of previous entry_hash
 - entry_hash: sha256(prev_hash + canonical_payload)
 - hmac (optional): HMAC-SHA256 over the entry when AUDIT_SIGNING_KEY_PATH is set

The logger is intentionally failure-tolerant: logging errors are annotated on the returned record.
"""

import hashlib
import hmac
import json
import os
import pathlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from src.config import get_settings
from src.utils.request_id import get_request_id
from src.audit.signer import get_signer


def _sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _safe_hash(obj: Optional[Any]) -> Optional[str]:
    if obj is None:
        return None
    try:
        return _sha256_str(json.dumps(obj, sort_keys=True, ensure_ascii=False))
    except Exception:
        return _sha256_str(str(obj))


def log_query_audit(
    user: str,
    role: int,
    query: str,
    dp_report: Optional[Dict[str, Any]],
    zkp_proof: Optional[Dict[str, Any]],
    allowed: bool,
    dp_merkle_root: Optional[str] = None,
    dp_proof_hash: Optional[str] = None,
) -> Dict[str, Any]:
    settings = get_settings()
    path = pathlib.Path(getattr(settings, "AUDIT_LOG_PATH", "audit.jsonl"))
    signing_key_path = getattr(settings, "AUDIT_SIGNING_KEY_PATH", None)

    record: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "user": user,
        "role": role,
    "request_id": get_request_id(),
        "query_hash": _sha256_str(query or ""),
    "dp_hash": _safe_hash(dp_report),
    "zkp_hash": _safe_hash(zkp_proof),
    "dp_merkle_root": dp_merkle_root,
    "dp_proof_hash": dp_proof_hash,
    # include small debug-friendly excerpts (non-sensitive): truncated JSON
    "dp_report_excerpt": (json.dumps(dp_report, ensure_ascii=False)[:256] if dp_report else None),
    "zkp_proof_excerpt": (json.dumps(zkp_proof, ensure_ascii=False)[:256] if zkp_proof else None),
        "allowed": allowed,
    }

    try:
        # Ensure parent directory exists
        if path.parent and str(path.parent) != "":
            path.parent.mkdir(parents=True, exist_ok=True)

        # Determine prev_hash from last entry if present
        prev_hash = "0" * 64
        if path.exists():
            try:
                with path.open("r", encoding="utf-8") as f:
                    last = None
                    for line in f:
                        line = line.strip()
                        if line:
                            last = line
                if last:
                    try:
                        last_obj = json.loads(last)
                        prev_hash = last_obj.get("entry_hash", prev_hash)
                    except Exception:
                        prev_hash = prev_hash
            except Exception:
                prev_hash = prev_hash

        # Compute entry hash over canonical payload
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        entry_hash = hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()
        record["prev_hash"] = prev_hash
        record["entry_hash"] = entry_hash

        # Optional HMAC signing
        if signing_key_path:
            try:
                sk = pathlib.Path(signing_key_path).read_bytes()
                sig = hmac.new(sk, json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"), hashlib.sha256).hexdigest()
                record["hmac"] = sig
            except Exception as e:  # pragma: no cover - signing optional
                record["hmac_error"] = str(e)

        # Optional asymmetric signature (if configured via AUDIT_PRIVKEY_PATH)
        try:
            s = get_signer()
            if s is not None:
                try:
                    record["signature_alg"] = s.alg
                    record["signature"] = s.sign(record["entry_hash"])
                except Exception as e:
                    record["signature_error"] = str(e)
        except Exception:
            # best-effort
            pass

        # Append to file and ensure durability (flush + fsync)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
            try:
                f.flush()
                os.fsync(f.fileno())
            except Exception:
                # best-effort: if fsync not available on platform, ignore
                pass
    except Exception as e:
        # Do not crash the request on logging errors; annotate the record and return
        record["write_error"] = str(e)

    return record
