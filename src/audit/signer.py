from __future__ import annotations
import os
import hmac
import hashlib
import base64
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any

try:
    # settings loader is imported lazily/safely
    from src.config import get_settings
except Exception:  # pragma: no cover
    get_settings = None  # type: ignore


_SIGNER_SINGLETON: Optional["AuditSigner"] = None


class AuditSigner:
    """
    Lazy audit signer.
    - Supports HMAC-SHA256 when AUDIT_HMAC_KEY is set.
    - Publishes metadata for /audit/pubkey even if only a public key is configured.
    - Does NOT hard-depend on crypto libraries; if only PEM keys are present without
      an HMAC key, sign() will return None (verification can still be external).
    """

    def __init__(self) -> None:
        s = get_settings() if callable(get_settings) else None

        # Config
        self.algo: Optional[str] = None
        self.kid: Optional[str] = None
        self.created_at_iso: Optional[str] = None

        self.public_key_pem: Optional[str] = None
        self.private_key_pem: Optional[str] = None
        self._hmac_key_bytes: Optional[bytes] = None

        pub_path = getattr(s, "AUDIT_PUBKEY_PATH", None) if s else None
        priv_path = getattr(s, "AUDIT_PRIVKEY_PATH", None) if s else None
        hmac_key = getattr(s, "AUDIT_HMAC_KEY", None) if s else None
        algo_hint = getattr(s, "AUDIT_ALGO", None) if s else None
        kid = getattr(s, "AUDIT_KEY_ID", None) if s else None

        # Load public key (optional)
        if pub_path:
            p = Path(pub_path)
            if p.exists():
                self.public_key_pem = p.read_text(encoding="utf-8")
                # Prefer file mtime as created_at if available
                try:
                    ts = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc)
                    self.created_at_iso = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
                except Exception:
                    self.created_at_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Load private key (optional, but unused without crypto lib)
        if priv_path:
            q = Path(priv_path)
            if q.exists():
                self.private_key_pem = q.read_text(encoding="utf-8")
                if not self.created_at_iso:
                    try:
                        ts = datetime.fromtimestamp(q.stat().st_mtime, tz=timezone.utc)
                        self.created_at_iso = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
                    except Exception:
                        self.created_at_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Load HMAC key (enables signing without extra deps)
        if hmac_key:
            # Accept raw, hex, or base64
            hk = str(hmac_key).strip()
            try:
                if all(c in "0123456789abcdefABCDEF" for c in hk) and len(hk) % 2 == 0:
                    self._hmac_key_bytes = bytes.fromhex(hk)
                else:
                    # try base64
                    self._hmac_key_bytes = base64.b64decode(hk, validate=True)
            except Exception:
                # fall back to utf-8 bytes
                self._hmac_key_bytes = hk.encode("utf-8")

        # Algorithm resolution
        if algo_hint:
            self.algo = str(algo_hint)
        elif self._hmac_key_bytes:
            self.algo = "hmac-sha256"
        elif self.private_key_pem:
            # Without crypto parsing, expose a generic tag
            self.algo = "asymmetric-pem"
        elif self.public_key_pem:
            self.algo = "public-only"
        else:
            self.algo = None  # disabled

        # Key ID (kid): configured or derived from public key
        if kid:
            self.kid = str(kid)
        elif self.public_key_pem:
            digest = hashlib.sha256(self.public_key_pem.encode("utf-8")).hexdigest()
            self.kid = f"kid-{digest[:16]}"
        elif self._hmac_key_bytes:
            digest = hashlib.sha256(self._hmac_key_bytes).hexdigest()
            self.kid = f"hmac-{digest[:16]}"
        else:
            self.kid = None

        # Ensure created_at exists if any material is present
        if (self.public_key_pem or self.private_key_pem or self._hmac_key_bytes) and not self.created_at_iso:
            self.created_at_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ---- API ----

    def sign(self, data: bytes) -> Optional[str]:
        """
        Returns a hex signature if HMAC is configured; otherwise None.
        (Asymmetric signing omitted to avoid crypto dependency.)
        """
        if self._hmac_key_bytes:
            return hmac.new(self._hmac_key_bytes, data, hashlib.sha256).hexdigest()
        return None

    def public_info(self) -> Dict[str, Any]:
        return {
            "algo": self.algo,
            "public_key": self.public_key_pem,
            "kid": self.kid,
            "created_at": self.created_at_iso,
        }


def get_signer() -> Optional[AuditSigner]:
    """
    Lazy singleton. Returns None when no signing material is configured.
    Conditions for a non-None signer:
      - PRIVMCP_AUDIT_HMAC_KEY set, OR
      - PRIVMCP_AUDIT_PUBKEY_PATH or PRIVMCP_AUDIT_PRIVKEY_PATH points to an existing file
    """
    global _SIGNER_SINGLETON
    if _SIGNER_SINGLETON is not None:
        return _SIGNER_SINGLETON

    try:
        s = get_settings() if callable(get_settings) else None
        pub = getattr(s, "AUDIT_PUBKEY_PATH", None) if s else None
        priv = getattr(s, "AUDIT_PRIVKEY_PATH", None) if s else None
        hmk = getattr(s, "AUDIT_HMAC_KEY", None) if s else None

        has_pub = bool(pub and Path(pub).exists())
        has_priv = bool(priv and Path(priv).exists())
        has_hmac = bool(hmk)

        if not (has_pub or has_priv or has_hmac):
            _SIGNER_SINGLETON = None
            return None

        # Create and cache the singleton instance
        _SIGNER_SINGLETON = AuditSigner()
        return _SIGNER_SINGLETON
    except Exception:
        return None

