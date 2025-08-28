# src/dp/vrf_drbg.py
from __future__ import annotations
import hmac, hashlib, json, math
from typing import Tuple, Optional, Dict, Any

class HmacDRBG:
    """
    Minimal deterministic DRBG for DP noise using HMAC-SHA256.
    NOT a general-purpose RNG.
    """
    def __init__(self, secret_key: bytes):
        if not isinstance(secret_key, (bytes, bytearray)) or len(secret_key) == 0:
            raise ValueError("HmacDRBG requires a non-empty secret key")
        self.secret = bytes(secret_key)

    def derive_block(self, label: str, data: Dict[str, Any]) -> bytes:
        msg = json.dumps(
            {"label": label, "data": data},
            sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hmac.new(self.secret, msg, hashlib.sha256).digest()

    def uniform01(self, label: str, data: Dict[str, Any]) -> float:
        """Return U in (0,1) deterministically from one 256-bit block."""
        block = self.derive_block(label, data)
        n = int.from_bytes(block, "big")
        denom = (1 << 256)
        u = (n + 0.5) / denom
        # clamp to open interval
        if u <= 0.0:
            u = 1.0 / denom
        if u >= 1.0:
            u = 1.0 - 1.0 / denom
        return u

def laplace_inverse_cdf(u: float, b: float) -> float:
    if not (0.0 < u < 1.0):
        raise ValueError("u must be in (0,1)")
    if b <= 0.0:
        raise ValueError("b must be > 0")
    # Laplace(0,b) inverse CDF
    if u <= 0.5:
        return b * math.log(2.0 * u)
    return -b * math.log(2.0 * (1.0 - u))

def laplace_sample(epsilon: float, sensitivity: float, seed_material: Dict[str, Any], secret_key: bytes) -> float:
    """Deterministic Laplace noise using HMAC-DRBG."""
    if epsilon <= 0.0:
        raise ValueError("epsilon must be > 0")
    if sensitivity <= 0.0:
        raise ValueError("sensitivity must be > 0")
    b = sensitivity / epsilon
    drbg = HmacDRBG(secret_key=secret_key)
    u = drbg.uniform01("laplace", seed_material)
    return laplace_inverse_cdf(u, b)

def derive_seed_commit(seed_material: Dict[str, Any], secret_key: bytes) -> Tuple[bytes, str]:
    """
    Returns (seed_bytes, commitment_hex). seed = HMAC(secret, JSON(seed_material)),
    commit = SHA256(seed).
    """
    msg = json.dumps(seed_material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    seed = hmac.new(secret_key, msg, hashlib.sha256).digest()
    return seed, hashlib.sha256(seed).hexdigest()

def default_seed_material(
    *,
    request_id: str,
    timestamp_iso: str,
    policy_version: str,
    mechanism: str,
    epsilon: float,
    sensitivity: float,
    user_role: int,
    query_hash: str,
    model_id: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "request_id": request_id,
        "timestamp": timestamp_iso,
        "policy_version": policy_version,
        "mechanism": mechanism,
        "epsilon": float(epsilon),
        "sensitivity": float(sensitivity),
        "user_role": int(user_role),
        "query_hash": query_hash,
        "model_id": model_id or "",
    }
    if extra:
        base["extra"] = extra
    return base

def mix_with_beacon(seed_material: Dict[str, Any], beacon_entropy: Optional[str]) -> Dict[str, Any]:
    """Optionally mix a public randomness beacon (string) into seed material."""
    if not beacon_entropy:
        return seed_material
    m = dict(seed_material)
    m["beacon"] = hashlib.sha256(beacon_entropy.encode("utf-8")).hexdigest()
    return m
