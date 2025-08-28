# src/dp/proof.py
from __future__ import annotations
import json, hashlib
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Tuple

from .merkle import merkle_root, merkle_path, verify_inclusion
from .vrf_drbg import derive_seed_commit, laplace_sample, default_seed_material, mix_with_beacon

def _sha256_json(obj: object) -> str:
    b = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b).hexdigest()

@dataclass
class DpProof:
    version: str
    mechanism: str
    epsilon: float
    sensitivity: float
    value_hash: str
    seed_commit: str
    noise: float
    noised_value: float
    leaf_hash: str
    merkle_root: str
    merkle_path: List[Dict[str, str]]
    audit_entry_hash: Optional[str] = None
    signature: Optional[str] = None  # hex bytes

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True)

    @staticmethod
    def from_json(s: str) -> "DpProof":
        return DpProof(**json.loads(s))

def build_leaf_object(**kwargs) -> dict:
    allowed = ["version","mechanism","epsilon","sensitivity","value_hash","seed_commit","noise","noised_value"]
    return {k: kwargs[k] for k in allowed}

def build_dp_proof(
    *,
    secret_key: bytes,
    mechanism: str,
    epsilon: float,
    sensitivity: float,
    original_value: Optional[float],
    request_id: str,
    timestamp_iso: str,
    policy_version: str,
    user_role: int,
    query_hash: str,
    model_id: Optional[str],
    beacon_entropy: Optional[str],
    audit_entry_hash: Optional[str],
    signer: Optional[object],
) -> Tuple[DpProof, float]:
    sm = default_seed_material(
        request_id=request_id, timestamp_iso=timestamp_iso, policy_version=policy_version,
        mechanism=mechanism, epsilon=epsilon, sensitivity=sensitivity,
        user_role=user_role, query_hash=query_hash, model_id=model_id
    )
    sm = mix_with_beacon(sm, beacon_entropy)
    seed, seed_commit = derive_seed_commit(sm, secret_key)
    noise = laplace_sample(epsilon, sensitivity, seed_material=sm, secret_key=secret_key)
    value_hash = "null" if original_value is None else _sha256_json(original_value)
    noised_value = (original_value if original_value is not None else 0.0) + float(noise)

    leaf_obj = build_leaf_object(
        version="dpv1",
        mechanism=mechanism,
        epsilon=epsilon,
        sensitivity=sensitivity,
        value_hash=value_hash,
        seed_commit=seed_commit,
        noise=float(noise),
        noised_value=float(noised_value),
    )
    leaf_json = json.dumps(leaf_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    leaf_hash = hashlib.sha256(leaf_json).hexdigest()

    # Single-leaf Merkle (expandable later)
    leaves = [leaf_json]
    root = merkle_root(leaves).hex()
    path = merkle_path(leaves, 0)

    signature = None
    if signer is not None:
        payload = (leaf_hash + "|" + root).encode("utf-8")
        try:
            sig = signer.sign(payload)
            if isinstance(sig, bytes):
                signature = sig.hex()
            else:
                # attempt to normalize base64/hex string
                try:
                    import base64
                    signature = base64.b64decode(sig).hex()
                except Exception:
                    try:
                        bytes.fromhex(sig)
                        signature = sig
                    except Exception:
                        signature = str(sig)
        except Exception:
            try:
                # some signers expect hex-string input
                sig = signer.sign(leaf_hash + "|" + root)
                if isinstance(sig, bytes):
                    signature = sig.hex()
                else:
                    signature = str(sig)
            except Exception:
                signature = None

    proof = DpProof(
        version="dpv1",
        mechanism=mechanism,
        epsilon=epsilon,
        sensitivity=sensitivity,
        value_hash=value_hash,
        seed_commit=seed_commit,
        noise=float(noise),
        noised_value=float(noised_value),
        leaf_hash=leaf_hash,
        merkle_root=root,
        merkle_path=path,
        audit_entry_hash=audit_entry_hash,
        signature=signature,
    )
    return proof, float(noised_value)

def verify_dp_proof(proof: DpProof, signer_verify: Optional[object]=None) -> Tuple[bool, str]:
    # Reconstruct leaf
    leaf_obj = build_leaf_object(
        version=proof.version,
        mechanism=proof.mechanism,
        epsilon=proof.epsilon,
        sensitivity=proof.sensitivity,
        value_hash=proof.value_hash,
        seed_commit=proof.seed_commit,
        noise=proof.noise,
        noised_value=proof.noised_value,
    )
    leaf_json = json.dumps(leaf_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if hashlib.sha256(leaf_json).hexdigest() != proof.leaf_hash:
        return False, "leaf hash mismatch"

    if not verify_inclusion(leaf_json, proof.merkle_root, proof.merkle_path):
        return False, "merkle inclusion failed"

    if proof.signature and signer_verify is not None:
        payload = (proof.leaf_hash + "|" + proof.merkle_root).encode("utf-8")
        try:
            sig_bytes = bytes.fromhex(proof.signature)
        except Exception:
            try:
                import base64
                sig_bytes = base64.b64decode(proof.signature)
            except Exception:
                sig_bytes = proof.signature.encode("utf-8")

        if not signer_verify.verify(sig_bytes, payload):
            return False, "signature invalid"

    return True, "ok"
