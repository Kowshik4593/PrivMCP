import subprocess
import os
import hmac
import hashlib
from src.config import get_settings

SNARKJS_CMD = os.getenv("SNARKJS_CMD", "snarkjs")
VKEY_PATH = os.getenv("ZKP_VKEY_PATH", "verification_key.json")


def generate_proof(user_role: int, min_role: int, query_type: int):
    # If a real ZKP setup is present, integrate here.
    # Fallback: produce a lightweight HMAC-based receipt for the audit record.
    settings = get_settings()
    if getattr(settings, "USE_ZKP", False):
        # In production: call circom/snarkjs, write proof.json & public.json
        return {"protocol": "stub", "inputs": [user_role, min_role, query_type]}, ["1"]

    # HMAC-based receipt
    secret = getattr(settings, "AUDIT_SIGNING_KEY", None)
    payload = f"{user_role}:{min_role}:{query_type}".encode("utf-8")
    if secret:
        sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        return {"protocol": "hmac", "sig": sig, "inputs": [user_role, min_role, query_type]}, [sig]
    else:
        return {"protocol": "none", "inputs": [user_role, min_role, query_type]}, ["0"]


def verify_proof() -> bool:
    settings = get_settings()
    if not getattr(settings, "USE_ZKP", False):
        return True
    try:
        result = subprocess.run(
            [SNARKJS_CMD, "groth16", "verify", VKEY_PATH, "public.json", "proof.json"],
            capture_output=True, check=True,
        )
        return "OK" in result.stdout.decode()
    except Exception as e:
        print("ZKP verify_proof() error:", e)
        return False
