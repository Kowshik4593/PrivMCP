#!/usr/bin/env python3
import sys, json
from pathlib import Path

from src.dp.proof import DpProof, verify_dp_proof
from src.audit.verify import get_verifier

def main():
    if len(sys.argv) != 2:
        print("usage: dp_verify.py <proof.json>", file=sys.stderr); sys.exit(2)
    data = Path(sys.argv[1]).read_text(encoding="utf-8")
    proof = DpProof.from_json(data)
    verifier = None
    try:
        verifier = get_verifier()
    except Exception:
        verifier = None
    ok, reason = verify_dp_proof(proof, signer_verify=verifier)
    print(json.dumps({"ok": ok, "reason": reason}, indent=2))
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
