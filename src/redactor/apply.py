# src/redactor/apply.py
from __future__ import annotations

from typing import List, Dict, Any
import re

REDACTION = {
    "PERSON": "[NAME]",
    "MRN": "[MRN]",
    "SSN": "[SSN]",
    "DATE": "[DATE]",
    "ID": "[ID]",
    "PHONE": "[PHONE]",
    "EMAIL": "[EMAIL]",
}


def normalize_entities(entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize and dedupe entities by (type, value, start, end).

    Expected entity shape: {"type": str, "value": str, "start": int, "end": int, "score": float}
    """
    seen = set()
    out: List[Dict[str, Any]] = []
    for e in sorted(entities, key=lambda x: (x.get("start", 0), -len(x.get("value", "")))):
        key = (e.get("type"), e.get("value"))
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "type": e.get("type"),
            "value": e.get("value"),
            "start": e.get("start"),
            "end": e.get("end"),
            "score": float(e.get("score", 1.0)),
        })
    return out


def redact(text: str, entities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Apply typed placeholders and return redacted text and metadata.

    This function preserves surrounding punctuation and whitespace where possible.
    """
    ents = normalize_entities(entities)
    # Sort by start asc to rebuild text
    ents_sorted = sorted(ents, key=lambda x: x["start"] if x.get("start") is not None else -1)

    out = []
    last = 0
    for e in ents_sorted:
        s = e.get("start") or 0
        ed = e.get("end") or s
        if s < last:
            # overlapping entity; skip or truncate
            continue
        out.append(text[last:s])
        placeholder = REDACTION.get(e.get("type"), "[REDACTED]")
        out.append(placeholder)
        last = ed
    out.append(text[last:])

    redacted_text = "".join(out)

    # Simple safety checks
    # If any entity score is below 0.5, flag low confidence
    scores = [e.get("score", 1.0) for e in ents]
    low_confidence = any(s < 0.5 for s in scores)

    # residual PHI heuristic: digits that look like IDs remain
    residual_digits = bool(re.search(r"\d{4,}", redacted_text))

    return {
        "redacted_text": redacted_text,
        "phi_entities": ents,
        "low_confidence": low_confidence,
        "residual_digits": residual_digits,
    }


def safety_gate_check(redaction_result: Dict[str, Any], threshold: float = 0.15) -> bool:
    """Return True if the redaction passes the safety gate and an LLM call may proceed.

    - If low confidence in any detection, fail.
    - If residual digits that look like identifiers remain, fail.
    - Allow caller to tune threshold later (currently unused, placeholder).
    """
    if redaction_result.get("low_confidence"):
        return False
    if redaction_result.get("residual_digits"):
        return False
    return True
