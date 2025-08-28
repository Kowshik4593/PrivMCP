# src/redactor/main.py
from typing import Tuple, List
from .hybrid import HybridPHIRedactor

_redactor = HybridPHIRedactor()

def redact_phi(text: str) -> Tuple[str, List[str]]:
    res = _redactor.redact(text)
    return res["redacted_text"], res["phi_entities"]

def batch_redact_phi(texts: List[str]) -> List[Tuple[str, List[str]]]:
    return [redact_phi(t) for t in texts]
