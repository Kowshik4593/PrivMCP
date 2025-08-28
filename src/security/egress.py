import json
from pathlib import Path
from urllib.parse import urlparse
from src.audit.logger import log_query_audit

_ALLOWLIST_PATH = Path("./policy/egress.allow.json")

def _load():
    if _ALLOWLIST_PATH.exists():
        return set(json.loads(_ALLOWLIST_PATH.read_text()))
    return set()

def _save(domains: set[str]):
    _ALLOWLIST_PATH.write_text(json.dumps(sorted(list(domains)), indent=2))

def is_allowed(url: str) -> bool:
    host = urlparse(url).hostname or ""
    domains = _load()
    return any(host == d or host.endswith("." + d) for d in domains)

def add_domain(domain: str, actor: str):
    d = _load(); before = set(d)
    d.add(domain); _save(d)
    log_query_audit(user=actor, role=0, query=f"egress_add:{domain}", dp_report=None, zkp_proof=None, allowed=True)

def remove_domain(domain: str, actor: str):
    d = _load(); before = set(d)
    if domain in d:
        d.remove(domain); _save(d)
        log_query_audit(user=actor, role=0, query=f"egress_remove:{domain}", dp_report=None, zkp_proof=None, allowed=True)
