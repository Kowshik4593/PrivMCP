import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import List, Dict, Optional
from src.config import get_settings


_settings = get_settings()
_is_debug = bool(os.getenv("DEBUG", "0") == "1") if 'os' in globals() else False

RETRIES = 1 if _is_debug else getattr(_settings, "PUBMED_RETRIES", 2)
BACKOFF = 0.2 if _is_debug else 0.5
TIMEOUT = float(getattr(_settings, "RAG_TIMEOUT_SEC", getattr(_settings, "RAG_TIMEOUT_SEC", 7)))

retry = Retry(
    total=RETRIES,
    connect=RETRIES,
    read=RETRIES,
    backoff_factor=BACKOFF,
    status_forcelist=(429, 500, 502, 503, 504),
    allowed_methods=frozenset(["GET", "POST"]),
)

session = requests.Session()
session.mount("https://", HTTPAdapter(max_retries=retry))
session.mount("http://", HTTPAdapter(max_retries=retry))


def search_pubmed(query: str, *, email: str, api_key: str | None, timeout: float | None = None) -> List[Dict]:
    params = {"db": "pubmed", "term": query, "retmode": "json", "retmax": "5"}
    if api_key:
        params["api_key"] = api_key
    if email:
        params["email"] = email
    tout = timeout or TIMEOUT

    esearch = session.get(
        "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi",
        params=params,
        timeout=tout,
    )
    esearch.raise_for_status()
    ids = esearch.json().get("esearchresult", {}).get("idlist", [])
    if not ids:
        return []
    s = session.get(
        "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esummary.fcgi",
        params={"db": "pubmed", "id": ",".join(ids), "retmode": "json"},
        timeout=tout,
    )
    s.raise_for_status()
    data = s.json().get("result", {})
    out = []
    for pmid in ids:
        item = data.get(pmid, {})
        out.append({"pmid": pmid, "title": item.get("title", ""), "url": f"https://pubmed.ncbi.nlm.nih.gov/{pmid}/"})
    return out
