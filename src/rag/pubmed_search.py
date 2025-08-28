# src/rag/pubmed_search.py
import requests
from requests.adapters import HTTPAdapter, Retry
from typing import List, Dict, Optional
from src.config import get_settings
from src.connectors.pubmed import search_pubmed


def pubmed_search(
    query: str,
    max_results: Optional[int] = None,
    timeout: Optional[int] = None,
) -> List[Dict]:
    """
    Lightweight PubMed search using E-utilities.
    Backwards-compatible signature: accepts optional `timeout` kwarg.
    Returns a list of {pmid, title, url, snippet}.
    """
    settings = get_settings()
    k = getattr(settings, "RAG_MAX_RESULTS", 5) if max_results is None else max(0, min(max_results, 10))
    tout = getattr(settings, "PUBMED_TIMEOUT_SEC", 15.0) if timeout is None else max(1, timeout)
    if not query or k == 0:
        return []

    email = getattr(settings, "PUBMED_EMAIL", None)
    api_key = getattr(settings, "PUBMED_API_KEY", None)

    try:
        res = search_pubmed(query, email=email, api_key=api_key, timeout=tout)
        # Trim to k results
        return res[:k]
    except Exception as e:
        print("PubMed search failed:", e)
        return []
