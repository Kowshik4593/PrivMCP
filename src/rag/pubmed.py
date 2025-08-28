# src/rag/pubmed.py

import requests
from xml.etree import ElementTree

def pubmed_search(query, max_results=2):
    """Search PubMed for the query, return a list of {title, url, snippet} dicts."""
    base = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/"
    # 1. Search for article IDs
    resp = requests.get(base + "esearch.fcgi", params={
        "db": "pubmed", "retmode": "json", "retmax": max_results, "term": query
    })
    ids = resp.json().get("esearchresult", {}).get("idlist", [])
    if not ids:
        return []
    # 2. Fetch summaries
    summary = requests.get(base + "esummary.fcgi", params={
        "db": "pubmed", "retmode": "json", "id": ",".join(ids)
    }).json()
    out = []
    for pmid in ids:
        doc = summary.get("result", {}).get(pmid, {})
        if doc:
            url = f"https://pubmed.ncbi.nlm.nih.gov/{pmid}/"
            snippet = doc.get("title", "")
            out.append({"pmid": pmid, "title": doc.get("title", ""), "url": url, "snippet": snippet})
    return out
