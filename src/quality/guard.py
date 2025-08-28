def enforce(output: dict) -> dict:
    # If RAG was used, require citations
    rag_used = bool(output.get("reasoning_trace", {}).get("retrieval", True))
    cits = output.get("citations", [])
    if rag_used and len(cits) == 0:
        output["llm_response"] = (
            "Evidence currently unavailable. Providing a de-identified generic guidance summary. "
            "Share PubMed PMIDs to attach citations."
        )
        output.setdefault("warnings", []).append("missing_citations_fallback")
    return output
