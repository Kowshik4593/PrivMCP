import json, time

def save_feedback(query: str, response: str, rating: int,
                  correction: str | None, user: str = "clinician"):
    rec = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "user": user,
        "query": query,
        "response": response,
        "rating": rating,
        "correction": correction,
    }
    with open("feedback.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")
    return {"status": "ok"}
