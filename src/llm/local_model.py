def generate_completion(prompt: str) -> str:
    # simple, safe fallback: return the user prompt with a minimal preface
    head = prompt.strip()
    return head[:4000]  # avoid exploding outputs
