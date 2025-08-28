from typing import Optional

from src.llm.client import call_llm_guarded


def groq_completion(prompt: str, model: Optional[str] = None, timeout: Optional[float] = None) -> str:
    """Call Groq/OpenAI-compatible backend via guarded client."""
    return call_llm_guarded(prompt, timeout=timeout, model=model)
