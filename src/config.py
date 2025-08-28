from functools import lru_cache
from pydantic import BaseModel
import os

class Settings(BaseModel):
    # LLM / Groq
    USE_GROQ_API: bool = (os.getenv("USE_GROQ_API", "0") == "1")
    GROQ_API_KEY: str | None = os.getenv("GROQ_API_KEY")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
    GROQ_BASE_URL: str = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")

    # RAG / PubMed
    RAG_MAX_RESULTS: int = int(os.getenv("RAG_MAX_RESULTS", "2"))
    RAG_TIMEOUT_SEC: int = int(os.getenv("RAG_TIMEOUT_SEC", "7"))
    PUBMED_EMAIL: str | None = os.getenv("PUBMED_EMAIL")  # optional, for NCBI etiquette

    # Request-level timeout for proxy endpoints (seconds)
    REQUEST_TIMEOUT_SEC: int = int(os.getenv("REQUEST_TIMEOUT_SEC", "8"))

    # LLM / GROQ timeout (seconds)
    GROQ_TIMEOUT_SEC: float = float(os.getenv("GROQ_TIMEOUT_SEC", "30"))

    # DP / Privacy
    DP_EPSILON: float = float(os.getenv("DP_EPSILON", "1.0"))

    # ZKP
    USE_ZKP: bool = (os.getenv("USE_ZKP", "0") == "1")

    # Misc
    DEBUG: bool = (os.getenv("DEBUG", "0") == "1")
    AUDIT_LOG_PATH: str = os.getenv("AUDIT_LOG_PATH", "audit_log.jsonl")

@lru_cache()
def get_settings() -> Settings:
    return Settings()

# backward-compat one-liner (so `from src.config import config` keeps working)
config = get_settings()
