import os
from dataclasses import dataclass
from typing import Optional

@dataclass
class Config:
    # LLM
    use_groq_api: bool = False
    groq_api_key: Optional[str] = None
    groq_model: str = "openai/gpt-oss-120b"

    # RAG / PubMed
    rag_max_results: int = 2
    rag_timeout_sec: int = 7

    # Privacy
    dp_epsilon: float = 1.0
    use_real_zkp: bool = False

    # Service
    debug: bool = False

def load_config() -> Config:
    return Config(
        use_groq_api = os.getenv("USE_GROQ_API", "0") == "1",
        groq_api_key = os.getenv("GROQ_API_KEY"),
    groq_model   = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"),
        rag_max_results = int(os.getenv("RAG_MAX_RESULTS", "2")),
        rag_timeout_sec = int(os.getenv("RAG_TIMEOUT_SEC", "7")),
        dp_epsilon   = float(os.getenv("DP_EPSILON", "1.0")),
        use_real_zkp = os.getenv("USE_ZKP", "0") == "1",
        debug        = os.getenv("DEBUG", "0") == "1",
    )
