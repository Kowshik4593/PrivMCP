from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import logging
import sys

from pydantic import Field, HttpUrl, ValidationError, field_validator
try:
    from pydantic import EmailStr  # type: ignore
except Exception:  # pragma: no cover - fallback when email-validator isn't installed
    EmailStr = str  # type: ignore
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    # General
    ENV: str = Field("dev", description="dev|staging|prod")
    LOG_LEVEL: str = Field("INFO")

    # Audit
    AUDIT_LOG_PATH: Path = Field(..., description="Directory or file path for append-only audit logs")
    AUDIT_SIGNING_KEY_PATH: Path | None = Field(None, description="Optional signing key path for audit records")
    AUDIT_SIGNING_KEY: str | None = Field(None, description="Optional in-memory signing key (use with care)")
    # Optional HMAC key used when verifying audit entries (PRIVMCP_AUDIT_HMAC_KEY)
    AUDIT_HMAC_KEY: str | None = Field(None, description="Optional HMAC key for audit verification")

    # PubMed / RAG
    PUBMED_EMAIL: str = Field(..., description="Contact email for NCBI usage")
    PUBMED_API_KEY: str | None = None
    PUBMED_TIMEOUT_SEC: float = Field(15.0, gt=0.0)
    PUBMED_RETRIES: int = Field(2, ge=0)

    # LLM / GROQ
    GROQ_BASE_URL: HttpUrl = Field(..., description="Your LLM gateway/base URL")
    GROQ_API_KEY: str = Field(..., description="LLM API key")
    GROQ_TIMEOUT_SEC: float = Field(30.0, gt=0.0)
    GROQ_MODEL: str = Field("openai/gpt-oss-120b")
    USE_GROQ_API: bool = Field(False)

    # Redactor / NER
    HF_MODEL_PATH: Path | None = Field(None, description="Local HF model snapshot path")
    HF_MODEL_ID: str = Field("dslim/bert-base-NER")
    TRANSFORMERS_OFFLINE: bool = Field(True)
    # Backwards-compatible NER flags (used across the codebase)
    NER_USE_TRANSFORMER: bool = Field(False)
    NER_TRANSFORMER_MODEL: str = Field("dslim/bert-base-NER")

    # Security / rate limits
    ALLOWED_ORIGINS: list[str] = Field(default_factory=lambda: ["http://127.0.0.1:8000"])
    RATE_LIMIT_RPM_BY_ROLE: dict[int, int] = Field(default_factory=lambda: {1: 10, 3: 60, 5: 120})

    # EHR / external connectors
    FHIR_BASE_URL: str | None = Field(None, description="FHIR server base URL")

    # RAG / PubMed defaults used by pubmed_search
    RAG_MAX_RESULTS: int = Field(2)
    RAG_TIMEOUT_SEC: float = Field(7.0)
    PUBMED_TOOL: str = Field("PrivMCP")

    # Differential Privacy
    DP_EPSILON: float = Field(1.0)
    # DP accountant persistence (optional sqlite file). If set, the SQLite accountant will be used.
    DP_ACCOUNTANT_DB: str | None = Field(None, description="Optional path to sqlite DB for DP accounting")
    # Optional per-role epsilon budgets (role -> total epsilon allowed)
    DP_BUDGETS: dict[int, float] = Field(default_factory=lambda: {1: 10.0, 3: 50.0, 5: 100.0})

    # SLOs / error budget
    SLO_P95_MS_NO_LLM: int = Field(800, alias="PRIVMCP_SLO_P95_MS_NO_LLM")
    SLO_P95_MS_WITH_LLM: int = Field(4000, alias="PRIVMCP_SLO_P95_MS_WITH_LLM")
    ERROR_BUDGET_PCT_5XX: float = Field(0.1, alias="PRIVMCP_ERROR_BUDGET_PCT_5XX")

    # Redis / caching
    REDIS_URL: str = Field("redis://localhost:6379/0", alias="PRIVMCP_REDIS_URL")
    CACHE_TTL_SEC: int = Field(900, alias="PRIVMCP_CACHE_TTL_SEC")

    # Audit signing (asymmetric)
    AUDIT_SIGNING_ALG: str = Field("ECDSA_P256", alias="PRIVMCP_AUDIT_SIGNING_ALG")
    AUDIT_PRIVKEY_PATH: str | None = Field(None, alias="PRIVMCP_AUDIT_PRIVKEY_PATH")
    AUDIT_PUBKEY_PATH: str | None = Field(None, alias="PRIVMCP_AUDIT_PUBKEY_PATH")

    # Policy bundle path (json) and build/version
    POLICY_BUNDLE_PATH: str | None = Field(None, alias="PRIVMCP_POLICY_BUNDLE_PATH")
    BUILD_VERSION: str = "2025.08.26"

    # ZKP toggle
    USE_ZKP: bool = Field(False)
    # Verifiable DP
    DP_PROOF_ENABLED: bool = True
    DP_PROOF_STORE: str = "sqlite:///./data/dp_proofs.sqlite3"
    DP_SECRET_KEY: str = ""  # if empty, will fall back to AUDIT_PRIVKEY or another secret
    RNG_BEACON_URL: str = "" # optional URL to mix public randomness (ignored if empty)

    class Config:
        env_prefix = "PRIVMCP_"
        case_sensitive = False
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "allow"

    @field_validator("AUDIT_LOG_PATH")
    def ensure_audit_dir(cls, v: Path) -> Path:
        """Create the parent directory for the audit log if it doesn't exist.

        Accept either a file path (e.g. /var/log/audit_log.jsonl) or a directory path.
        If a directory is provided we keep it as-is (the consumer may write a file inside it).
        """
        p = Path(v)
        try:
            # If a directory was supplied, ensure it exists
            if p.exists() and p.is_dir():
                p.mkdir(parents=True, exist_ok=True)
                return p

            # Ensure parent directory exists for a file path
            parent = p if p.is_dir() else p.parent
            if parent:
                parent.mkdir(parents=True, exist_ok=True)
            return p
        except Exception as e:  # pragma: no cover - simple filesystem error
            raise ValueError(f"Unable to create audit log path '{v}': {e}") from e

    @field_validator("HF_MODEL_PATH")
    def validate_hf_model_path(cls, v: Path | None) -> Path | None:
        if v is None:
            return None
        p = Path(v)
        if not p.exists():
            raise ValueError(f"HF_MODEL_PATH='{v}' does not exist on disk")
        return p

    @field_validator("PUBMED_EMAIL")
    def validate_pubmed_email(cls, v: str) -> str:
        # Lightweight sanity check to avoid adding the `email-validator` dependency at import time.
        if not isinstance(v, str) or "@" not in v or v.startswith("@") or v.endswith("@"):
            raise ValueError("PUBMED_EMAIL must be a valid email address")
        return v


@lru_cache()
def get_settings() -> Settings:
    try:
        s = Settings()
        # Log a short fingerprint (no secrets)
        logger.debug("Loaded settings ENV=%s, GROQ_BASE_URL=%s", s.ENV, str(s.GROQ_BASE_URL))
        # ensure dp proofs storage directory if using dir mode
        try:
            if s.DP_PROOF_ENABLED and not s.DP_PROOF_STORE.startswith("sqlite:///"):
                import os
                os.makedirs(s.DP_PROOF_STORE, exist_ok=True)
        except Exception:
            pass
        return s
    except ValidationError as e:
        # Provide a friendly, compact message and re-raise for fail-fast behaviour
        err = f"Configuration validation error: {e.errors() if hasattr(e, 'errors') else str(e)}"
        # Print to stderr so container logs surface the issue at boot
        print(err, file=sys.stderr)  # noqa: T201 - intentional UX message
        raise


# Convenience singleton for modules that prefer a single constructed object.
settings = get_settings()
