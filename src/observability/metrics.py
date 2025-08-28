from prometheus_client import Histogram, Counter, Gauge

REQ_LATENCY = Histogram(
    "privmcp_request_latency_seconds",
    "Request latency by route and stage",
    ["route", "stage"]
)
REQ_ERRORS = Counter(
    "privmcp_request_errors_total",
    "Errors by route and code family",
    ["route", "family"]
)
SLO_P95_NO_LLM = Gauge("privmcp_slo_p95_no_llm_ms", "Configured p95 SLO no LLM")
SLO_P95_WITH_LLM = Gauge("privmcp_slo_p95_with_llm_ms", "Configured p95 SLO with LLM")

def init_from_settings(s):
    try:
        SLO_P95_NO_LLM.set(s.SLO_P95_MS_NO_LLM)
        SLO_P95_WITH_LLM.set(s.SLO_P95_MS_WITH_LLM)
    except Exception:
        # best-effort
        pass
