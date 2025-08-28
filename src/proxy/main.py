import os
import json
from typing import Optional, Dict, Any, List
import pathlib
import hmac
import hashlib
import asyncio

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Body, Response, Request
from fastapi import Query
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

from src.services.query_service import handle_query, query_with_ehr, QueryInput
from src.multimodal.image import image_to_text
from src.multimodal.audio import audio_to_text
from src.feedback.feedback_store import save_feedback
from src.config import get_settings
from src.observability.metrics import REQ_LATENCY, REQ_ERRORS, init_from_settings
from src.security.egress import _load as egress_load, add_domain, remove_domain, is_allowed as egress_is_allowed
from src.security.rate_limit_redis import allow as rl_allow
from src.security.idempotency_redis import get_or_set as redis_get_or_set
from src.audit.verify import verify_file, verify_records
from src.audit.verify import iter_audit_range
from src.security.rate_limiter import allow_request_for_role
from src.security.idempotency import get_cached_response, cache_response
from src.security.policy import POLICY_VERSION
from src.dp.storage import ProofStore
from src.dp.proof import DpProof, verify_dp_proof
from src.audit.verify import get_verifier
from src.audit.signer import get_signer
from src.security.policy import current_policy_version
try:
    from prometheus_client import CollectorRegistry, Counter, generate_latest
    PROMETHEUS_AVAILABLE = True
    registry = CollectorRegistry()
    QUERY_COUNTER = Counter("privmcp_queries_total", "Total queries handled", registry=registry)
except Exception:
    PROMETHEUS_AVAILABLE = False
    registry = None
    QUERY_COUNTER = None

settings = get_settings()
app = FastAPI()
try:
    init_from_settings(settings)
except Exception:
    pass

# --- Health / readiness endpoints required by tests ---
import time
from fastapi import Response
from src.config import settings  # if you need access to config

_START_TIME = time.monotonic()

@app.get("/healthz", include_in_schema=False, tags=["system"])
def healthz():
    # minimal liveness check (always 200 if process is up)
    return {
        "status": "ok",
        "uptime_sec": round(time.monotonic() - _START_TIME, 3),
        "service": "privmcp",
        "version": getattr(settings, "version", "unknown"),
    }

@app.get("/livez", include_in_schema=False, tags=["system"])
def livez():
    # alias for healthz (some probes use /livez)
    return {"status": "ok"}

@app.get("/readyz", include_in_schema=False, tags=["system"])
def readyz():
    # lightweight readiness: check that critical config values exist
    missing = []
    for key in ("PRIVMCP_AUDIT_LOG_PATH", "PRIVMCP_PUBMED_EMAIL",
                "PRIVMCP_GROQ_BASE_URL", "PRIVMCP_GROQ_API_KEY"):
        if not getattr(settings, key.replace("PRIVMCP_", "").lower(), None):
            # Settings likely store them lowercased; fall back to env check
            missing.append(key)

    ok = len(missing) == 0
    return {
        "status": "ok" if ok else "degraded",
        "missing": missing,
        "uptime_sec": round(time.monotonic() - _START_TIME, 3),
    }

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=getattr(settings, "ALLOWED_ORIGINS", ["http://127.0.0.1:8000"]),
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_request_id_middleware(request, call_next):
    # Prefer an incoming X-Request-ID header, else generate one.
    from src.utils.request_id import set_request_id, new_request_id

    incoming = request.headers.get("x-request-id")
    if incoming:
        set_request_id(incoming)
        rid = incoming
    else:
        rid = new_request_id()

    resp = await call_next(request)
    resp.headers["X-Request-ID"] = rid
    # HSTS for transport security
    resp.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
    return resp


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    route = request.url.path
    import time
    t0 = time.perf_counter()
    try:
        resp = await call_next(request)
        return resp
    except Exception:
        try:
            REQ_ERRORS.labels(route=route, family="5xx").inc()
        except Exception:
            pass
        raise
    finally:
        dt = time.perf_counter() - t0
        try:
            REQ_LATENCY.labels(route=route, stage="total").observe(dt)
        except Exception:
            pass

class EHRReq(BaseModel):
    patient_id: str
    user_role: int
    min_role: int
    query_type: int = 0
    numeric_value: float | None = None
    vital_code: str = "55284-4"
    summary_style: str = "clinical"


class AuditVerifyRequest(BaseModel):
    path: Optional[str] = None
    records: Optional[list[dict]] = None

@app.post("/query")
async def api_query(q: QueryInput, request: Request):
    # Idempotency (support both legacy header and X-Request-ID)
    idem_key = None
    try:
        idem_key = request.headers.get("Idempotency-Key") or request.headers.get("X-Request-ID")
    except Exception:
        idem_key = None
    if idem_key:
        prev = None
        try:
            prev = redis_get_or_set(idem_key, {})
        except Exception:
            prev = None
        if prev and isinstance(prev, tuple) and prev[1] is True:
            # stored tuple (response, replay) handled by redis_get_or_set; fall back to cached behaviour
            return prev[0]

    # Rate limit per role (prefer Redis-backed token bucket if available)
    try:
        user = "clinician"
        if not rl_allow(q.user_role, f"rl:{q.user_role}:{user}", capacity=60, refill_per_sec=1.0):
            return JSONResponse({"detail": "rate limit"}, status_code=429)
    except Exception:
        rpm = settings.RATE_LIMIT_RPM_BY_ROLE.get(q.user_role, 10)
        if not allow_request_for_role(q.user_role, rpm):
            raise HTTPException(status_code=429, detail="Rate limit exceeded for role")

    # enforce request-level timeout to avoid slow downstreams
    try:
        from src.utils.request_id import get_request_id
        req_id = get_request_id()
    except Exception:
        req_id = None

    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(handle_query, q, req_id),
            timeout=getattr(settings, "REQUEST_TIMEOUT_SEC", getattr(settings, "request_timeout_sec", 8)),
        )
    except asyncio.TimeoutError:
        return JSONResponse(
            status_code=504,
            content={
                "error": "request_timeout",
                "detail": f"Exceeded {getattr(settings, 'REQUEST_TIMEOUT_SEC', getattr(settings, 'request_timeout_sec', 8))}s",
                "request_id": req_id,
            },
        )
    # legacy in-memory cache key handling removed (use redis-backed cache via query_service)
    # if idempotency header present, persist response
    if idem_key:
        try:
            from src.security.idempotency import cache_response as mem_cache_response
            mem_cache_response(idem_key, result)
        except Exception:
            pass
    if PROMETHEUS_AVAILABLE and QUERY_COUNTER is not None:
        try:
            QUERY_COUNTER.inc()
        except Exception:
            pass
    if "detail" in result and not result.get("access_allowed", True):
        raise HTTPException(status_code=403, detail=result["detail"])
    # Wrap result in envelope expected by smoke tests
    return {"output": result}

@app.post("/query_with_ehr")
def api_query_with_ehr(req: EHRReq):
    rpm = settings.RATE_LIMIT_RPM_BY_ROLE.get(req.user_role, 10)
    if not allow_request_for_role(req.user_role, rpm):
        raise HTTPException(status_code=429, detail="Rate limit exceeded for role")

    result = query_with_ehr(
        patient_id=req.patient_id,
        user_role=req.user_role,
        min_role=req.min_role,
        query_type=req.query_type,
        numeric_value=req.numeric_value,
        vital_code=req.vital_code,
        summary_style=req.summary_style
    )
    if "detail" in result and result["detail"].startswith("No observations"):
        raise HTTPException(status_code=404, detail=result["detail"])
    if "detail" in result and not result.get("access_allowed", True):
        raise HTTPException(status_code=403, detail=result["detail"])
    return result

@app.post("/multimodal_query")
async def multimodal_query(
    user_role: int = Form(...),
    min_role: int = Form(...),
    query_type: int = Form(...),
    query_text: str = Form(""),
    numeric_value: float = Form(None),
    image: UploadFile = File(None),
    audio: UploadFile = File(None)
):
    context = query_text
    if image is not None:
        image_path = f"temp_{image.filename}"
        with open(image_path, "wb") as f:
            f.write(await image.read())
        image_caption = image_to_text(image_path)
        context += f"\n[Image]: {image_caption}"
    if audio is not None:
        audio_path = f"temp_{audio.filename}"
        with open(audio_path, "wb") as f:
            f.write(await audio.read())
        transcript = audio_to_text(audio_path)
        context += f"\n[Audio]: {transcript}"

    q = QueryInput(
        user_role=user_role,
        min_role=min_role,
        query_type=query_type,
        query_text=context,
        numeric_value=numeric_value
    )
    return handle_query(q)

@app.post("/feedback")
def submit_feedback(
    query: str = Body(...),
    response: str = Body(...),
    rating: int = Body(...),
    correction: str = Body(None),
    user: str = Body("clinician")
):
    return save_feedback(query, response, rating, correction, user)

@app.get("/audit_log")
def get_audit_log():
    path = settings.AUDIT_LOG_PATH
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f]
        return lines
    except Exception as e:
        return {"error": str(e)}


@app.get("/health")
def health():
    # Lightweight health probe - ensures settings load and audit path writable
    path = settings.AUDIT_LOG_PATH
    ok = True
    errors = []
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write("")
    except Exception as e:
        ok = False
        errors.append(str(e))
    return {"status": "ok" if ok else "fail", "errors": errors}


@app.get("/metrics")
def metrics():
    if not PROMETHEUS_AVAILABLE:
        return {"error": "prometheus_client not installed"}
    try:
        data = generate_latest(registry)
        return Response(content=data, media_type="text/plain; version=0.0.4; charset=utf-8")
    except Exception as e:
        return {"error": str(e)}


    @app.get("/admin/egress", response_class=HTMLResponse)
    def egress_admin():
            items = "".join(f"<li>{d}</li>" for d in sorted(list(egress_load())))
            html = f"""
            <h3>Egress allowlist</h3>
            <ul>{items}</ul>
            <form method="post" action="/admin/egress/add">
                <input name="domain" placeholder="example.org"><button>Add</button>
            </form>
            <form method="post" action="/admin/egress/remove">
                <input name="domain" placeholder="example.org"><button>Remove</button>
            </form>
            """
            return HTMLResponse(html)

    @app.post("/admin/egress/add")
    def egress_add(domain: str = Form(...), request: Request = None):
            add_domain(domain.strip().lower(), actor="admin")
            return {"ok": True}

    @app.post("/admin/egress/remove")
    def egress_remove(domain: str = Form(...), request: Request = None):
            remove_domain(domain.strip().lower(), actor="admin")
            return {"ok": True}


@app.get("/audit/pubkey")
def audit_pubkey():
    """
    Always returns a stable schema. When no signer is configured,
    'enabled' is False and other fields are null.
    """
    try:
        signer = get_signer()  # may return None in lazy mode
    except Exception:
        signer = None

    # Default payload when disabled
    payload = {
        "enabled": False,
        "algo": None,
        "public_key": None,
    "pubkey": None,
        "kid": None,
        "created_at": None,
        "policy_version": current_policy_version(),
    }

    if signer:
        # Support either attributes or a helper on the signer
        info = {}
        if hasattr(signer, "public_info") and callable(getattr(signer, "public_info")):
            try:
                info = signer.public_info() or {}
            except Exception:
                info = {}

        algo = getattr(signer, "algo", info.get("algo"))
        pubkey = getattr(signer, "public_key_pem", None) or info.get("public_key")
        kid = getattr(signer, "kid", info.get("kid"))
        created = getattr(signer, "created_at_iso", info.get("created_at"))

        payload.update({
            "enabled": True,
            "algo": algo,
            "public_key": pubkey,
            "pubkey": pubkey,
            "kid": kid,
            "created_at": created,
        })

    return payload


from datetime import datetime, timezone


def _parse_iso_utc(ts: str) -> datetime:
    """Tolerant ISO8601 parser that accepts trailing Z and returns a UTC-aware datetime."""
    ts = (ts or "").strip()
    if not ts:
        raise ValueError("empty timestamp")
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt


@app.get("/audit/range")
def audit_range(
    start: Optional[str]   = Query(default=None, description="ISO8601, accepts 'Z'"),
    end: Optional[str]     = Query(default=None, description="ISO8601, accepts 'Z'"),
    from_iso: Optional[str]= Query(default=None, description="Legacy alias for start"),
    to_iso: Optional[str]  = Query(default=None, description="Legacy alias for end"),
    limit: int = Query(100000, ge=1, le=200000),
) -> Dict[str, Any]:
    s_raw = start or from_iso
    e_raw = end or to_iso
    if not s_raw or not e_raw:
        raise HTTPException(status_code=422, detail="Provide start/end (or from_iso/to_iso).")

    try:
        s_dt = _parse_iso_utc(s_raw)
        e_dt = _parse_iso_utc(e_raw)
    except Exception as ex:
        raise HTTPException(status_code=400, detail=f"Bad timestamps: {ex}")

    if s_dt > e_dt:  # be forgiving if swapped
        s_dt, e_dt = e_dt, s_dt

    items: List[Dict[str, Any]] = list(iter_audit_range(s_dt, e_dt, limit=limit, newest_first=True))
    # expose both `items` and `entries` for compatibility with callers/tests
    return {"items": items, "entries": items, "count": len(items)}



@app.get("/audit/verify")
def audit_verify_get():
    """Verify the on-disk audit log file configured in settings."""
    res = verify_file(str(settings.AUDIT_LOG_PATH), getattr(settings, "AUDIT_HMAC_KEY", None))
    # Return 200 on success (even if verified=False), only 404 if file missing
    if not res.get("ok") and res.get("error") == "not_found":
        raise HTTPException(status_code=404, detail=res)
    return res


@app.post("/audit/verify")
def audit_verify_post(payload: AuditVerifyRequest):
    # If records provided, verify them directly
    if payload.records:
        return verify_records(payload.records, getattr(settings, "AUDIT_HMAC_KEY", None))
    # Otherwise verify file at provided path or default
    path = payload.path or str(settings.AUDIT_LOG_PATH)
    res = verify_file(path, getattr(settings, "AUDIT_HMAC_KEY", None))
    if not res.get("ok") and res.get("error") == "not_found":
        raise HTTPException(status_code=404, detail=res)
    return res


@app.get("/dp/proof/{request_id}")
def get_dp_proof(request_id: str):
    s = get_settings()
    if not getattr(s, "DP_PROOF_ENABLED", False):
        raise HTTPException(status_code=404, detail="DP proofs disabled")
    store = ProofStore(s.DP_PROOF_STORE)
    js = store.get(request_id)
    if not js:
        raise HTTPException(status_code=404, detail="Proof not found")
    return json.loads(js)


class ProofPayload(BaseModel):
    proof: dict


@app.post("/dp/verify")
def dp_verify(payload: ProofPayload):
    try:
        proof = DpProof.from_json(json.dumps(payload.proof, separators=(",", ":"), sort_keys=True))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"invalid proof: {e}")

    verifier = None
    try:
        verifier = get_verifier()
    except Exception:
        verifier = None

    ok, reason = verify_dp_proof(proof, signer_verify=verifier)
    return {"ok": ok, "reason": reason}
