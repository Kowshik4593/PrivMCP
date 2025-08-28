# src/services/query_service.py
import re
import string
import os
from typing import Optional, List, Dict, Any, Tuple
import hashlib

from fastapi import HTTPException

from pydantic import BaseModel

# Avoid shadowing by aliasing the import
from src.config import get_settings as _get_settings
from src.dp.main import LaplaceMechanism
from src.dp.accountant import get_accountant
from src.dp.shim import safe_charge
from src.ehr.fhir_connector import get_patient_observations
from src.llm.local_model import generate_completion
from src.llm.groq_api import groq_completion
from src.rag.pubmed_search import pubmed_search
from src.redactor.hybrid import HybridPHIRedactor
from src.redactor.apply import redact as apply_redact, safety_gate_check
from src.audit.logger import log_query_audit
from src.services.response_meta import MetaBadges
from src.security.policy import current_policy_version
from src.quality.guard import enforce as enforce_quality
from src.cache.results import cache_key, get as cache_get, set_ as cache_set
from src.llm.router import decide_model
from src.zk.verify import generate_proof, verify_proof
from src.security.policy import check_access, POLICY_VERSION


# Instantiate heavy components once
settings = _get_settings()
_phi_redactor = HybridPHIRedactor(
    use_transformer=settings.NER_USE_TRANSFORMER,
    transformer_model=settings.NER_TRANSFORMER_MODEL,
)


class QueryInput(BaseModel):
    user_role: int
    min_role: int
    query_type: int
    query_text: str
    numeric_value: Optional[float] = None


def _extract_pubmed_keywords(prompt: str) -> str:
    stop_words = {
        "what", "is", "the", "in", "for", "and", "of", "a", "an", "to", "with",
        "by", "on", "as", "or", "from", "above", "latest", "write", "given",
        "these", "findings", "describe", "summarize", "summary", "trend",
        "comment", "attached", "image", "audio", "if", "present", "clinical",
        "readings", "reading", "date", "value", "mmhg"
    }
    text = prompt.translate(str.maketrans('', '', string.punctuation))
    words = [w for w in text.lower().split()]
    filtered = [w for w in words if not w.isdigit() and w not in stop_words and not any(c.isdigit() for c in w)]
    filtered = [w for w in filtered if len(w) > 2 and w.isalpha()]
    return " AND ".join(filtered) if filtered else prompt


def _final_redact(text: str) -> str:
    """
    Run the hybrid redactor again on model output for extra safety.
    """
    res = _phi_redactor.redact(text)
    return res.get("redacted_text", text)


def _build_llm_prompt(redacted_query: str, citations: List[Dict[str, Any]]) -> str:
    evidence_block = ""
    if citations:
        evidence_block = "\n\nRelevant PubMed evidence:\n" + "\n".join(
            f"- {c['title']} (PMID: {c['pmid']}): {c.get('snippet', '')}" for c in citations
        )

    # IMPORTANT: Do not ask for chain-of-thought. Ask for concise, structured answer.
    return (
        f"{redacted_query}{evidence_block}\n\n"
        "Instructions:\n"
        "1) Provide a concise clinical answer and trend analysis where relevant.\n"
        "2) Cite ONLY the PubMed items above by PMID.\n"
        "3) Do NOT include any identifiers; keep the response de-identified.\n"
    )


def _hash(s: str) -> str:
    try:
        return hashlib.sha256((s or "").encode("utf-8")).hexdigest()
    except Exception:
        return ""


def _zkp_stub(q: QueryInput) -> Dict[str, Any]:
    # Minimal stub so callers that expect a zkp structure have one even on denial
    return {"protocol": "none", "inputs": [q.user_role, q.min_role, q.query_type]}


def handle_query(q: QueryInput, request_id: Optional[str] = None) -> Dict[str, Any]:
    settings = _get_settings()
    dp_merkle_root: Optional[str] = None
    dp_proof_hash: Optional[str] = None
    # --- defaults to prevent UnboundLocalError on early/exception paths ---
    reasoning_trace = {}
    citations = []
    llm_response = ""
    dp_report = None
    noised_value = None
    zkp = None
    # ---------------------------------------------------------------------

    # --- fast-fail safety gate ---
    try:
        from src.security.policy import is_query_safe
    except Exception:
        is_query_safe = None

    if is_query_safe is not None:
        safe, reason = is_query_safe(q.query_text or "")
        if not safe:
            # shape a body consistent with the normal success path but mark blocked
            hybrid_res = _phi_redactor.redact(q.query_text or "")
            redacted_text = hybrid_res.get("redacted_text")
            entities = hybrid_res.get("phi_entities") or []
            flat_phi = []
            seen = set()
            for e in (entities or []):
                v = e.get("value") if isinstance(e, dict) else str(e)
                if v and v not in seen:
                    seen.add(v)
                    flat_phi.append(v)

            audit_record = log_query_audit(
                user="clinician",
                role=q.user_role,
                query=redacted_text or (q.query_text or ""),
                dp_report=None,
                zkp_proof=_zkp_stub(q),
                allowed=False,
            )

            body = {
                "output": {
                    "redacted_query": redacted_text,
                    "phi_entities": flat_phi,
                    "phi_entities_detailed": entities or [],
                    "dp_report": None,
                    "noised_value": None,
                    "zkp": _zkp_stub(q),
                    "access_allowed": False,
                    "audit_log_record": audit_record,
                    "llm_response": f"[blocked] {reason}",
                    "citations": [],
                    "reasoning_trace": {
                        "prompt": redacted_text,
                        "model_used": settings.GROQ_MODEL if getattr(settings, "GROQ_MODEL", None) else "unknown",
                        "zkp_public": ["1"],
                        "dp_report": None,
                        "phi_entities": flat_phi,
                        "explainability": "Safety-gate block (no model call).",
                    },
                    "clinical_report_synthesis": "Query blocked by safety policy."
                }
            }
            raise HTTPException(status_code=400, detail=body)

    # 1) EHR hint: try to extract a patient id like 'patient 12345'
    pid = None
    m = re.search(r"patient[_\s:]*(\d{4,10})", q.query_text, re.I)
    if m:
        pid = m.group(1)

    # 2) If we have a patient id, enrich with BP observations; else as-is
    if pid:
        if settings.FHIR_BASE_URL:
            obs = get_patient_observations(settings.FHIR_BASE_URL, pid, code="55284-4")
        else:
            obs = None

        if obs:
            obs_text = "\n".join(
                f"{i+1}. {o['date']}: "
                f"Systolic={o['value'].get('Systolic Blood Pressure','?')} "
                f"Diastolic={o['value'].get('Diastolic Blood Pressure','?')}"
                for i, o in enumerate(obs)
            )
            prompt = (
                f"Given these blood pressure readings for patient {pid}:\n{obs_text}\n"
                f"Write a clinical summary and comment on the trend."
            )
        else:
            prompt = f"No BP observations found for patient {pid}. {q.query_text}"
    else:
        prompt = q.query_text

    # 3) PHI redaction (query) using typed placeholders + safety gate
    # Use the hybrid detector to produce candidate entities (values + spans)
    # then apply typed placeholder redaction which normalizes/dedupes and returns flags.
    # The hybrid detector returns a dict with 'redacted_text' and 'phi_entities' already,
    # but we prefer the structured apply.redact which expects entity dicts.
    # Build entity objects from hybrid outputs when needed.
    hybrid_res = _phi_redactor.redact(prompt)
    # If hybrid produced typed entities already (list of strings), convert to crude spans
    entities = []
    for idx, val in enumerate(hybrid_res.get("phi_entities", [])):
        # best-effort spans: find first occurrence
        try:
            start = prompt.index(val)
            end = start + len(val)
        except Exception:
            start = None
            end = None
        entities.append({"type": "PERSON", "value": val, "start": start, "end": end, "score": 1.0})

    redaction = apply_redact(prompt, entities)
    redacted_query = redaction["redacted_text"]
    # Flatten entities to strings for test compatibility and keep detailed data
    detailed_entities = redaction.get("phi_entities") or []

    def _to_value(e):
        if isinstance(e, str):
            return e
        if isinstance(e, dict):
            return e.get("value") or e.get("text") or ""
        return str(e)

    flat_phi = []
    seen = set()
    for e in (detailed_entities or []):
        v = _to_value(e)
        if v and v not in seen:
            seen.add(v)
            flat_phi.append(v)

    phi_entities = flat_phi
    phi_entities_detailed = detailed_entities

    # Safety gate: block LLM calls if redaction looks unsafe
    gate_ok = safety_gate_check(redaction)
    # Ensure ZKP/audit variables exist even if we block early so audit can record a receipt
    proof = {"protocol": "none", "inputs": None}
    public = []
    allowed = False
    if not gate_ok:
        audit_record = log_query_audit(
            user="clinician",
            role=q.user_role,
            query=redacted_query,
            dp_report=None,
            zkp_proof=proof,
            allowed=allowed,
        )
        return {
            "status": 422,
            "detail": "Unable to safely de-identify this query. Please remove identifiers or rephrase.",
            "audit_log_record": audit_record,
        }

    # 4) Differential Privacy (for numeric / optional)
    dp_report = None
    noised_value = None
    if q.numeric_value is not None:
        try:
            mech = LaplaceMechanism(epsilon=settings.DP_EPSILON)
            noised_value, dp_report = mech.add_noise(q.numeric_value)
            # Record DP spend with the accountant (per-role principal)
            acct = get_accountant()
            principal = f"role:{q.user_role}"
            # Enforce per-role budget if configured
            budgets = getattr(settings, "DP_BUDGETS", {}) or {}
            role_budget = budgets.get(q.user_role)
            try:
                charged = safe_charge(
                    acct,
                    principal=principal,
                    epsilon=settings.DP_EPSILON,
                    sensitivity=1.0,
                    namespace="query",
                    account_key=principal,
                    budget=role_budget,
                    max_epsilon=settings.DP_EPSILON,
                )
            except Exception:
                charged = False
            if not charged:
                # Log audit and deny the request due to DP budget exhaustion
                audit_record = log_query_audit(
                    user="clinician",
                    role=q.user_role,
                    query=redacted_query,
                    dp_report=dp_report,
                    zkp_proof=proof,
                    allowed=False,
                )
                return {
                    "status": 429,
                    "detail": "DP budget exceeded for your role; request denied.",
                    "audit_log_record": audit_record,
                }
        except Exception as e:
            dp_report = {"error": str(e)}

    # --- verifiable DP (optional) ---
    try:
        from src.dp.proof import build_dp_proof
        from src.dp.storage import ProofStore
        from src.dp.vrf_drbg import default_seed_material
        from src.audit.signer import get_signer
        from src.security.policy import current_policy_version
        import json as _json, hashlib as _hashlib
    except Exception:
        build_dp_proof = None

    dp_proof_json = None
    dp_proof_obj = None
    if getattr(settings, "DP_PROOF_ENABLED", False) and build_dp_proof is not None:
        # choose a secret key
        secret_key_bytes = None
        if getattr(settings, "DP_SECRET_KEY", ""):
            secret_key_bytes = settings.DP_SECRET_KEY.encode("utf-8")
        else:
            signer_obj = get_signer()
            if signer_obj and getattr(signer_obj, "private_bytes", None):
                try:
                    secret_key_bytes = signer_obj.private_bytes()
                except Exception:
                    secret_key_bytes = None
            if secret_key_bytes is None:
                secret_key_bytes = (getattr(settings, "GROQ_API_KEY", None) or "default-dev-secret").encode("utf-8")

        # optional beacon
        beacon_entropy = None
        if getattr(settings, "RNG_BEACON_URL", ""):
            try:
                import requests
                r = requests.get(settings.RNG_BEACON_URL, timeout=1.5)
                if r.ok and r.text:
                    beacon_entropy = r.text.strip()
            except Exception:
                beacon_entropy = None

        mech = "Laplace"
        polver = current_policy_version()
        try:
            # Build seed inputs from available context (best-effort)
            _req_id = request_id or ""
            _ts = __import__("datetime").datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            _qhash = _hash(redacted_query)
            proof, verified_noised_value = build_dp_proof(
                secret_key=secret_key_bytes,
                mechanism=mech,
                epsilon=settings.DP_EPSILON,
                sensitivity=1.0,
                original_value=q.numeric_value,
                request_id=_req_id,
                timestamp_iso=_ts,
                policy_version=polver,
                user_role=int(q.user_role),
                query_hash=_qhash,
                model_id=locals().get("model_used", None),
                beacon_entropy=beacon_entropy,
                audit_entry_hash=None,
                signer=get_signer(),
            )
            # Overwrite reported noised_value to match proof
            noised_value = verified_noised_value
            store = ProofStore(settings.DP_PROOF_STORE)
            dp_proof_json = proof.to_json()
            store.save(request_id or _req_id or "", dp_proof_json)
            output["dp_proof"] = _json.loads(dp_proof_json)
            dp_merkle_root = proof.merkle_root
            dp_proof_hash = _hashlib.sha256(dp_proof_json.encode("utf-8")).hexdigest()
        except Exception:
            # Non-fatal: continue without storing proof
            pass
    # --- end verifiable DP ---

    # 5) ZKP gate (configurable)
    proof = {"protocol": "stub", "inputs": [q.user_role, q.min_role, q.query_type]}
    public = ["1"]
    # policy check
    policy_ok, policy_reason = check_access(q.user_role, q.min_role)
    allowed = policy_ok
    policy_version = POLICY_VERSION
    if settings.USE_ZKP:
        try:
            proof, public = generate_proof(q.user_role, q.min_role, q.query_type)
            # verify proof and combine with policy decision
            zk_ok = verify_proof()
            allowed = allowed and zk_ok
        except Exception as e:
            return {
                "error": f"ZKP system error: {e}",
                "access_allowed": False,
            }

    if not allowed:
        # Build a consistent, top-level response that mirrors the happy-path shape.
        access_allowed = False
        llm_response = f"Denied by policy: {policy_reason}" if policy_reason else "Denied by policy."
        citations = []
        dp_report = None
        noised_value = None
        zkp = {"proof": {"protocol": "stub", "inputs": []}, "public": []}

        # These are already computed earlier in the function:
        # - redacted_query
        # - phi_entities (flat_phi)
        # - phi_entities_detailed (detailed_entities)
        # Use the same audit logger as the happy path, but with allowed=False and reason
        audit_record = log_query_audit(
            user="clinician",
            role=q.user_role,
            query=redacted_query,
            dp_report=None,
            zkp_proof=zkp,
            allowed=False,
            dp_merkle_root=None,
            dp_proof_hash=None,
        )

        # Build badges if possible
        try:
            badges = MetaBadges(
                rbac_ok=False,
                dp_epsilon=None,
                audit_verifiable=True,
                sources_count=0,
                policy_version=current_policy_version(),
                build_version=settings.BUILD_VERSION,
            )
            badges_row = badges.as_badge_row()
            policy_version_val = badges.policy_version
            build_version_val = badges.build_version
        except Exception:
            badges_row = None
            policy_version_val = current_policy_version()
            build_version_val = getattr(settings, "BUILD_VERSION", None)

        result = {
            "redacted_query": redacted_query,
            "phi_entities": phi_entities,
            "phi_entities_detailed": phi_entities_detailed,
            "dp_report": dp_report,
            "noised_value": noised_value,
            "zkp": zkp,
            "access_allowed": False,
            "audit_log_record": audit_record,
            "llm_response": llm_response,
            "citations": citations,
            "reasoning_trace": {"policy_denied": True, "reason": policy_reason or ""},
            "clinical_report_synthesis": "Request denied by policy; no synthesis generated.",
            "badges": badges_row,
            "policy_version": policy_version_val,
            "build_version": build_version_val,
            "routing_reason": "policy_denied",
        }
        return result

    # 6) PubMed RAG
    pubmed_query = _extract_pubmed_keywords(redacted_query)
    try:
        # Backwards-compatible: our function accepts optional timeout kwarg, but we
        # simply use defaults here.
        citations = pubmed_search(pubmed_query)
    except Exception as e:
        print("PubMed search failed:", e)
        citations = []

    # 7) Build prompt with evidence; call LLM
    llm_prompt = _build_llm_prompt(redacted_query, citations)
    # 7.5 Adaptive routing: decide model based on retrieval scores if available
    try:
        rag_scores = [c.get("score", 0.0) for c in citations]
    except Exception:
        rag_scores = []
    dec = decide_model(rag_scores, settings.GROQ_MODEL, "meta-llama/llama-3.1-70b-instruct")
    routing_reason = dec.reason
    model_to_use = dec.model

    # Check cache for de-identified results
    try:
        key = cache_key(_hash(redacted_query), current_policy_version(), model_to_use)
        cached = cache_get(key)
        if cached:
            cached_output = cached.get("output")
            if cached_output:
                cached_output.setdefault("routing_reason", routing_reason)
                return cached_output
    except Exception:
        pass

    # 8. LLM backend (Groq/local)
    try:
        if settings.USE_GROQ_API and settings.GROQ_API_KEY and model_to_use == settings.GROQ_MODEL:
            llm_response = groq_completion(
                llm_prompt,
                model=settings.GROQ_MODEL,
                timeout=float(settings.GROQ_TIMEOUT_SEC),
            )
            model_used = settings.GROQ_MODEL
        else:
            # Fallback to local model
            llm_response = generate_completion(llm_prompt)
            model_used = os.environ.get("LLM_MODEL", "local")
    except Exception as e:
        llm_response = f"[LLM error: {e}]"
        model_used = "error"

    # 8) Append reference list
    if citations:
        ref_list = "\n\nReferences:\n" + "\n".join(
            f"[{c['pmid']}] {c['title']} ({c['url']})" for c in citations
        )
        llm_response = f"{llm_response}{ref_list}"

    # 9) Final redaction on model output
    llm_response = _final_redact(llm_response)

    # 10) Audit
    audit_record = log_query_audit(
        user="clinician",
        role=q.user_role,
        query=redacted_query,
        dp_report=dp_report,
        zkp_proof=proof,
        allowed=allowed,
        dp_merkle_root=dp_merkle_root,
        dp_proof_hash=dp_proof_hash,
    )

    # 11) Build output and badges
    output = {
        "redacted_query": redacted_query,
        "phi_entities": phi_entities,
        "phi_entities_detailed": phi_entities_detailed,
        "dp_report": dp_report,
        "noised_value": noised_value,
        "zkp": zkp or {"proof": {"protocol": "stub", "inputs": []}, "public": []},
        "access_allowed": allowed,
        "audit_log_record": audit_record,
        "llm_response": llm_response or "No model response was generated.",
        "citations": citations,
        "reasoning_trace": reasoning_trace or {"explainability": "n/a"},
        "clinical_report_synthesis": (
            "Clinical report synthesis and explainability trace included."
            if llm_response else
            "No synthesis available."
        ),
    }

    # enforce quality guardrails (citations, fallbacks)
    try:
        output = enforce_quality(output)
    except Exception:
        pass

    # badges
    try:
        badges = MetaBadges(
            rbac_ok=allowed,
            dp_epsilon=settings.DP_EPSILON if output.get("dp_report") else None,
            audit_verifiable=True,
            sources_count=len(output.get("citations", [])),
            policy_version=current_policy_version(),
            build_version=settings.BUILD_VERSION,
        )
        output["badges"] = badges.as_badge_row()
        output["policy_version"] = badges.policy_version
        output["build_version"] = badges.build_version
    except Exception:
        pass

    # Cache de-identified outputs
    try:
        if not output.get("phi_entities"):
            try:
                cache_set(key, {"output": output})
            except Exception:
                pass
    except Exception:
        pass

    # attach routing reason
    output.setdefault("routing_reason", routing_reason)

    # 11) Reasoning trace (no chain-of-thought; just metadata)
    reasoning_trace = {
        "prompt": llm_prompt,
        "model_used": model_used,
        "zkp_public": public,
        "dp_report": dp_report,
    "phi_entities": phi_entities,
        "explainability": "Evidence-cited summary (no chain-of-thought).",
    }

    return output


def query_with_ehr(
    patient_id: str,
    user_role: int,
    min_role: int,
    query_type: int = 0,
    numeric_value: Optional[float] = None,
    vital_code: str = "55284-4",
    summary_style: str = "clinical",
) -> Dict[str, Any]:
    """
    Convenience wrapper for EHR-aware query. Kept for compatibility with existing routes.
    """
    settings = _get_settings()
    obs = get_patient_observations(settings.FHIR_BASE_URL, patient_id, code=vital_code)
    if not obs:
        return {"detail": "No observations found for patient."}

    obs_text = "\n".join(
        f"{i+1}. {o['date']}: "
        f"Systolic={o['value'].get('Systolic Blood Pressure','?')} "
        f"Diastolic={o['value'].get('Diastolic Blood Pressure','?')}"
        for i, o in enumerate(obs)
    )
    clinical_prompt = (
        f"Given these blood pressure readings for patient {patient_id}:\n{obs_text}\n"
        f"Write a {summary_style} summary and comment on the trend."
    )

    q = QueryInput(
        user_role=user_role,
        min_role=min_role,
        query_type=query_type,
        query_text=clinical_prompt,
        numeric_value=numeric_value,
    )
    return handle_query(q)
