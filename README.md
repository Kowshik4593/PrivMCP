# PrivMCP · Verifiable-Privacy, Policy-as-Code, and Audit-First Clinical Prompt Server

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.11+-blue)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/FastAPI-%F0%9F%9A%80-green)](https://fastapi.tiangolo.com/)

**PrivMCP** is a modular, privacy-preserving clinical prompt server with **verifiable privacy guarantees**, **policy-as-code**, **idempotent requests**, and **cryptographically chain-linked audit logs**. It powers explainable, evidence-aware answers while ensuring PHI minimization and post-hoc verifiability.

> **Scope**: Text pipeline is production-ready. Image/audio are pluggable stubs (adapters included, enable via config). ZK proof interface is implemented with a default **stub** protocol; real circuits can drop-in without API changes.

---

## ✨ Novelty (What’s new vs. typical LLM/RAG servers)

- **Verifiable Differential Privacy (vDP)** Per-request DP proof objects with **VRF-DRBG** seeding, **Merkle leaf/root**, value/noise commitments, and an optional signer. Proofs are retrievable via `GET /dp/proof/{request_id}` and checkable by `POST /dp/verify`. An **audit hash chain** links requests to proofs.

- **Policy-as-Code** Load a signed policy bundle at boot; query **`current_policy_version()`** at runtime and surface it in responses/badges. This makes results **policy-pinned** and citable.

- **Audit-by-Design** Append-only **JSONL hash chain** with durable writes (flush + fsync). Range queries via `GET /audit/range` and public key exposure via `GET /audit/pubkey` (if signing is configured).

- **RBAC & Egress Governance** Request-time **role checks** (min role thresholds) and **egress allowlist** with an **admin UI** + POST endpoints. Results include a compact **badges** string (“RBAC ✅ | DP ε=… | Audit verifiable | …”).

- **Operational Hardening** **Idempotency** (client request IDs), **rate limiting** and **response caching** via Redis, **LLM router** (provider-agnostic), **quality guard** (basic output hygiene), homoglyph PHI defense, and **metrics middleware**.

- **Forensics-Ready** Every result returns a minimal **reasoning trace tag** (no chain-of-thought), PHI hits, and the **policy/build IDs** for reproducibility.

---

## 🧭 Architecture (high-level)
Client → /query

├─ Homoglyph defense & PHI scrubbing (pattern/rule-based; pluggable NER)

├─ RBAC gate (role ≥ min_role)

├─ DP module (Laplace, ε per-policy) → vDP proof store (VRF-DRBG + Merkle)

├─ Retrieval / RAG (evidence adapters; PubMed or internal sources)

├─ LLM Router (provider-agnostic; quality guard on output)

├─ Audit logger (JSONL hash chain; optional signing)

└─ Response (badges, policy version, audit excerpt, proof retrieval link)

**Infra glue**: Redis (rate-limit, idempotency, caching) · FastAPI · Pydantic Settings (env-first) · Optional signer (lazy) · Policy bundle loader.

---

## 📚 API Overview

All endpoints are rooted at your server base (e.g., `http://127.0.0.1:8000`).

### Health & Metrics
- `GET /healthz` → `200 OK` if process up
- `GET /readyz` → `200 OK` if dependencies ready
- `GET /metrics` → Prom-style metrics (optional)

### Query (primary)
- `POST /query`

**Request (two compatible shapes):**
```json
// Preferred
{
  "query_text": "Patient John Doe, MRN 123-45-6789, visited for diabetes checkup.",
  "user_role": 5,
  "min_role": 2,
  "query_type": "clinical_summary",
  "client_request_id": "optional-guid"  // for idempotency; server also generates one
}

// Legacy (still supported)
{ "query": "..." }
````

**Response (truncated example):**

```json
{
  "redacted_query": "Patient [NAME], [NAME], visited for diabetes checkup.",
  "phi_entities": ["John Doe", "MRN 123-45-6789", "123-45-6789"],
  "dp_report": { "original": 123.4, "noised": 122.67, "epsilon": 1.0, "mechanism": "Laplace" },
  "noised_value": 122.67,
  "zkp": { "proof": { "protocol": "stub", "inputs": [] }, "public": [] },
  "access_allowed": true,
  "audit_log_record": {
    "timestamp": "2025-08-28T09:41:22Z",
    "request_id": "52e0b69c-....",
    "entry_hash": "273ef2bd4f56....",
    "dp_merkle_root": null, "dp_proof_hash": null,
    "allowed": true
  },
  "llm_response": "...explainable answer with citations...",
  "citations": [{ "pmid": "7807615", "title": "...", "url": "..." }],
  "badges": "RBAC ✅ | DP ε=1.00 | Audit verifiable | Sources #1 | Policy 2025-08-26-v1@000000000000",
  "policy_version": "2025-08-26-v1@000000000000",
  "build_version": "2025.08.26"
}
```

### Verifiable DP (proofs)

  - `GET /dp/proof/{request_id}` → returns proof object (seed commit, leaf/root, noise/value hashes, signature if enabled)
  - `POST /dp/verify` with the proof object → `{ "ok": true }` if valid

**Proof sample:**

```json
{
  "version": "dpv1",
  "epsilon": 1.0,
  "sensitivity": 1.0,
  "noised_value": 122.018,
  "noise": -1.382,
  "value_hash": "5f466d7a...",
  "seed_commit": "a828ed...",
  "leaf_hash": "45eca2...",
  "merkle_root": "45eca2...",
  "merkle_path": [],
  "signature": null,
  "audit_entry_hash": null,
  "mechanism": "Laplace"
}
```

### Audit

  - `GET /audit/range?start=ISO_UTC&end=ISO_UTC` → JSON entries within inclusive UTC window
      - Back-compat: also accepts `from_iso`/`to_iso`.
  - `GET /audit/pubkey` → `{ "kid": "...", "alg": "ed25519", "pubkey": "base64/hex", "policy_version": "..." }` (when signing configured)

**Audit line (JSONL):**

```json
{"timestamp":"2025-08-28T09:41:22Z","user":"clinician","role":5,"request_id":"...","entry_hash":"...","prev_hash":"...","allowed":true,"dp_hash":"...","zkp_hash":"..."}
```

### Admin (optional)

  - Egress allowlist `GET`/`POST` endpoints (exposed when enabled)
  - Simple admin UI routes to manage allowlist

## ⚙️ Configuration (env)

| Key | Example | Notes |
| --- | --- | --- |
| `PRIVMCP_AUDIT_LOG_PATH` | `audit.jsonl` | JSONL audit path (durable fsync on write) |
| `PRIVMCP_AUDIT_PRIVKEY_PATH` | `./keys/audit_ed25519.sk` | Optional; enables signing |
| `PRIVMCP_AUDIT_PUBKEY_PATH` | `./keys/audit_ed25519.pk` | Optional; served at `/audit/pubkey` |
| `PRIVMCP_AUDIT_KEY_ID` | `audit-ed25519-v1` | Optional `KID` in pubkey response |
| `PRIVMCP_POLICY_BUNDLE_PATH` | `./policy/policy.bundle.json` | Policy-as-code bundle; surfaced in responses |
| `PRIVMCP_REDIS_URL` | `redis://localhost:6379/0` | Rate limit, idempotency, cache |
| `PRIVMCP_RATE_LIMIT_RPS` | `5` | Simple global/token bucket |
| `PRIVMCP_REQUEST_TIMEOUT_S` | `8` | Server-side timeout guard |
| `PRIVMCP_EGRESS_ADMIN_ENABLED` | `true` | Enable allowlist UI+endpoints |
| `LLM_PROVIDER` | `openai/groq/local` | LLM router selection |
| `LLM_API_KEY` | `...` | Provider key (if needed) |

The signer is lazy (via `get_signer()`), so missing keys won’t crash startup unless strict mode is enabled.

## 🛠️ Run

### Local (dev)

```bash
# Create and activate a virtual environment
python -m venv .venv && source .venv/bin/activate   # (Windows: .venv\Scripts\activate)

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env                                 # set variables from the table above

# Run the server
uvicorn src.proxy.main:app --reload
```

### Docker (optional)

```yaml
# docker-compose.yml
services:
  privmcp:
    build: .
    ports: ["8000:8000"]
    env_file: .env
    depends_on: [redis]
  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]
```

```bash
docker compose up --build
```

## 🧪 Smoke & Paper-Eval

```bash
# Run a comprehensive smoke test
python tests/super_smoke_test_privmcp.py

# Typical pass criteria:
# - happy path 200 + DP proof verified
# - idempotency replay accepted
# - RBAC denial observed
# - audit range includes request
# - audit pubkey available (if configured)
# - metrics endpoint available (optional)

# Run paper-style throughput/latency + privacy checks
$env:BASE="[http://127.0.0.1:8000](http://127.0.0.1:8000)"
$env:PRIVMCP_TEST_TIMEOUT="60"
python tests/paper_eval.py --n 50 --rps "1,3,5" --dur 20
```

The eval script exercises: happy path → DP fetch/verify → known-sources check → RBAC denial → audit window coverage; collects latency/err rates for tables.

## 🔐 Privacy & Security Model

  - **PHI Minimization**: rule-based scrubbing with homoglyph defense (pluggable NER compatible).
  - **Differential Privacy**: Laplace mechanism with policy-tunable ε; proof object per request (VRF-DRBG seed commit → Merkle leaf/root).
  - **RBAC**: request-time `user_role` ≥ `min_role`; denial still produces auditable entry.
  - **Egress Allowlist**: outbound calls constrained; admin UI/POST to manage allowlist.
  - **Audit Hash Chain**: each entry links to prior; optional signature with exposed pubkey for external verification.
  - **No CoT**: responses include a terse “explainability tag” but avoid chain-of-thought leakage.

## 📁 Repository Layout

```
src/
  proxy/main.py           # FastAPI app, routes, middleware, CORS, metrics
  services/query_service.py
  audit/
    logger.py             # durable JSONL append, hash chain
    signer.py             # lazy signer, get_signer()
    verify.py             # range iteration, signature/entry verification helpers
  dp/
    vrf_drbg.py           # verifiable randomness for DP
    merkle.py             # Merkle leaf/root utilities
    proof.py              # proof object schema/build/verify
    storage.py            # proof store (per request_id)
  policy/
    policy.py             # bundle loader, current_policy_version()
  security/
    rbac.py               # role checks
    egress.py             # allowlist + admin routes
    quality_guard.py      # output hygiene
    injection.py          # prompt injection checks
    homoglyph_phi.py      # homoglyph/PHI defense helpers
  router/
    llm_router.py         # provider-agnostic routing
  cache/
    redis_client.py       # rate limit, idempotency, caching
tests/
  super_smoke_test_privmcp.py
  paper_eval.py
  redteam/                # optional adversarial harness
frontend/                 # optional glossy console (React)
```

## 📈 Reproducible Results (for papers)

  - **Policy pinned**: every result includes `policy_version` and `build_version`.
  - **Verifiable privacy**: DP proof fetch/verify is first-class and scriptable.
  - **Audit coverage**: `audit/range` APIs reproduce all entries for specified windows.

You can export a results bundle (JSON) for submission artifacts:

  - request/response bodies (scrubbed), DP proofs, verification receipts
  - audit excerpt (range), policy version, build version
  - latency and success metrics from `paper_eval.py`

## ⚠️ Limitations

  - **ZKP**: the default proof is a stub. The interface is production-compatible; plug in real circuits/verification without API changes.
  - **Advanced PHI NER**: current default is rule-based + homoglyph defense; drop in med-NER for higher recall if desired.
  - **Image/Audio**: adapters are present; enable models/providers in config to activate.

## 🤝 Contributing

  - Open a PR with focused commits.
  - Include a smoke run (`super_smoke_test_privmcp.py`) in the PR description.
  - If you touch audit/DP/policy code, add a tiny test that fetches and verifies a DP proof.

## 📜 License

MIT © 2025 PrivMCP contributors
