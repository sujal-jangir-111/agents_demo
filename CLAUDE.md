# CLAUDE.md — Sentinel: Autonomous DevSecOps & Self-Healing Multi-Agent System

> Project context for Claude Code. Read this file fully before writing or changing any code.
> Hackathon: **Fetch-A-Thon 3.0** (Fetch.ai Innovation Lab). Every agent must be discoverable on **ASI:One** and registered on **Agentverse**.

---

## 1. What We Are Building (One Paragraph)  

Sentinel is a closed-loop, 5-agent system built with the Python **uAgents** framework. A user types a request into **ASI:One** chat (e.g. *"Diagnose and heal the outage on https://sentinel-target.onrender.com for repo org/sentinel-target"*). The swarm then:

1. probes the live service and captures the failure (HTTP 500, latency, traceback),
2. correlates the failure with the exact offending Git commit and builds an AST map of imported packages/functions,
3. runs reachability-aware CVE scanning (OSV.dev) and SAST,
4. drafts a fix that a second agent must security-vet before it is allowed through,
5. shows the user an ASI:One card and asks for a **0.1 FET Dorado testnet payment** as change-control authorization,
6. after payment is verified on-chain, opens a real GitHub PR (with `tx_hash`, attestation and a CycloneDX SBOM), triggers a hotfix/redeploy,
7. re-probes the service and reports the recovery (`HTTP 500 → HTTP 200 OK`) back in ASI:One.

**Nothing in the demo path may be mocked.** OSV.dev, GitHub, ASI:One LLM and Dorado verification are real API calls. The only "staged" part is the deliberately broken demo target app.

---

## 2. Tech Stack  

| Concern | Choice |
|---|---|
| Language | Python 3.11+ |
| Agent framework | `uagents`, `uagents-core` (chat + payment protocols) |
| HTTP client | `httpx` (async only — never `requests` inside agent handlers) |
| LLM | ASI:One, OpenAI-compatible: `https://api.asi1.ai/v1/chat/completions`, model `asi1-mini` |
| Chain | Fetch.ai **Dorado testnet** via `cosmpy` (`chain_id="dorado-1"`, denom `atestfet`) |
| Vulnerability DB | OSV.dev `POST https://api.osv.dev/v1/querybatch` (no API key) |
| Source control | GitHub REST API v3 with a fine-grained PAT |
| SBOM | CycloneDX v1.5 JSON (hand-built dict; no heavy dependency required) |
| Demo target | FastAPI + uvicorn (`demo_target_app/`) |
| Config | `python-dotenv`, `.env` file |
| Tests | `pytest`, `pytest-asyncio`, `respx` (for mocking httpx **in tests only**) |

---

## 3. Repository Layout


Project/
├── CLAUDE.md
├── README.md                        # Hackathon badges + agent registry table (see §13)
├── requirements.txt
├── .env.example
├── docker-compose.yml               # 5 agents + demo target app
├── common/
│   ├── __init__.py
│   ├── config.py                    # Loads .env, exposes typed settings (single source of config)
│   ├── models.py                    # ALL inter-agent uagents.Model schemas (§6) — only place they live
│   ├── addresses.py                 # Agent addresses derived from seeds / read from env
│   ├── asi1_client.py               # Async ASI:One chat-completions wrapper + JSON-mode helper
│   ├── github_client.py             # Commits, diffs, file contents, branches, commits, PRs
│   ├── osv_client.py                # OSV batch query + manifest parsing + reachability classification
│   ├── sast_rules.py                # Regex/AST SAST rule set
│   ├── ast_mapper.py                # Python `ast` import & call-symbol extractor
│   ├── sbom_generator.py            # CycloneDX v1.5 JSON builder
│   ├── dorado.py                    # cosmpy tx verification helper
│   └── logging.py                   # Structured log helper: [incident_id][agent][stage] message
├── agents/
│   ├── Agent_1.py     # :8001
│   ├── Agent_2.py        # :8002
│   ├── Agent_3.py          # :8003
│   ├── Agent_4.py          # :8004
│   └── Agent_5.py      # :8005
├── demo_target_app/
│   ├── app.py
│   ├── requirements.txt             # deliberately vulnerable pins
│   └── Dockerfile                   # deliberately insecure
└── tests/
    ├── test_models.py
    ├── test_osv_client.py
    ├── test_sast_rules.py
    ├── test_ast_mapper.py
    ├── test_sbom_generator.py
    └── test_end_to_end_pipeline.py


Do not create extra top-level folders without a reason. Shared logic goes in `common/`; agent files stay thin (handlers + orchestration only).

---

## 4. Commands


# Setup
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # then fill in values

# Run each agent in its own terminal (each is a separate process)
python -m agents.Agent_1
python -m agents.Agent_2
python -m agents.Agent_3
python -m agents.Agent_4
python -m agents.Agent_5

# Demo target app (local)
uvicorn demo_target_app.app:app --port 9000 --reload

# Everything at once
docker compose up --build

# Tests
pytest -q
pytest tests/test_osv_client.py -q        # single file
pytest -m integration -q                  # opt-in live OSV.dev call (deselected by default)

# Step 11 helpers (Windows PowerShell)
python -m scripts.seed_demo_repo [--create] [--reset]   # build the demo repo history (parent commit + faulty commit)
python -m scripts.show_addresses [--markdown]           # agent addresses from the seeds (never prints seeds)
.\scripts\start_demo.ps1 [-SkipPayment] [-NoDemoApp] [-Stop]   # demo app :9000 + all 5 agents in separate windows
```

When you add a new command or script, update this section.

---

## 5. The Five Agents 
> **Naming (renamed after Step 11):** the agents are named and filed by port: `Agent_1`=Sentinel-Orchestrator (8001), `Agent_2`=Telemetry-Watchdog (8002), `Agent_3`=Commit-Detective (8003), `Agent_4`=Vuln-CVE-Scanner (8004), `Agent_5`=Remediation-Executor (8005). Files are `agents/Agent_N.py`, run with `python -m agents.Agent_N`; READMEs are `agents/readmes/Agent_N.md`. The role names used in this document are descriptive roles for those agents. Seeds and addresses are unchanged.


All agents: `Agent(name=..., seed=<from env>, port=<port>, mailbox=True, publish_agent_details=True)` where supported by the installed uagents version. Each runs as its **own process** (do not put them in a `Bureau`, because each needs its own mailbox/Agentverse identity). Agents talk to each other by address, imported from `common/addresses.py`.

| Agent | Port | Seed env var | Responsibility |
|---|---|---|---|
| `Sentinel-Orchestrator` | 8001 | `ORCHESTRATOR_SEED` | ASI:One entry point, incident state machine, blast radius, payment gate |
| `Telemetry-Watchdog` | 8002 | `WATCHDOG_SEED` | Burst probe, continuous polling, chaos trigger, canary verification |
| `Commit-Detective` | 8003 | `DETECTIVE_SEED` | Fetch last N commits, correlate with failure, AST symbol map |
| `Vuln-CVE-Scanner` | 8004 | `SCANNER_SEED` | OSV.dev SCA, SAST, reachability, **patch gatekeeper** |
| `Remediation-Executor` | 8005 | `EXECUTOR_SEED` | Patch + rollback synthesis, Dorado verification, PR + SBOM, redeploy |

### 5.1 Sentinel-Orchestrator (`agents/Agent_1.py`)
- Implements the standard **chat protocol** (`chat_protocol_spec`) and the **payment protocol** (seller role).
- On every `ChatMessage`: **send `ChatAcknowledgement` first**, then process.
- Parses intent into `{repo_full_name, service_url, mode}` where `mode ∈ {"diagnose_and_heal", "security_audit", "chaos_test", "status"}`. Use regex first (URL + `owner/repo` patterns); fall back to ASI:One LLM only if regex fails.
- Owns the **incident state machine** (§7). Stores state in `ctx.storage` keyed by `incident_id`, and also remembers which ASI:One `sender` + session owns the incident so replies go to the right chat.
- Sends short progress `ChatMessage`s to the user at each stage (e.g. "🔍 Probing endpoints…", "🧬 Commit a8f921 identified…") so the chat never looks frozen.
- Computes the **Counterfactual Blast Radius** (§8) deterministically in Python — the LLM may phrase it, but must not compute the numbers.
- Fires `RequestPayment` (0.1 FET) — see the timing rule in §9.2.
- On `CommitPayment`: verify the tx (via `common/dorado.py`), then send `ExecuteRemediationCommand` to the executor; on `RemediationCompletionReport`, request a canary probe; on canary report, send the final recovery message. (`CompletePayment` is sent as soon as the Dorado payment is verified — decided in Step 9 — not after the canary.)

### 5.2 Telemetry-Watchdog (`agents/Agent_2.py`)
- Handles `HealthProbeRequest` → returns `HealthProbeReport`.
- Burst probe: probe every endpoint concurrently with `httpx.AsyncClient(timeout=10)`, **3 requests per endpoint**, record status, latency (ms, `time.perf_counter`), p50/p95 across the burst, UTC ISO-8601 timestamp, and an `error_snippet` built from the JSON body + `X-Error-File` / `X-Error-Line` headers (truncate to 1,000 chars).
- If `inject_chaos=True`: `POST {service_url}/admin/simulate-fault` before probing.
- `is_healthy = all endpoints returned 2xx`.
- **Implementation note (Step 5):** `HealthProbeReport.metrics` holds one `EndpointMetric` per individual request (3 per endpoint), so `failing_probes/total_probes` is a count over `metrics` and p50/p95 are recomputed with `common.probe.summarize()`. `error_snippet` format is `HTTP <code> <body>\nX-Error-File: <f>\nX-Error-Line: <n>`; parse it with `common.probe.parse_error_snippet()`. A target already down at first poll alerts once; after that only a healthy→unhealthy transition alerts.
- Continuous mode: `@agent.on_interval(period=WATCHDOG_INTERVAL_SECONDS)` polls registered URLs (from env `WATCHDOG_TARGETS`, comma-separated). On a new failure, notify the orchestrator with a `HealthProbeReport` (`incident_id` prefixed `auto-`). Never spam: only alert on a healthy→unhealthy transition.
- Network errors (DNS, TLS, timeout) are recorded as `status_code=0` with the exception class in `error_snippet` — never raise out of a handler.

### 5.3 Commit-Detective (`agents/Agent_3.py`)
- Handles `CommitCorrelationRequest` → `CommitEvidenceReport`.
- `GET /repos/{owner}/{repo}/commits?sha={branch}&per_page=5`, then `GET /repos/{owner}/{repo}/commits/{sha}` for each to get file `patch`es.
- Deterministic scoring first, LLM second:
  1. +50 if a changed file matches `X-Error-File` / traceback file,
  2. +30 if the diff hunk covers the reported error line,
  3. +15 if the diff text mentions the failing endpoint path,
  4. +5 for most recent commit before `failure_timestamp_utc`.
  Pick the top score; only if there's a tie or no signal, ask ASI:One to choose (JSON response) given commit messages and truncated diffs.
- `root_cause_explanation`: ASI:One, 2–4 sentences, grounded in the diff snippet.
- `active_ast_imports`: fetch the current content of all `.py` files at the repo root and `app/`/`src/` (cap at 30 files), run `common/ast_mapper.py`. Output both module names (`yaml`) and dotted call symbols (`yaml.load`) in one list.
- If the repo has no Python files, return an empty list — do not fail.

### 5.4 Vuln-CVE-Scanner (`agents/Agent_4.py`)
Two jobs:

**A. Scanning** — `VulnerabilityScanRequest` → `VulnerabilityReport`
- Fetch `requirements.txt` (and `pyproject.toml` / `package.json` if present). Parse only pinned `name==version` lines for PyPI; for npm use exact versions from `package.json` after stripping `^`/`~`.
- Normalize package names (PEP 503: lowercase, `_`/`.` → `-`).
- One `POST /v1/querybatch`. **Note:** querybatch returns only vuln IDs; to get severity, summary and fixed versions, call `GET https://api.osv.dev/v1/vulns/{id}` for each unique ID (concurrently, cache results in memory).
- `fixed_version`: smallest `fixed` event in `affected[].ranges[].events` for the matching package that is greater than the installed version. If none, `"unknown"`.
- Severity: use `database_specific.severity` if present, else derive from CVSS score (≥9 CRITICAL, ≥7 HIGH, ≥4 MEDIUM, else LOW), else `"UNKNOWN"`.
- Reachability: map package → import name (`pyyaml→yaml`, `beautifulsoup4→bs4`, `pillow→PIL`, `scikit-learn→sklearn`, `python-jose→jose`, `pyjwt→jwt`, default = normalized name with `-`→`_`). `is_reachable_in_ast = import name in active_ast_imports`. Classification shown to the user: `CRITICAL_EXPLOITABLE` (reachable) vs `LATENT_DEPENDENCY` (not reachable).
- SAST: run `common/sast_rules.py` on modified files + `Dockerfile`. Rules (each with `rule_id`, severity, regex, advice):
  - `HARDCODED_SECRET` — `AKIA[0-9A-Z]{16}`, `sk_(live|test)_[0-9a-zA-Z]{10,}`, `ghp_[0-9A-Za-z]{36}`, `github_pat_\w{20,}`, generic `(?i)(secret|password|api_key|token)\s*=\s*["'][^"']{8,}["']`
  - `UNSAFE_EVAL` — `\beval\(`, `\bexec\(`
  - `UNSAFE_DESERIALIZATION` — `yaml.load(` without `SafeLoader`/`safe_load`, `pickle.loads(`
  - `COMMAND_INJECTION` — `shell=True`, `os.system(`
  - `SQL_INJECTION` — f-string or `%`/`.format` inside a string starting with SELECT/INSERT/UPDATE/DELETE
  - `INSECURE_DOCKER` — no `USER` instruction, `FROM .*:latest`, `EXPOSE` of debug ports (5678, 9229)
- Optionally ask ASI:One to drop obvious false positives, but **never** let the LLM add findings that no rule produced.
- **Mask secrets** in `code_snippet` (keep first 6 chars + `****`). Never log or return a full secret.

> **Implementation note (Step 6):** part A is built (`agents/Agent_4.py`). The SBOM is generated on every scan and kept in `ctx.storage["sbom:<incident_id>"]`; `VulnerabilityReport` has no SBOM field (schema unchanged), so the executor rebuilds it with `common.sbom_generator` when opening the PR. The optional LLM false-positive filter is intentionally not implemented. Commit scoring lives in `common/commit_scoring.py`; shared agent construction in `common/agent_factory.py`.

**B. Adversarial Patch Gatekeeper** — `PatchVettingRequest` → `SecurityApprovalAttestation`
- Re-run all SAST rules on `patched_code_content`.
- Re-run OSV on `updated_requirements_txt`; every previously reachable CVE must be fixed (installed version ≥ `fixed_version`).
- Check the original runtime bug location no longer contains the faulty pattern (simple string/AST check provided by the executor in the request is acceptable).
- Check the patched file parses (`ast.parse`).
- If any check fails → `approved=False`, `attestation_hash=""`, specific `rejection_reasons`.
- If clean → `approved=True`, `attestation_hash = sha256(incident_id + target_file + unified_diff + updated_requirements_txt + scanner_address)` hex, and sign it with the agent identity if the uagents version exposes `ctx.agent.sign_digest`/equivalent (optional; hash alone is acceptable for the MVP).

> **Implementation note (Step 7, gatekeeper):** `PatchVettingRequest` has no "faulty pattern" field (schema unchanged), so the gatekeeper uses what it remembers from the scan: `ctx.storage["scan:<incident_id>"]` holds the branch, suspect commit SHA and the reachable CVEs. Checks (all in `common/gatekeeper.py`): (1) `unified_diff` equals the diff the Scanner recomputes from `main` and is non-empty; (2) the file parses; (3) every SAST rule is clean on the patched file; (4) at least one line the suspect commit added is gone; (5) every previously reachable CVE is gone and pinned ≥ `fixed_version`. With no stored scan (e.g. restart) rule 5 degrades to "no CRITICAL CVE remains" and rule 4 is skipped. `attestation_hash` follows the spec formula; it is not additionally signed. The display diff is built from secret-masked text on both sides (`common.patching.make_unified_diff`).

### 5.5 Remediation-Executor (`agents/Agent_5.py`)

> **Implementation note (Step 7, patch synthesis):** built: `PatchDraftRequest` → gatekeeper loop → `PatchDraftResult`. The loop is stateful, not blocking (`ctx.storage["loop:<incident_id>"]`; the Scanner's `SecurityApprovalAttestation` is handled in its own handler, only accepted from the Scanner's address and only if it matches the submitted draft); a 15 s sweeper fails loops with no verdict after 120 s. `PatchDraftRequest` carries no raw error snippet, so the LLM gets `root_cause_explanation` + the offending diff hunk. Order of work: deterministic hardening (`os.getenv` for secrets, `yaml.safe_load`, reachable-CVE bumps) is applied before prompting and re-applied on the LLM output; if ASI:One is unavailable the executor falls back to reverting the offending hunk (`common.patching.revert_hunk`). The original file is re-fetched each attempt and never stored (it may contain a secret). Max attempts: `PATCH_MAX_ATTEMPTS` (default 3). `ExecuteRemediationCommand` is described in the Step 10 note below.
> **Implementation note (Step 10):** `handle_execute_command` (logic in `common/remediation.py`, `run_remediation`). When the gatekeeper finishes, the Executor stores `pr:<incident_id>` (repo, target file, suspect commit, CVE/SAST findings, rollback availability, the hash the Scanner approved). On `ExecuteRemediationCommand` (accepted only from the Orchestrator; a duplicate returns the stored report from `exec:<id>` and writes nothing) it refuses, **before any GitHub write**, unless: the attestation hash recomputes from the content (`attestation_hash(..., scanner_address)`), equals the hash the Scanner approved and the patch is SAST-clean; and, when `SKIP_PAYMENT=false`, the Dorado tx re-verifies (`DoradoVerifier`, same wallet/price), the payer matches and the hash is unused in the Executor's own storage (`used_tx:<HASH>`, released if the run fails before a PR exists). Then: branch `sentinel/fix-<id>` from `main` head (an existing branch/PR from a partial run is reused), commit patched file + `requirements.txt` + `sbom.cdx.json` (CycloneDX 1.5 of the *patched* dependencies, listing only unresolved findings), open the PR with the §10 body, then POST the webhook with `X-Sentinel-Token` (`DEMO_ADMIN_TOKEN`). The webhook is only called if its path is `/admin/apply-hotfix` and, when `DEMO_SERVICE_URL` is set, its host matches (the token must not leak to arbitrary URLs). `ROLLBACK_COMMIT` commits the parent commit's version of the offending file (no attestation exists; payment is still re-verified). A failed webhook still returns `success=True, redeploy_triggered=False`; any refusal/GitHub failure sends `AgentErrorReport(stage="execute")`. Messages use the existing `RemediationCompletionReport` (there is no separate `RemediationResult`). The PR body omits the §10 "Failing endpoint" row (the executor is never told the probe result; `ExecuteRemediationCommand` is unchanged). The PR is never merged.

- `PatchDraftRequest` → builds two tracks:
  1. **Rollback**: the parent commit content of the offending file(s).
  2. **Forward patch**: ASI:One generates the full patched file (JSON response: `{"patched_code": "...", "explanation": "..."}`) given the original file, diff, error snippet and SAST findings. Then deterministically: bump each reachable CVE package in `requirements.txt` to `fixed_version`; replace secrets with `os.getenv("NAME")`.
  - Build `unified_diff` with `difflib.unified_diff`.
- Gatekeeper loop: send `PatchVettingRequest`; on rejection, feed `rejection_reasons` back into the LLM prompt and retry. **Max 3 attempts.** If still rejected, report failure to the orchestrator and offer rollback only.
- When approved, send the attestation to the orchestrator (it builds the user card).
- `ExecuteRemediationCommand` → in order:
  1. Verify the Dorado tx again (defense in depth): exists, succeeded, recipient = orchestrator wallet, amount ≥ `0.1 FET`, not already used (keep a set of used tx hashes in storage — replay protection).
  2. Create branch `sentinel/fix-<incident_id>` from `main` head SHA.
  3. Commit patched file, `requirements.txt`, and `sbom.cdx.json` via `PUT /contents/{path}` (needs the current blob `sha` for existing files).
  4. Open the PR with the body template in §10.
  5. If `service_reload_webhook` is set, `POST` to it (demo: `/admin/apply-hotfix`) with header `X-Sentinel-Token: $DEMO_ADMIN_TOKEN`.
  6. Return `RemediationCompletionReport`.

---

## 6. Message Schemas (`common/models.py`)

These are the contract between agents. **Copy them exactly; do not rename fields.** If you need a new field, add it with a default value so older messages still validate, and update this file.


from typing import List, Optional
from uagents import Model

# 1. Orchestrator -> Telemetry-Watchdog
class HealthProbeRequest(Model):
    incident_id: str
    service_url: str
    endpoints: List[str] = ["/health", "/api/checkout"]
    inject_chaos: bool = False
    is_canary_check: bool = False

class EndpointMetric(Model):
    endpoint: str
    status_code: int
    latency_ms: float
    error_snippet: Optional[str] = None
    timestamp_utc: str

class HealthProbeReport(Model):
    incident_id: str
    service_url: str
    is_healthy: bool
    is_canary_check: bool
    metrics: List[EndpointMetric]

# 2. Orchestrator -> Commit-Detective
class CommitCorrelationRequest(Model):
    incident_id: str
    repo_full_name: str
    branch: str = "main"
    failure_timestamp_utc: str
    failing_endpoint: str
    error_snippet: Optional[str] = None

class CommitEvidenceReport(Model):
    incident_id: str
    repo_full_name: str
    suspect_commit_sha: str
    suspect_commit_url: str
    author: str
    commit_message: str
    committed_at_utc: str
    offending_file: str
    offending_diff_snippet: str
    root_cause_explanation: str
    active_ast_imports: List[str]

# 3. Orchestrator -> Vuln-CVE-Scanner
class VulnerabilityScanRequest(Model):
    incident_id: str
    repo_full_name: str
    branch: str = "main"
    suspect_commit_sha: str
    modified_files: List[str]
    active_ast_imports: List[str]

class CVEFinding(Model):
    package_name: str
    installed_version: str
    fixed_version: str
    vuln_id: str          # GHSA-xxxx or CVE-YYYY-xxxx
    severity: str         # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    is_reachable_in_ast: bool
    summary: str

class SASTFinding(Model):
    file_path: str
    line_number: int
    rule_id: str          # HARDCODED_SECRET, SQL_INJECTION, UNSAFE_EVAL, UNSAFE_DESERIALIZATION, COMMAND_INJECTION, INSECURE_DOCKER
    severity: str
    code_snippet: str     # secrets MUST be masked
    remediation_advice: str

class VulnerabilityReport(Model):
    incident_id: str
    repo_full_name: str
    cve_findings: List[CVEFinding]
    sast_findings: List[SASTFinding]
    total_reachable_critical: int

# 4. Remediation-Executor <-> Vuln-CVE-Scanner
class PatchDraftRequest(Model):
    incident_id: str
    repo_full_name: str
    commit_evidence: CommitEvidenceReport
    vuln_report: VulnerabilityReport

class PatchVettingRequest(Model):
    incident_id: str
    repo_full_name: str
    target_file: str
    patched_code_content: str
    updated_requirements_txt: str
    unified_diff: str

class SecurityApprovalAttestation(Model):
    incident_id: str
    approved: bool
    attestation_hash: str
    rejection_reasons: List[str] = []
    target_file: str
    patched_code_content: str
    updated_requirements_txt: str
    unified_diff: str

# 5. Orchestrator -> Remediation-Executor
class ExecuteRemediationCommand(Model):
    incident_id: str
    repo_full_name: str
    action_type: str      # "OPEN_PR_AND_HOTFIX" | "ROLLBACK_COMMIT"
    dorado_tx_hash: str
    payer_wallet: str
    attestation: SecurityApprovalAttestation
    service_reload_webhook: Optional[str] = None

class RemediationCompletionReport(Model):
    incident_id: str
    success: bool
    pr_url: str
    sbom_file_url: str
    dorado_tx_hash: str
    dorado_explorer_url: str
    redeploy_triggered: bool
    summary_message: str


Additional small models you may add (keep them in the same file):
- `AgentErrorReport(incident_id: str, agent: str, stage: str, error: str)` — any agent sends this to the orchestrator instead of silently failing.
- `PatchDraftResult(incident_id: str, attestation: SecurityApprovalAttestation, rollback_available: bool, attempts: int)` — executor → orchestrator after the gatekeeper loop.

uAgents message size is limited — keep `patched_code_content` and diffs to single files and truncate snippets for display. If a payload could exceed ~200 KB, store the content on GitHub/branch and pass a reference instead.

---

## 7. Incident State Machine (Orchestrator)


RECEIVED → PROBING → CORRELATING → SCANNING → PATCHING → AWAITING_PAYMENT
        → EXECUTING → VERIFYING → RESOLVED
Any state → FAILED (with reason sent to user)


| Stage | Trigger | Orchestrator action |
|---|---|---|
| 1 Intent | `ChatMessage` | ack, parse, create `incident_id = "inc-" + uuid4().hex[:8]`, send `HealthProbeRequest` |
| 2 Probe | `HealthProbeReport` (non-canary) | if healthy and mode is heal → tell user + offer audit; else pick first failing endpoint, send `CommitCorrelationRequest` |
| 3 Correlate | `CommitEvidenceReport` | send `VulnerabilityScanRequest` |
| 4 Scan | `VulnerabilityReport` | send `PatchDraftRequest` to executor |
| 5 Patch | `PatchDraftResult` | build incident card text, **fire `RequestPayment` immediately**, then send the card |
| 6 Pay | `CommitPayment` | verify tx, send `ExecuteRemediationCommand` |
| 7 Execute | `RemediationCompletionReport` | send `HealthProbeRequest(is_canary_check=True)` |
| 7 Verify | `HealthProbeReport` (canary) | final recovery message, `CompletePayment`, `EndSessionContent` |

Rules:
- Every outgoing request includes `incident_id`; every handler first loads state by `incident_id` and ignores messages for unknown / already-finished incidents.
- Per-stage timeout (default 60 s, 120 s for patching): use an `on_interval` sweeper that marks stale incidents `FAILED` and tells the user which stage timed out.
- For `security_audit` mode: skip probing, go straight to Commit-Detective (for AST map) → Scanner → report. No payment.

> **Implementation note (Step 8):** `agents/Agent_1.py` implements stages 1-5 plus the user's decision. The installed chat protocol (`AgentChatProtocol` 0.3.0) has only text/resource/metadata/session/stream content — **no interactive-card type** — so the incident card is rich Markdown (`common/incident_card.py`); the native payment card will be the separate `RequestPayment` message. States actually used: `PROBING → CORRELATING → SCANNING → PATCHING → AWAITING_APPROVAL (SKIP_PAYMENT=true) | AWAITING_PAYMENT (payment required) → APPROVED`, terminal `RESOLVED | FAILED | CANCELLED`. `APPROVED` is the hook for steps 9-10 (payment sits in front of it; `ExecuteRemediationCommand` + canary verification sit after it). In step 8, approving only records the authorization — nothing is executed yet. With `SKIP_PAYMENT=false` an incident goes to `AWAITING_PAYMENT` and the real payment flow runs (Step 9 note in §9.2; the payment replaces the approve reply, typing `approve` just re-sends the request, `reject` cancels, unpaid incidents expire after 30 min). If the gatekeeper rejects every draft, the card offers `rollback` only (`action_type=ROLLBACK_COMMIT`). Watchdog `auto-` alerts open an incident for the last chatting user (or park it until the next chat message claims it). A2A messages are accepted only from the expected agent address. **Step 10:** after `APPROVED` (payment verified or dev bypass) the Orchestrator sends `ExecuteRemediationCommand` (state `EXECUTING`, 120 s timeout; webhook = `<service_url>/admin/apply-hotfix`), then on `RemediationCompletionReport` sends a canary `HealthProbeRequest` (`VERIFYING`, 60 s) and on the canary report sends the final before/after message (`RESOLVED` if healthy, otherwise `FAILED` with the PR link and an honest note). Deterministic helpers: `common/intent.py` (regex-first intent), `common/blast_radius.py` (§8). Uagents persists each agent's `ctx.storage` to `<address>_data.json` in the working directory (gitignored); tests run in a temp cwd for that reason.

---

## 8. Counterfactual Blast Radius (deterministic)

Inputs from env (with defaults) so the demo numbers are explainable:
`TRAFFIC_RPM=120`, `AVG_ORDER_VALUE_USD=40`, `CONVERSION_RATE=0.03`, `SLA_TARGET=0.999`.

```
failure_ratio        = failing_probes / total_probes
dropped_requests_hr  = TRAFFIC_RPM * 60 * failure_ratio
revenue_at_risk_hr   = dropped_requests_hr * CONVERSION_RATE * AVG_ORDER_VALUE_USD
minutes_since_commit = failure_time - suspect_commit_time
sla_budget_burn_pct  = (minutes_since_commit / (30*24*60 * (1 - SLA_TARGET))) * 100
credential_exposure  = minutes since the commit that introduced a HARDCODED_SECRET (if any)
score (0–100)        = min(100, 40*failure_ratio + 10*reachable_critical + 5*reachable_high + 20*(secrets>0) + 10*(p95>1000ms))
```

Show the formula assumptions in the card so judges see it's not invented.

---

## 9. Fetch.ai Rules (MUST follow)

### 9.1 Chat protocol
```python
from datetime import datetime, timezone
from uuid import uuid4
from uagents import Agent, Context, Protocol
from uagents_core.contrib.protocols.chat import (
    ChatAcknowledgement, ChatMessage, EndSessionContent,
    StartSessionContent, TextContent, chat_protocol_spec,
)

chat_proto = Protocol(spec=chat_protocol_spec)

@chat_proto.on_message(ChatMessage)
async def handle_chat(ctx: Context, sender: str, msg: ChatMessage):
    await ctx.send(sender, ChatAcknowledgement(
        timestamp=datetime.now(timezone.utc),
        acknowledged_msg_id=msg.msg_id,
    ))
    text = " ".join(c.text for c in msg.content if isinstance(c, TextContent))
    ...

@chat_proto.on_message(ChatAcknowledgement)
async def handle_ack(ctx: Context, sender: str, msg: ChatAcknowledgement):
    pass

orchestrator.include(chat_proto, publish_manifest=True)

Helper for replies (put in the orchestrator):

def make_chat(text: str, end_session: bool = False) -> ChatMessage:
    content = [TextContent(type="text", text=text)]
    if end_session:
        content.append(EndSessionContent(type="end-session"))
    return ChatMessage(timestamp=datetime.now(timezone.utc), msg_id=uuid4(), content=content)

Replies are Markdown — ASI:One renders it, so use headings, tables and code blocks for the incident card.

### 9.2 Payment protocol & the timing rule
- Use the payment protocol from `uagents_core.contrib.protocols.payment` (`RequestPayment`, `CommitPayment`, `CompletePayment`, `RejectPayment`, `CancelPayment`, `Funds`, `payment_protocol_spec`). Orchestrator uses the **seller** role. **Before writing this code, inspect the installed package** (`python -c "import uagents_core.contrib.protocols.payment as p; help(p)"`) and match the real field names — don't guess.
- **TIMING RULE:** in the handler that triggers payment, send `RequestPayment` **as the very first await**, before any LLM call or slow I/O. All data needed for the card must already be computed in earlier stages. A delay causes ASI:One to fall back to plain text instead of the native payment card.
- Amount: `0.1 FET` = `100000000000000000 atestfet` (18 decimals). Currency/denom per the protocol's `Funds` model; network Dorado testnet.
- Include `incident_id` in the payment `reference`/metadata so `CommitPayment` can be matched to the incident.

> **Implementation note (Step 9, verified against the installed `uagents_core` payment module):** `RequestPayment(accepted_funds: list[Funds], recipient, deadline_seconds, reference, description, metadata)`; `Funds(amount: str, currency, payment_method="fet_direct")`; `CommitPayment(funds, recipient, transaction_id, reference, description, metadata)` (`transaction_id` = the Dorado tx hash); `CompletePayment(transaction_id)`; `CancelPayment(transaction_id, reason)`; `RejectPayment(reason)`. `payment_protocol_spec` roles: **seller** handles {CommitPayment, RejectPayment}, **buyer** handles {RequestPayment, CancelPayment, CompletePayment}. So the Orchestrator registers `Protocol(spec=payment_protocol_spec, role="seller")` and **cannot send `RejectPayment`**: a payment it refuses is answered with `CancelPayment(reason)` (spec: CommitPayment → CompletePayment | CancelPayment). A user-sent `CancelPayment` is not in the seller role (the protocol is locked), so that handler is registered directly on the agent. Currency is `atestfet`, amount `REMEDIATION_PRICE_ATESTFET`. `RequestPayment` is the first await in `_request_authorization` and is sent **before** the incident card. Flow: `CommitPayment` → find the sender's `AWAITING_PAYMENT` incident (by `reference`, else the latest) → reserve `used_tx:<HASH>` in storage (replay + concurrency guard, released on failure) → `DoradoVerifier.verify` → `CompletePayment`, state `APPROVED`, `dorado_tx_hash` / `payer_wallet` stored. Refusals send `CancelPayment`, re-send `RequestPayment` (retry) and cancel the incident after 3 definitive failures (a tx that is simply not indexed yet does not count). `CompletePayment` is sent as soon as the payment is verified (not after the canary as §5.1 originally said). The Executor's defense-in-depth re-verification belongs to Step 10 and can reuse `common/dorado.py`.

### 9.3 Dorado verification (`common/dorado.py`)

from cosmpy.aerial.client import LedgerClient, NetworkConfig
client = LedgerClient(NetworkConfig.fetchai_stable_testnet())   # Dorado

> **Implementation note (Step 9):** `common/dorado.py` — `DoradoVerifier(fetch, attempts=5, delay=3.0, sleep)`; `fetch(tx_hash) -> TxInfo | None` is injectable (default `CosmpyFetcher`, cosmpy in `asyncio.to_thread`, client created lazily). Transfers are read from the per-message logs (the flattened `events` also contain the fee transfer). Also checks the tx is not older than the payment request (minus 2 min skew) and returns `PaymentVerification(ok, reason, definitive, tx_hash, payer, amount)`; `definitive=False` means undecided (not indexed / RPC trouble). Replay protection lives with the caller's storage.

Verify: tx found, `code == 0`, contains a bank `MsgSend` to `ORCHESTRATOR_WALLET_ADDRESS` with `atestfet` amount ≥ required, and hash not previously used. Retry lookup up to 5× with 3 s backoff (tx may not be indexed yet). Explorer link: `https://explore-dorado.fetch.ai/transactions/{tx_hash}` (make the base URL an env var).

### 9.4 ASI:One LLM (`common/asi1_client.py`)
- `POST https://api.asi1.ai/v1/chat/completions`, header `Authorization: Bearer $ASI1_API_KEY`, model from env `ASI1_MODEL` (default `asi1-mini`).
- Provide `chat_json(system, user, schema_hint) -> dict`: asks for JSON only, strips ```json fences, `json.loads`, one retry on parse failure, then raises `LLMError`.
- Timeout 30 s, temperature 0.2. Never send secrets (mask them first) or whole repositories to the LLM — truncate to what's needed.

### 9.5 Agentverse / ASI:One discoverability
- Every agent: `mailbox=True`, a clear `README`-style description (set via `Agent(..., readme_path=...)` or Agentverse UI), category **Innovation Lab**.
- Only the orchestrator needs the chat protocol for ASI:One; the other four only need their A2A protocols (still include chat on them if you want them individually discoverable).
- Log each agent's address on startup: `ctx.logger.info(f"Address: {agent.address}")`.

---

## 10. GitHub PR Body Template

```markdown
## 🛡️ Sentinel Auto-Remediation — {incident_id}

### Root Cause
| Field | Value |
|---|---|
| Suspect commit | [{short_sha}]({commit_url}) by @{author} |
| File | `{offending_file}` |
| Failing endpoint | `{endpoint}` → HTTP {status} @ {latency} ms |
| Explanation | {root_cause_explanation} |

### Security Findings Fixed
| ID | Package / Rule | Severity | Reachable | Fix |
|---|---|---|---|---|
...

### Change-Control Audit Trail
- **Dorado testnet tx:** [`{tx_hash}`]({explorer_url})
- **Authorized by wallet:** `{payer_wallet}`
- **Security attestation:** `{attestation_hash}` (Vuln-CVE-Scanner)
- **SBOM:** [`sbom.cdx.json`]({sbom_url}) (CycloneDX v1.5)

_Generated by the Sentinel multi-agent swarm on Fetch.ai._


---

## 11. Demo Target App (`demo_target_app/`)

A small FastAPI app (~60–100 lines) in a **separate GitHub repo we control** (`DEMO_REPO_FULL_NAME`). Requirements:
- Global `PATCHED = False` (or read from env) that switches behavior.
- `GET /health` → 200.
- `GET /api/checkout` → when not patched, raises `KeyError: 'discount_rate'`; an exception handler returns 500 with JSON `{"error": "KeyError", "detail": "'discount_rate'"}` and headers `X-Error-File: app.py`, `X-Error-Line: <real line number>`.
- Uses `yaml.load(...)` without SafeLoader somewhere active (reachability proof).
- A **fake** test key `STRIPE_SECRET_KEY = "sk_test_51SENTINELDEMOxxxxxxxx"` — must be obviously fake, never a real key.
- An f-string SQL query against an in-memory SQLite table.
- `requirements.txt` pins `pyyaml==5.3` and `urllib3==1.24.1` (known OSV hits) plus fastapi/uvicorn.
- `POST /admin/simulate-fault` → sets `PATCHED=False`; `POST /admin/apply-hotfix` → sets `PATCHED=True`. Both require header `X-Sentinel-Token == DEMO_ADMIN_TOKEN`.
- Insecure `Dockerfile`: `FROM python:latest`, no `USER`, `EXPOSE 5678`.
- The intentional bugs are **demo content**. Do not "fix" them in `demo_target_app/` unless asked — Sentinel is supposed to find them.

---

## 12. Environment Variables (`.env.example`)


# ASI:One
ASI1_API_KEY=
ASI1_MODEL=asi1-mini

# GitHub (fine-grained PAT: Contents RW + Pull requests RW on the demo repo only)
GITHUB_TOKEN=
DEMO_REPO_FULL_NAME=your-org/sentinel-target
DEMO_SERVICE_URL=https://sentinel-target.onrender.com
DEMO_ADMIN_TOKEN=change-me

# Agent seeds (unique, long, secret)
ORCHESTRATOR_SEED=
WATCHDOG_SEED=
DETECTIVE_SEED=
SCANNER_SEED=
EXECUTOR_SEED=

# Payment / chain
ORCHESTRATOR_WALLET_ADDRESS=fetch1...
REMEDIATION_PRICE_ATESTFET=100000000000000000
DORADO_EXPLORER_BASE=https://explore-dorado.fetch.ai/transactions

# Watchdog
WATCHDOG_TARGETS=
WATCHDOG_INTERVAL_SECONDS=60

# Blast radius assumptions
TRAFFIC_RPM=120
AVG_ORDER_VALUE_USD=40
CONVERSION_RATE=0.03
SLA_TARGET=0.999


Never commit `.env`. Never hardcode any of these values in source.

---

## 13. README Requirements (Fetch-A-Thon 3.0 checklist)

The README is graded. It must contain, in this order:
1. At the very top:
   ```markdown
   ![tag:innovationlab](https://img.shields.io/badge/innovationlab-3D8BD3)
   ![tag:hackathon](https://img.shields.io/badge/hackathon-5F43F1)
   ```
2. One-paragraph pitch + architecture diagram (ASCII is fine).
3. **Agent registry table**: Name | Address (`agent1q...`) | Agentverse profile URL | Port — for all 5 agents. Leave placeholders until real addresses exist; never invent addresses.
4. ASI:One shared chat URL (placeholder until recorded).
5. Demo video link (3–5 min).
6. Setup & run instructions, env vars, tech stack, and the sponsor tools used.

---

## 14. Coding Conventions

- **Async everywhere** in handlers. No blocking calls (`requests`, `time.sleep`, sync `cosmpy` calls run via `asyncio.to_thread`).
- Type hints on all functions. Small, pure functions in `common/` so they're unit-testable without agents.
- One shared `httpx.AsyncClient` per agent process (create on startup, close on shutdown).
- Handlers never raise: wrap the body in `try/except Exception`, log with `incident_id`, send `AgentErrorReport` to the orchestrator.
- Logging format: `[{incident_id}][{agent}][{stage}] message`. These logs appear in the demo video — keep them clean and readable, with emojis only at stage boundaries.
- Retries: GitHub/OSV/ASI:One — 3 attempts, exponential backoff (0.5 s, 1 s, 2 s), only on 5xx/timeouts; respect GitHub 403 rate-limit headers.
- Truncate anything shown to users or the LLM (diffs ≤ 4,000 chars, snippets ≤ 1,000).
- Prefer deterministic logic; use the LLM only for: intent fallback, root-cause wording, commit tie-break, patch generation, false-positive filtering.

## 15. Safety Rules (non-negotiable)

- The executor may only write to `DEMO_REPO_FULL_NAME` (or an explicit allowlist env var). Refuse any other repo.
- Never push to `main` directly — always a `sentinel/fix-*` branch + PR. Auto-merge is off by default.
- No PR without both: `approved=True` attestation **and** a verified, unused Dorado tx.
- Never log, store, or put into an LLM prompt a full secret value.
- The chaos/hotfix admin endpoints require the token header.

---

## 16. Build Order (do these in sequence; verify each before moving on)

1. `common/config.py`, `common/models.py`, `requirements.txt`, `.env.example` + `tests/test_models.py`.
2. `demo_target_app/` — run locally; confirm `/api/checkout` returns 500 and `/admin/apply-hotfix` flips it to 200.
3. Pure helpers with tests: `ast_mapper.py`, `sast_rules.py`, `osv_client.py` (one real call against OSV is fine in a marked integration test), `sbom_generator.py`.
4. `asi1_client.py` + `github_client.py`.
5. Telemetry-Watchdog alone (send it a `HealthProbeRequest` from a tiny test agent).
6. Commit-Detective, then Vuln-CVE-Scanner (scan path).
7. Remediation-Executor patch synthesis + Scanner gatekeeper loop.
8. Orchestrator chat flow end-to-end **without** payment (temporary `SKIP_PAYMENT=true` flag, default false, dev only).
9. Payment protocol + `dorado.py` verification.
10. PR creation + SBOM + webhook + canary.
11. Register on Agentverse, test from ASI:One, fill README.
12. `tests/test_end_to_end_pipeline.py` with `respx`-mocked externals.

After each step: run `pytest -q` and tell me what changed and what to test manually.

## 17. Working Agreement for Claude Code 

- Ask before adding a new dependency or changing a schema in §6.
- If a library API differs from what this file says (uagents / uagents-core / cosmpy versions change), **check the installed package source** and follow the real API, then note the correction in this file.
- Keep each agent file under ~400 lines; move logic to `common/`.
- Don't create mock/stub versions of external APIs in production code paths. Mocks live in `tests/` only.
- When unsure about demo behavior, prefer what makes the live 3–5 minute demo deterministic and visible.
