# LuminaFPM — Implementation Roadmap

> Derived from Volume 14 (phases), the dependency-aware build order in
> [CODEBASE_GAP_ANALYSIS.md](CODEBASE_GAP_ANALYSIS.md), and the mandate's P0–P10 priority order.
> **Never sacrifice** acquisition, normalization, anomaly detection (V14 Table 1).
> Gap totals: 311 items — 186 missing · 84 partial · 27 conflicting · 6 obsolete · 5 implemented · 3 unknown.

Each phase lists: goal · key work · **exit gate** (acceptance) · primary files. Work bottom-up; a
phase's exit gate must pass before the next phase is *trusted* (phases may overlap where independent).

---

## Phase 0 — Foundation  *(P0-blocker)*
**Goal:** a clean, configurable, migratable skeleton on the approved stack.
- `core/config.py` (typed settings), `core/logging.py` (structured + secret redaction),
  `core/security.py` (credential encryption + auth/RBAC helpers + global exception handlers).
- Introduce **Alembic**; retire `Base.metadata.create_all` from the runtime path; central `db/session.py`.
- Restrict CORS off wildcard; remove plaintext secrets from `.env`; align `.env.example` to V13 §6.
- Split Celery into per-job-type queues (`acquisition/normalization/analysis/cti/reporting`) with `task_routes`.
- Harden docker-compose: Postgres/Redis **internal-only**, healthchecks, worker services, Nginx prod frontend.

**Exit gate:** app boots via `alembic upgrade head`; config/logging centralized; no public DB/Redis ports;
CORS restricted; CI lint/build green.
**Files:** `backend/core/*`, `backend/alembic/*`, `backend/main.py`, `backend/celery_app.py`,
`docker-compose.yml`, `.env.example`.

## Phase 1 — Schema v4  *(P0-blocker / mandate P3, pulled early)*
**Goal:** freeze the data contract before backend logic (V14 §17).
- Extend `network_object` ownership (`device_id, vendor_id, vendor_object_id, vendor_uuid, raw_value, ts`).
- Extend `policy_rule` (canonical posture booleans, `normalized_content_hash`, `deleted_at`) + UNIQUE
  `(device_id, vdom_vsys, vendor_uuid)`.
- Extend `rule_anomaly` (confidence, evidence JSONB, recommendation, detection_mode, status,
  `analysis_run_id` FK; `related_rule_id` → Integer FK to policy_rule).
- Add: `normalized_object`, `object_normalization_mapping`, `normalized_service`,
  `service_normalization_mapping`, `risk_assessment`, `anomaly_execution_log`, `cti_indicator`,
  `cti_observation`, `llm_report`, `benchmark_case`, `benchmark_result`, `acquisition_job`,
  `raw_artifact`, `device_credential` (encrypted), `normalization_warning`, `rule_snapshot`.
- Seed vendors Fortinet + Palo Alto; **remove Cisco/ASA seeds**.

**Exit gate:** `alembic upgrade head` builds the full v4 schema on a clean DB; ERD matches
[DATABASE_SCHEMA_V4.md](DATABASE_SCHEMA_V4.md); model unit tests (NOT-NULL/enum/FK) pass.
**Files:** `backend/models/*`, `backend/alembic/versions/*`, `backend/seed_data.py`.

## Phase 2 — Acquisition layer  *(P1-core / mandate P1)*
**Goal:** real, read-only, async extraction from FortiGate + Palo Alto.
- `services/acquisition/`: `ConnectorInterface`, `registry` (dispatch on `vendor_type`),
  `FortiGateConnector` (FortiOS REST, Bearer), `PaloAltoConnector` (PAN-OS XML, keygen) — **read-only only**.
- `AcquisitionBundle` / `RawArtifact` + raw storage under `/raw_acquisition/...` with manifest + SHA-256
  (parser-replayable without re-polling).
- Encrypted `device_credential` store (decrypt only in worker memory; never to frontend/logs; rotatable).
- Celery acquisition tasks on the `acquisition` queue; `acquisition_job` state machine;
  `/api/v1/devices/{id}/poll`, `/jobs/...` polling endpoints. **Delete the synchronous `/sync` mock path.**

**Exit gate (V3 Table 30/34):** ACQ-FGT-001..004, ACQ-PA-001..004, ACQ-JOB-001, ACQ-ERR-001, ACQ-RAW-001
pass against the lab (or recorded fixtures); **no write/commit op anywhere in connectors** (grep gate).
**Files:** `backend/services/acquisition/*`, `backend/tasks/acquisition.py`, `backend/api/routes/devices.py`,
`backend/api/routes/jobs.py`.

## Phase 3 — Parsing  *(P1-core / mandate P2)*
**Goal:** vendor JSON/XML → structured parser models (no anomaly logic).
- `services/parsing/fortigate.py`, `services/parsing/paloalto.py`; replay from stored raw artifacts.

**Exit gate:** parser unit tests over FortiGate JSON + PAN XML fixtures produce complete parser models.
**Files:** `backend/services/parsing/*`, `backend/tests/fixtures/*`.

## Phase 4 — Normalization  *(P1-core / mandate P2)*
**Goal:** canonical normalized repository + correlation (the keystone).
- 12-step deterministic pipeline (NORMALIZATION_MODEL §10): canonical action/zone/logging/security/NAT/
  schedule; recursive group expansion + cycle detection; ANY_OBJECT/ANY_SERVICE; negation;
  object/service correlation with confidence; derived stable `vendor_uuid`; idempotent **upsert** on the
  re-sync key; soft-delete + snapshots + content hash; `normalization_warning` emission.

**Exit gate (V4 Table 21/23):** normalization test cases pass; **repeated poll creates no duplicates**;
equivalent FGT/PAN rules normalize to comparable structures; anomaly engine reads normalized data only.
**Files:** `backend/services/normalization/*`, `backend/tasks/normalization.py`.

## Phase 5 — Deterministic anomaly engine  *(P1-core / mandate P4)*
**Goal:** replace the mock with real detectors over normalized data.
- **Delete** `services/anomaly_engine.py` mock + random assignment in `tasks/anomaly.py`.
- Config-only core first (ANOMALY_ENGINE_SPEC §5): shadowing, conflict, redundancy, duplicate,
  overlapping, over-permissive, any-to-sensitive, unprotected-allow, missing/weak logging+profile,
  disabled-review, missing-description, temp-without-schedule, wide-port, object/service sprawl,
  zone-mismatch, + the two mandatory **cross-device** detectors.
- Full finding contract + `anomaly_execution_log` lifecycle; runs **only after** successful normalization.

**Exit gate:** every detector unit-tested; atomic benchmark cases detected; each finding links to the
exact rule with evidence; no fabricated/random data anywhere.
**Files:** `backend/services/anomaly/*`, `backend/tasks/anomaly.py`.

## Phase 6 — Benchmark framework  *(P1/P2 / mandate P5)*
**Goal:** prove correctness against ground truth.
- `benchmark_case`/`benchmark_result`; ~22 FGT + ~23 PAN dataset (no Cisco); evaluation runner;
  precision/recall/F1/FP/FN; regression gate after every engine change.

**Exit gate (V7 Table 7):** all core config-only anomalies detected in atomic cases; both cross-device
types detected; metrics computed; FNs triaged before UI polish.
**Files:** `backend/services/benchmark/*`, `backend/api/routes/benchmarks.py`, dataset fixtures.

## Phase 7 — Risk engine  *(P2 / mandate P6)*
**Goal:** separate 0–100 scoring with factor breakdown.
- Deterministic versioned scoring → `risk_assessment` (JSONB factor breakdown); recalc triggers
  (V8 Table 7); device/environment aggregation; `/api/v1/risks`.

**Exit gate:** unit tests assert expected score bands; tiers correct; factor breakdown persisted; recalc
fires on anomaly/CTI/asset changes without rewriting evidence.
**Files:** `backend/services/risk/*`, `backend/api/routes/risks.py`.

## Phase 8 — CTI engine (API-based)  *(P2 / mandate P7)*
**Goal:** legal, provider-abstracted enrichment feeding risk.
- `CTIProvider` abstraction + ≥1 adapter (NVD/CVE recommended first); indicator extraction (public
  only by default); correlate to rules/devices; `cti_indicator`/`cti_observation`; rate-limit + cache.
- **Demote** dark-web/Tor/Robin behind a disabled-by-default flag; remove from default compose + image.

**Exit gate:** indicator extraction excludes RFC1918 by default; ≥1 provider integrated + correlated;
CTI failure does not block the anomaly dashboard.
**Files:** `backend/services/cti/*`, `backend/api/routes/cti.py`, `docker-compose.yml`, `backend/Dockerfile`.

## Phase 9 — AI / LLM reporting  *(P3 / mandate P8)*
**Goal:** evidence-grounded SOC reports; AI never the anomaly authority.
- `LLMProvider` abstraction (Gemini/OpenAI/Ollama): `generate_cti_queries`, `summarize_cti_findings`,
  `generate_soc_report`, `generate_executive_summary`; store in `llm_report` with provider/model/
  prompt-version/evidence-refs/confidence/ts; deterministic fallback if LLM down.

**Exit gate:** reports cite DB evidence IDs; separate evidence vs interpretation; LLM-down path still
renders deterministic findings.
**Files:** `backend/services/llm/*`, `backend/services/reporting/*`, `backend/api/routes/reports.py`.

## Phase 10 — Visualization (React + TS + Cytoscape)  *(P3 / mandate P9)*
**Goal:** the required centers on the approved frontend stack.
- TS toolchain + typed API client; **Policy Explorer first** (validates normalized data); Anomaly Center,
  Risk Center, CTI Threat Center, Benchmark Center, Reports, Device Inventory, Settings.
- `GET /api/graph/policy-relationships` + **Cytoscape.js** logical graph (no traffic claims).

**Exit gate:** pages bind to real APIs; graph renders logical nodes/edges; no fabricated UI data; TS build clean.
**Files:** `frontend/*` (incremental JS→TS), `backend/api/routes/graph.py`.

## Phase 11 — Security & deployment hardening  *(P0 baseline early, finalized here / mandate P10)*
**Goal:** production-like, safe deployment.
- Real auth (session/JWT) + RBAC on every route; encrypted secrets; audit logging; rate limits;
  backup/restore scripts; health checks; HTTPS; finalized compose. Read-only firewall behavior verified
  by code review + grep gate.

**Exit gate (V12/V13):** all routes authenticated+authorized; secrets encrypted; Postgres/Redis private;
backup/restore tested; end-to-end acceptance run green.
**Files:** `backend/core/security.py`, `backend/api/*`, `docker-compose.yml`, `scripts/backup_restore.sh`.

---

## Open items to confirm with the client (from gap analysis §Risks)
1. **Migration baseline:** clean baseline-from-scratch vs reconcile existing populated DB.
2. **Derived `vendor_uuid` algorithm:** pin the exact formula (currently
   `sha256(device_id|vdom_vsys|vendor_rule_id|rule_name|vendor_path)`).
3. **detection_mode boundary:** explicit criteria separating `benchmark_simulated` from forbidden
   "fake live evidence" for conditional anomalies (unused/drift/age/hit-distribution).
4. **v1 anomaly coverage:** which of the 46 categories are in-scope for precision/recall acceptance
   (some are `future_enhanced`/CTI-coupled and not realistically coverable by ~45 config-only rules).
5. **Correlation confidence matrix + tie-breaks** for cross-device equivalence (drives false-positive rate).
6. **Auth mechanism** (JWT vs opaque token) and the authoritative per-endpoint RBAC matrix.
7. **LTI/Robin preservation:** confirm nothing must be kept as "future" before removal from default stack.
8. **Lab reachability** (FortiGate 192.168.55.10 / PAN 192.168.55.20) for real-connector + ACQ-* acceptance.

> These do not block Phases 0–1 (foundation + schema). They are answered before/within the phase that
> first depends on them and are tracked in [EXECUTION_LOG.md](EXECUTION_LOG.md).
