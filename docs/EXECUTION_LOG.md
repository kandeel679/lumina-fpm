# LuminaFPM — Execution Log

Chronological record of every meaningful implementation decision and change, per the mandate
(§6, §10). Newest entries at the bottom of each day. Each entry: **what changed · why · files ·
tests/verification · remaining.**

---

## 2026-06-22

### E-001 — Read all 14 specification volumes (authoritative intake)
- **What:** Extracted `Volumes/*.docx` → `Volumes/_extracted/*.txt` (python-docx) and read Volumes
  1–14 in full. Established the binding identity, 8-layer pipeline, Schema v4, 46-anomaly taxonomy,
  risk/CTI/AI contracts, security + deployment requirements, and the V14 phase order.
- **Why:** The mandate requires extracting requirements from the volumes, not the codebase.
- **Files:** `Volumes/_extracted/` (gitignored — regenerate from the .docx).
- **Verification:** All 14 volumes + tables read; key contracts cross-checked.

### E-002 — Specification & process deliverable docs authored
- **What:** Wrote `docs/CLAUDE_SCOPE_UNDERSTANDING.md`, `DATABASE_SCHEMA_V4.md`,
  `NORMALIZATION_MODEL.md`, `ANOMALY_ENGINE_SPEC.md`, `SECURITY_MODEL.md`, `BENCHMARK_FRAMEWORK.md`,
  `ARCHITECTURE_DECISIONS.md` (ADR-001..022 + LFPM-IMPL-001..009), `API_CONTRACT.md`.
- **Why:** Freeze the understanding/schema/normalized-model before backend logic (V14 §17).
- **Files:** `docs/*.md`.

### E-003 — Codebase gap analysis (50-agent spec-vs-code pass)
- **What:** Ran a structured workflow: one specialist per functional area read its authoritative
  volume + current code; high/conflicting claims were adversarially re-verified; a lead reconciled.
  Generated `docs/CODEBASE_GAP_ANALYSIS.md` (311 items: 186 missing · 84 partial · 27 conflicting ·
  6 obsolete · 5 implemented · 3 unknown) and `docs/IMPLEMENTATION_ROADMAP.md`.
- **Why:** Required "first output" + drives the prioritized plan.
- **Key conflicts confirmed:** mock anomaly engine (fabricated findings), synchronous mock `/sync`
  acquisition, off-direction dark-web/Tor CTI stack, no normalization/correlation model, `create_all`
  (no Alembic), Cisco/ASA seeds, no auth + wildcard CORS, incomplete `rule_anomaly` contract.

### E-004 — P0 foundation scaffolding (started)
- **What:**
  - Added `backend/core/` package: `config.py` (typed env-based settings, V13 §6; graceful fallback
    if `pydantic-settings` absent), `logging.py` (structured logging + `SecretRedactingFilter`, V12 §8).
  - `.gitignore`: exclude `Volumes/_extracted/` and `raw_acquisition/`.
  - `backend/models/models.py`: added timezone-aware `utcnow()` helper (replaces deprecated
    `datetime.utcnow`, V5 §14) — column defaults migrate to it as models are extended.
- **Why:** P0 prerequisites for every later layer (ADR LFPM-IMPL-002/003).
- **Files:** `backend/core/__init__.py`, `backend/core/config.py`, `backend/core/logging.py`,
  `.gitignore`, `backend/models/models.py`.
- **Remaining (this turn):** Schema v4 model extensions + new tables; Alembic scaffolding + baseline
  migration; `.env.example` alignment; compose hardening. Then Phase 2+ in subsequent turns.

### E-005 — Schema v4 implemented in SQLAlchemy models (Phase 1)
- **What:** Extended `backend/models/models.py`:
  - `network_object`: added `device_id, vendor_id, vendor_object_id, vendor_uuid, raw_value,
    created_at, updated_at` ownership fields + `idx_netobj_device_type_value` (V4 §7.3, V5 Table 12).
  - `policy_rule`: added canonical posture fields (`logging_enabled, logging_mode,
    security_inspection_enabled, security_profile_strength, schedule_scope`),
    `normalized_content_hash`, `deleted_at`; converted timestamp defaults to tz-aware `utcnow`.
    (The re-sync UNIQUE `(device_id, vdom_vsys, vendor_uuid)` partial index already existed.)
  - `rule_anomaly`: full V6 contract — `confidence, evidence(JSONB), recommendation, detection_mode,
    analysis_run_id(FK), status, suppression_*`; `related_rule_id` changed String→Integer FK to policy_rule.
  - Added 17 new tables: `normalized_object`, `object_normalization_mapping`, `service_object`,
    `normalized_service`, `service_normalization_mapping`, `normalization_warning`, `rule_snapshot`,
    `anomaly_execution_log`, `risk_assessment`, `cti_indicator`, `cti_observation`, `llm_report`,
    `benchmark_case`, `benchmark_result`, `acquisition_job`, `raw_artifact`, `device_credential` (encrypted).
- **Why:** Freeze Schema v4 before backend logic (V14 §17); matches DATABASE_SCHEMA_V4.md.
- **Verification:** Installed SQLAlchemy locally and ran `configure_mappers()` → **30 tables**, all
  relationships/FKs resolve. Caught + fixed an ambiguous-FK error on `PolicyRule.anomalies` (two FKs
  from rule_anomaly to policy_rule) by pinning `foreign_keys`.
- **Files:** `backend/models/models.py`.

### E-006 — Alembic introduced; create_all retired; foundation hardening (Phase 0)
- **What:**
  - Alembic scaffolding: `backend/alembic.ini`, `alembic/env.py` (URL + metadata from `core.config`;
    best-effort LTI metadata include), `alembic/script.py.mako`, and baseline migration
    `alembic/versions/0001_schema_v4_baseline.py` (model-driven create_all baseline; future revisions
    are incremental autogenerate).
  - `backend/main.py`: removed `Base.metadata.create_all` from lifespan (Alembic owns schema);
    **CORS** now uses `settings.cors_allowed_origins` (no wildcard+credentials); **removed the duplicate
    `include_router` block**; logging configured on startup.
  - `backend/entrypoint.sh`: runs `alembic upgrade head` before uvicorn; Tor now best-effort and gated
    behind `ENABLE_DARKWEB_INTEL` (non-fatal — dark-web is optional, ADR LFPM-IMPL-005).
  - `docker-compose.yml`: **Postgres & Redis no longer published to the host** (internal-only, V12/V13).
  - `backend/requirements.txt`: added `alembic`, `pydantic-settings`, `cryptography`.
  - `.env.example`: rewritten to the canonical V13 §6 variables (SECRET_KEY, ENCRYPTION_KEY,
    CORS_ALLOWED_ORIGINS, LLM_*, CTI_*, ENABLE_DARKWEB_INTEL, FIREWALL_TLS_VERIFY, …); legacy LTI/Tor
    vars commented as optional.
- **Why:** P0 foundation (ADR LFPM-IMPL-002/007); closes confirmed conflicts (create_all, CORS=*,
  duplicate routers, exposed DB/Redis).
- **Verification:** `py_compile` of main.py + core + models + alembic env/migration passed; `core.config`
  + `core.logging` import and run locally (fallback path) with working secret redaction.
- **⚠️ Operational note:** Existing dev DBs built via the old `create_all` must either be dropped &
  re-created, or stamped: `alembic stamp 0001_schema_v4_baseline`. Fresh DBs: `alembic upgrade head`
  (run automatically by the api entrypoint).
- **Remaining in Phase 0 (next turn):** `core/security.py` (auth/JWT, RBAC dependency, Fernet
  credential helpers, global exception handlers), Celery per-queue `task_routes` + worker-service split
  in compose, frontend prod build (Nginx) wiring.

### E-007 — Phase 2 Acquisition layer (read-only connectors + async jobs)
- **Decision input:** Client confirmed the lab VMs are up and API-reachable (GUI/CLI/SSH/API), so
  connectors are built **live-capable** and validated by fixture-based unit tests here.
- **What:**
  - `core/security.py`: Fernet credential encryption (`encrypt_secret`/`decrypt_secret`/`mask_secret`),
    keyed by `ENCRYPTION_KEY` (V12 §6). Round-trip verified.
  - `services/acquisition/` package (V3): `base.ConnectorInterface` + `ConnectorConfig`; `errors.py`
    (normalized codes AUTH_FAILED/CONNECTION_FAILED/TIMEOUT/… + retryable flags, V3 Table 23);
    `models.py` (`AcquisitionBundle`, `RawArtifact`, `AcquisitionStatus`); **`fortigate.py`**
    (FortiOS REST, Bearer, GET-only over the 6 required + 2 recommended endpoints, firmware extract);
    **`paloalto.py`** (PAN-OS XML, keygen/op/config-show, GET-only, firmware extract); `registry.py`
    (dispatch on vendor_type); `storage.py` (raw artifacts → `/raw_acquisition/{vendor}/{device}/{job}/`
    + manifest + per-artifact SHA-256, replayable).
  - `services/credentials.py`: encrypted device-credential CRUD (decrypt only in memory; never logged/returned).
  - `tasks/acquisition.py`: Celery `acquisition.poll_device` on the `acquisition` queue — loads device +
    credential, runs the connector, persists raw artifacts + `raw_artifact` rows, updates the
    `acquisition_job` lifecycle + device firmware/last_poll, maps connector errors → job status. Runs
    **only** in the worker (never the request cycle).
  - `api/routes/devices.py`: **removed the synchronous mock `/sync`**; added `POST /{id}/credentials`
    (write-only, encrypted), `POST /{id}/test-connection` (status only), `POST /{id}/poll` (202 → job id).
  - `api/routes/jobs.py`: `GET /jobs`, `GET /jobs/{id}`, `GET /jobs/{id}/artifacts` (metadata only).
  - `celery_app.py`: `task_routes` queue split (acquisition/normalization/analysis/cti/reporting);
    registered `tasks.acquisition`. `main.py`: mounted the jobs router.
- **Read-only guarantee:** connectors issue GET/keygen/op-show only; no set/edit/delete/move/commit
  path exists (V3 Table 24, V12 §3).
- **Verification:** `py_compile` of all 16 files; **`backend/tests/test_acquisition.py` passes** —
  FortiGate collect (8 artifacts, firmware v7.4.1), partial-success on optional-endpoint 404,
  Palo Alto collect (firmware 11.1.3), and storage manifest + SHA-256 + replay. No network/DB needed.
- **Orphaned:** `services/connectors/mock_connector.py` is now unimported (removed from the prod path);
  safe to delete in a cleanup pass.
- **Files:** `backend/core/security.py`, `backend/services/acquisition/*`, `backend/services/credentials.py`,
  `backend/tasks/acquisition.py`, `backend/api/routes/devices.py`, `backend/api/routes/jobs.py`,
  `backend/celery_app.py`, `backend/main.py`, `backend/tests/test_acquisition.py`.

> **Live validation (team, against the lab):** rebuild → `POST /api/v1/devices` (vendor_type
> fortinet/paloalto, management_ip 192.168.55.10 / .20) → `POST /{id}/credentials` → `POST
> /{id}/test-connection` → `POST /{id}/poll` → `GET /jobs/{id}`. Set `ENCRYPTION_KEY` and (lab)
> `FIREWALL_TLS_VERIFY=false` for self-signed certs.

### E-008 — Phase 3 Parsing + connector fix from real lab artifacts
- **Input:** Client provided **real** captured API output — FortiOS **v7.0.5** `firewall/policy` JSON
  (rule `FGT_ALLOW_WEB`) and a PAN-OS `rulebase` XML (rule `PA_ALLOW_WEB`). Both are the *same logical
  access*: LAN_NET → WEB_SERVER, HTTPS, allow, **no inspection** (FGT `utm-status:disable`/empty
  `profile-group`; PAN no `profile-setting`) — a textbook cross-device pair + dual "unprotected allow".
- **Connector fix (from real data):** PAN-OS connector now uses the **proven unqualified xpath**
  `/config/devices/entry/vsys/entry/<leaf>` (the lab query worked without `[@name=...]` predicates);
  removed the hardcoded device/vsys name predicates.
- **What (Phase 3):** `services/parsing/` package — `models.py` (uniform `ParsedRule`/`ParsedAddress*`/
  `ParsedService*`/`ParsedDevicePayload`, raw vendor values preserved), `fortigate.py` (FortiOS JSON →
  parsed; subnet→CIDR, firmware from top-level `version`, profiles, negation), `paloalto.py` (PAN XML →
  parsed via **defusedxml** with stdlib fallback; zones/members/log/profile-setting), `registry.py`
  (dispatch). Parsers do extraction only — no canonicalization (that is normalization's job).
- **Fixtures captured:** `backend/tests/fixtures/fortigate_policy.json`,
  `backend/tests/fixtures/paloalto_rulebase.xml` (the real lab responses) — regression evidence.
- **Verification:** `backend/tests/test_parsing.py` passes — FortiGate parse (fw v7.0.5, action accept,
  LAN_NET→WEB_SERVER HTTPS, logging on, no profile), Palo Alto parse (action allow, trust→dmz,
  log-end yes, no profile), and cross-vendor equivalence at the parse level. `defusedxml` added to
  requirements (V12 §10).
- **Files:** `backend/services/parsing/*`, `backend/services/acquisition/paloalto.py`,
  `backend/tests/fixtures/*`, `backend/tests/test_parsing.py`, `backend/requirements.txt`.

> **Next:** Phase 4 **Normalization** (the keystone) — canonical action/zone/logging/inspection mapping,
> object & service **correlation model** with confidence, recursive group expansion + cycle detection,
> derived stable `vendor_uuid`, idempotent **upsert** on `(device_id, vdom_vsys, vendor_uuid)` into the
> normalized repository, snapshots + `normalization_warning`. Then Phase 5 deterministic anomaly engine.
> **Helpful for live validation:** address/service object dumps (`firewall/address` + `firewall.service/
> custom` for FGT; `address` + `service` for PAN) so correlation (LAN_NET→CIDR, WEB_SERVER→IP) is
> validated against real objects.

### E-009 — Phase 4 Normalization engine (the keystone) — pure + proven on real lab data
- **Input:** Client provided the **real** object/service inventory for both firewalls — FortiGate
  `firewall/address` (20 objs incl. ipmask/iprange/fqdn/`all`), `addrgrp`, 87 custom `services`,
  service `groups`; Palo Alto `address` (clean CIDRs), `service` (incl. predefined-style names),
  `service-group` (address-group returned "No such node" — none defined).
- **What:** `services/normalization/` package —
  - `canonical.py`: canonical action map (FGT accept→allow; PAN allow/deny/drop/reset), logging &
    inspection abstraction (→ true/false/unknown), ANY detection (`all`/0.0.0.0/0), object/service
    canonical keys, **PAN predefined-service map** (`service-https`→tcp/443), derived stable
    `vendor_uuid`, content hash, sensitivity inference.
  - `engine.py`: deterministic `normalize_payloads()` — cross-vendor **object & service correlation**
    with confidence (V4 Table 11), rule canonicalization, object/service resolution (incl. predefined
    + unresolved warnings), normalized content hash. **Pure (no DB), idempotent.**
  - `model.py`: `NormalizationResult` (normalized objects/services + mappings + canonical rules + warnings).
- **Parser improvements from real shapes:** FortiGate `iprange` handling; Palo Alto `service-group` parsing.
- **Verification:** `backend/tests/test_normalization.py` passes on **real fixtures** —
  - `LAN_NET` (10.10.10.0/24) and `WEB_SERVER` (10.10.20.10/32) **correlate across FortiGate + Palo Alto**
    to one canonical object each (confidence 1.00, both devices).
  - HTTPS service correlates; PAN rule's predefined **`service-https` resolves to the same tcp/443**
    canonical service as FortiGate's custom HTTPS.
  - Both rules normalize to **action=allow, logging=true, inspection=false (unprotected allow)** with
    **identical canonical access sets** → cross-device equivalent; distinct content hashes per device.
  - Determinism: repeated runs produce identical hashes.
  All real fixtures saved under `backend/tests/fixtures/` (regression evidence).
- **Decisions:** ADR LFPM-IMPL-010 (separate `service_object` + add `rule_service_mapping` in migration
  0002), LFPM-IMPL-011 (pure engine + thin persist layer).
- **Files:** `backend/services/normalization/*`, `backend/services/parsing/{fortigate,paloalto}.py`,
  `backend/tests/test_normalization.py`, `backend/tests/fixtures/*`.

> **Next (Phase 4 completion):** `persist.py` + migration 0002 (`rule_service_mapping`) to write the
> NormalizationResult into Schema v4 via idempotent upsert on `(device_id, vdom_vsys, vendor_uuid)`,
> + `tasks/normalization.py` chaining acquire→parse→normalize, validated against the live lab DB.
> **Then Phase 5:** the deterministic anomaly engine (replace the mock) — its first real win is already
> set up: FGT_ALLOW_WEB and PA_ALLOW_WEB are a cross-device-equivalent, dual unprotected-allow pair.

### E-010 — Phase 4 completion + Phase 5 anomaly engine (multi-agent build + integration review)
- **What:** Ran a dynamic workflow (parallel authoring against a pinned integration contract) to build:
  - **Schema:** `RuleServiceMapping` model + migration `0002_rule_service_mapping` (rule↔service axis,
    ADR LFPM-IMPL-010). Now **31 tables**, mappers configure clean.
  - **Persist + loader:** `services/normalization/persist.py` (idempotent upsert of the NormalizationResult
    into Schema v4 by natural keys; PolicyRule upsert on `(device_id, vdom_vsys, vendor_uuid)`) and
    `services/normalization/loader.py` (reconstructs the canonical model from persisted rows so the anomaly
    engine reads the **normalized repository**; canonical keys byte-identical to the engine's).
  - **Chaining task:** `tasks/normalization.py` (`normalization.normalize_device`): replay raw artifacts →
    parse → normalize → persist → enqueue analysis. `tasks/acquisition.py` enqueues it on success/partial;
    `celery_app.py` includes `tasks.normalization`.
  - **Deterministic anomaly engine:** `services/anomaly/` (model `Finding`, `detectors.py` with the
    config-only core — unprotected_allow, missing_logging, any_to_sensitive, overly_permissive,
    wide_port_range, missing_description, disabled_rule_review, object_sprawl, duplicate, redundancy,
    shadowing, conflict, cross_device_inconsistency, cross_device_security_posture_inconsistency — and
    `engine.analyze()`). Deletes the random mock `services/anomaly_engine.py`.
  - **Anomaly task:** `tasks/anomaly.py` rewritten — task `analysis.run_anomaly_analysis`, queue `analysis`,
    callable `run_anomaly_analysis_task(device_id=None)`: creates `AnomalyExecutionLog`, loads the normalized
    repo, runs `analyze`, maps `Finding.rule_uuid`→`PolicyRule.rule_id`, writes full-contract `RuleAnomaly`
    rows, finalizes the run. **No randomness, no LLM, no raw-data analysis.**
- **Integration review (I stopped the workflow before its verifier stage and reviewed each module myself):**
  detectors are deterministic + read-only; loader keys round-trip with the engine; persist is idempotent and
  correctly maps the PAN predefined `service-https` to the shared `tcp:443-443` normalized service; migration
  0002 matches the model; the broken-import the user flagged is gone (tasks/anomaly.py no longer imports the
  deleted mock; the lazy import in tasks/normalization.py:102 now resolves).
- **Cleanup:** removed the orphaned `services/connectors/mock_connector.py` (dead, off the prod path).
- **Verification:** `py_compile` all; **31 tables**; full suite green —
  `test_acquisition`, `test_parsing`, `test_normalization`, **`test_anomaly`** (real-fixture ground truth:
  exactly 2 unprotected_allow + 2 missing_description, NO false cross-device finding; crafted unit tests for
  shadowing/duplicate/conflict/any_to_sensitive/overly_permissive; determinism). DB-dependent modules
  (persist/loader/normalize task) are reviewed-correct and await live-lab validation.
- **Pipeline now wired end-to-end:** poll_device → normalize_device → run_anomaly_analysis_task.

> **Next:** live-lab run of the full chain (poll → normalize → analyze) to validate persist/loader against
> Postgres; then Phase 6 Benchmark, Phase 7 Risk, Phase 8 CTI (API-based realign), Phase 9 AI reporting,
> Phase 10 frontend (TS + Cytoscape).

### E-011 — Fix: device vendor_type (blocker for the live run)
- **Bug:** `FirewallDevice` had no `vendor_type` column, but `tasks/acquisition.py`, `api/routes/devices.py`,
  and connector dispatch read `device.vendor_type` → would `AttributeError` at test-connection/poll.
- **Fix:** Added `firewall_device.vendor_type` (nullable, V3 Table 8) + `DeviceBase.vendor_type` (optional) +
  migration `0003_device_vendor_type`. Added `normalize_vendor_type()` + `resolve_device_vendor_type(device)`
  to the connector registry (resolves explicit vendor_type, else derives from the related vendor's
  name/api_type) and used it in the poll/test-connection/credential-config paths and the acquisition task
  (fails the job cleanly if it cannot be determined).
- **Verify:** py_compile OK; resolver unit-checked (Palo Alto Networks/FortiOS-REST → paloalto/fortinet);
  full suite green; 32→ still 31 core tables (column add, no new table).
- **Files:** `models/models.py`, `schemas/pydantic_schemas.py`, `services/acquisition/registry.py` + `__init__.py`,
  `api/routes/devices.py`, `tasks/acquisition.py`, `alembic/versions/0003_device_vendor_type.py`.

### E-012 — Anomaly API + lab benchmark provisioner (live-run enablement)
- **Anomaly API** (`api/routes/anomalies.py`, mounted in main.py):
  * `POST /api/v1/anomalies/run` — trigger analysis; **omit device_id for an all-scope run** (required for
    cross-device detectors). Dispatches the `analysis` Celery task.
  * `GET /api/v1/anomalies` — list findings (filters: severity/type/status/device/run; joins policy_rule
    for device context); `GET /api/v1/anomalies/{id}`; `GET /api/v1/anomalies/runs` (execution logs).
  * `PATCH /api/v1/anomalies/{id}` — analyst lifecycle (resolve/suppress/accept_risk/false_positive),
    reason required for suppression; never deletes history (V6 §12).
- **Lab provisioner** (`lab/` — **NOT part of the read-only platform**, ADR boundary preserved):
  * `lab/benchmark_dataset.py` — phase-1 logical rule specs (FortiGate + Palo Alto) with design ground
    truth covering the config-only taxonomy (shadowing, redundancy, duplicate, conflict, overly_permissive,
    any_to_sensitive, unprotected_allow, missing_logging, wide_port_range, missing_description,
    disabled_rule_review, cross_device_inconsistency) using the existing lab baseline objects.
  * `lab/provision_benchmark.py` — translates specs → FortiGate REST POST / Palo Alto XML set+commit;
    **default --dry-run** (no network), `--apply --confirm` to push with a **separate write credential**;
    exports ground-truth JSON (33 expected-anomaly cases + 1 cross-device pair) for the Phase-6 runner.
  * `lab/README.md` + gitignore for the generated `benchmark_ground_truth.json`.
- **Verify:** py_compile OK; provisioner `--dry-run` emits correct vendor payloads + ground truth; full
  backend suite green; 31 tables; 13 routers mounted.
- **Read-only guarantee intact:** the platform never writes to firewalls; provisioning is explicit operator
  tooling under `lab/` with a distinct write credential.

### E-013 — Compose fix: Celery worker must consume all routed queues
- **Bug:** `docker-compose.yml` started the worker with no `-Q`, so it only drained the default `celery`
  queue. With `task_routes` sending tasks to `acquisition`/`normalization`/`analysis`/`cti`/`reporting`,
  poll/normalize/analyze tasks would queue forever and the live run would silently stall.
- **Fix:** worker command now includes `-Q acquisition,normalization,analysis,cti,reporting,celery`.
- **File:** `docker-compose.yml`.

### E-014 — First live end-to-end run against the lab (both vendors) + benchmark
- **Brought the stack up against the real lab** (FortiGate 192.168.55.10, Palo Alto 192.168.55.20).
  Fixed an `.env` mismatch (DATABASE_URL password/db name vs POSTGRES_*); clean `down -v` + migrate.
- **Lab connectivity (firewall-side, not Lumina):**
  * FortiGate VM admin **HTTPS never binds 443** on this box. Root causes found in order: SSL-VPN
    occupying 443 (moved to 10443), then `admin-https-ssl-versions=tlsv1-2` paired with **TLS-1.3-only
    ciphersuites** (firmware has no `tlsv1-3`), so the admin TLS listener has no usable cipher and drops
    every handshake (0-byte EOF). The REST API **does** work over **HTTP/80**.
  * Palo Alto mgmt plane was intermittently unresponsive under host resource contention; revived.
- **Lab-gated HTTP escape hatch (code):** new setting `FIREWALL_INSECURE_HTTP_HOSTS` (CSV of management
  IPs reached over plain HTTP because their HTTPS admin is unavailable). `ConnectorConfig.scheme`
  (`https` default) is honored by the FortiGate connector; wired from the device route + acquisition task;
  provisioner gained `--fgt-scheme`. **Production stays HTTPS-only** — the host must be explicitly listed.
  Files: `core/config.py`, `services/acquisition/base.py`, `services/acquisition/fortigate.py`,
  `api/routes/devices.py`, `tasks/acquisition.py`, `lab/provision_benchmark.py`, `.env.example`.
- **Cross-vendor correlation proven on live data:** baseline LAN/DMZ/DB objects + WEB/DB/ADMIN/MALICIOUS
  hosts are defined identically on both vendors and collapse to 9 shared canonical `normalized_object`s
  (each backed by 2 vendor objects); FortiGate-only objects (FQDN/ISDB/SSLVPN) correctly stay uncorrelated.
- **Benchmark pushed (Step 5):** FortiGate hit its **unlicensed-VM policy cap (10)** — swapped the
  redundant `FGT_ADMIN_DB_NOLOG` (missing_logging also covered by `FGT_ANY_DB`) for the cross-device
  keystone `FGT_DB_ACCESS_XDEV`. Palo Alto: profile-group `lumina-inspect` + 8 rules + commit (OK).
  Final live policy sets: FGT 10, PA 8.
- **All-scope analysis (run 9): 38 findings across 12 anomaly types**, deterministic, evidence-backed:
  unprotected_allow(8), missing_description(6), conflict(5), missing_logging(5), duplicate_rules(4),
  cross_device_security_posture_inconsistency(2), redundancy(2), any_to_sensitive(2),
  **cross_device_inconsistency(1)** (FGT allow vs PA deny, same canonical LAN→DB:MYSQL — the keystone),
  shadowing(1), wide_port_range(1), overly_permissive(1).
- **Observed gap (to fix next):** FortiGate `shadowing`/`redundancy` did NOT fire while Palo Alto's
  identical designs did, and FortiGate `conflict` (overlap-based) did fire. Hypothesis: the FortiGate
  `ALL` service normalizes to a form that passes *overlap* but fails *superset (⊇)* checks (the canonical
  ANY_SERVICE sentinel), so shadowing/redundancy supersets miss. Needs a normalization fix + unit test.
  Also `disabled_rule_review` and `object_sprawl` not exercised (DISABLED rule omitted for the policy cap;
  object count below the sprawl threshold).

### E-015 — Fix: FortiGate `ALL` service must normalize to canonical ANY (closes E-014 gap)
- **Root cause:** FortiGate's predefined `ALL` service carries no tcp/udp port range, so the parser
  yielded `protocol=None, ports=None` → `service_key(None,None,None)` = `unknown:any`, NOT the
  `ANY_SERVICE_KEY` (`any:any`). Superset-based `detect_shadowing`/`detect_redundancy` (`_covers`) never
  saw the ANY sentinel, so every FortiGate pair using `ALL` was missed; overlap-based `detect_conflict`
  (`_sets_overlap`) still fired via the shared `unknown:any` key, which masked the bug. PAN's `any`
  resolved correctly via `PREDEFINED_SERVICES`, so only FortiGate was affected.
- **Fix:** `canonical.canonical_service()` + `is_any_service()` map `ALL`/`any` → ANY service and
  `ALL_TCP`/`ALL_UDP`/`ALL_ICMP` → full ranges; applied in `engine._correlate_services` (canonical key
  AND stored protocol/ports, so the loader stays consistent) and as an `is_any_service` fallback in
  `_resolve_services`. Files: `services/normalization/canonical.py`, `services/normalization/engine.py`.
- **Tests:** canonical unit test + a normalization regression (FortiGate `ALL` shadowing + redundancy
  must fire) in `tests/test_anomaly.py`. Full backend suite green.
- **Verified live:** all-scope run now reports FortiGate `shadowing`(1) + `redundancy`(5); total
  findings 38 → 46. The detector engine treats FortiGate and Palo Alto `all`/`any` services identically.

### E-016 — Phase 6: benchmark scoring (precision/recall/F1) — the acceptance gate
- **Built the benchmark subsystem (V7):** pure scorer + DB runner + API, scoring the deterministic
  engine against the ground-truth matrix.
  * `services/benchmark/scorer.py` — pure TP/FP/FN + precision/recall/F1 + severity-match. Matches at
    (rule, anomaly_type) granularity; **cross-device cases match if the anomaly appears on EITHER
    paired rule** (the engine attributes a cross-device finding to one side).
  * `services/benchmark/ground_truth.py` — the `benchmark_case` seed (mirrors `lab/benchmark_dataset.py`),
    **completed** so every expected anomaly per rule is enumerated; expected severity per TYPE (V6 Table 7).
  * `services/benchmark/runner.py` — resolves ground truth to the **deployed** rules, loads `rule_anomaly`
    for a run, scores, persists `benchmark_case` + `benchmark_result`. Cap-dropped rules are excluded
    (not counted as false negatives).
  * `api/routes/benchmark.py` — `POST /api/v1/benchmark/run`, `GET /report` (mounted in `main.py`).
- **Completed the design ground truth** (`lab/benchmark_dataset.py`): added design-derived incidental
  anomalies (`conflict`/`redundancy`/`duplicate_rules`) + the cross-device posture pairs, so precision
  is meaningful (the engine's real extra findings are recognized as true positives, not FPs).
- **Engine fix surfaced by the benchmark:** `cross_device_inconsistency` severity `high` → `critical`
  (V6 Table 7 / V7 §8 — a conflicting access decision is critical).
- **Tests:** `tests/test_benchmark.py` (perfect match, FN→recall, FP→precision, cross-device pair match,
  severity mismatch). Full backend suite green.
- **LIVE RESULT (run 12, FGT 10 + PA 8 deployed):** **41 expected cases across 12 anomaly types →
  precision 1.0, recall 1.0, F1 1.0, severity-match 1.0, FP 0, FN 0.** Persisted to `benchmark_result`.
- **Scope:** `config_only` taxonomy only (Bucket A). Conditional/simulated/future detectors (Bucket C)
  and the not-yet-implemented config_only types (Bucket B) are out of this scorecard by design.

### E-017 — Phase 7: deterministic risk scoring (0-100) engine
- **Built the risk subsystem (V8):** pure scorer + DB runner + API — a deterministic, versioned 0-100
  score per rule and device with a factor breakdown.
  * `services/risk/scorer.py` — `risk = min(100, anomaly + exposure + asset_sensitivity +
    security_posture + logging + cross_vendor + cti + lifecycle)`; factors derived from the rule's
    findings, each bounded to its V8 Table 4 range; tiers 90/70/40/1 (V8 Table 2). Device risk = a
    max-weighted blend of the top-5 rule risks + a critical-count modifier (V8 §8). `RISK_VERSION 1.0.0`.
  * `services/risk/runner.py` — scores every deployed rule from `rule_anomaly` for a run, aggregates per
    device, persists `risk_assessment` (rule + device scopes). Idempotent per run; keeps history.
  * `api/routes/risk.py` — `POST /api/v1/risk/run`, `GET /api/v1/risk?scope_type=rule|device`.
- **Wired lifecycle step 8 (V6 §11):** the anomaly analysis task now triggers risk recalculation for the
  run (best-effort — a risk failure never fails the analysis). `tasks/anomaly.py`.
- **Tests:** `tests/test_risk.py` — tier bands, clean→informational, governance→low, unprotected→medium,
  broad-unprotected-unlogged→critical, cross-device cross_vendor factor, cap at 100, device blend.
- **LIVE RESULT (run 13):** device risk FortiGate 92 / Palo Alto 99 (critical). Top rules: `ANY_DB`/
  `ANY_ANY` 98-99 critical; cross-device XDEV/posture rules 64-67 medium; plain unprotected web allows
  44 medium; redundant/governance low. Factor breakdown stored per rule (why it scored high).
- **Scope:** config_only factors. `cti_score` and `lifecycle_score` are stubs until Phase 8 (CTI) and
  the Bucket-C lifecycle data (snapshots/telemetry) land.
