# LuminaFPM — Architecture Decision Registry

> Binding ADRs from **Volume 1 Table 17** / **Volume 2 Table 19**, plus implementation-level
> decisions (LFPM-IMPL-*) made by the implementation team to realize them.
> Per V1 §19: **any deviation from a binding ADR requires a design change request before
> implementation.**

## A. Binding product ADRs (from the volumes)

| ID | Decision | Final choice |
|---|---|---|
| ADR-001 | Project identity | Firewall Anomaly Management Platform |
| ADR-002 | Primary innovation | Cross-vendor anomaly detection |
| ADR-003 | Supported vendors v1 | Fortinet + Palo Alto |
| ADR-004 | Cisco references | Remove from final v1 implementation |
| ADR-005 | Lab architecture | Hybrid Parallel Shared-Network |
| ADR-006 | Traffic analysis | No live traffic analysis |
| ADR-007 | Topology graph | Logical policy graph (not packet flow) |
| ADR-008 | Source of truth | PostgreSQL |
| ADR-009 | Normalized JSON | Interchange/model format, not DB source of truth |
| ADR-010 | Anomaly input | Normalized policies only |
| ADR-011 | Runtime anomalies | Conditional + benchmark-simulated |
| ADR-012 | CTI architecture | Separate risk engine |
| ADR-013 | AI role | Query generation, CTI review, SOC reporting (not anomaly authority) |
| ADR-014 | Backend | FastAPI |
| ADR-015 | Frontend | React + TypeScript |
| ADR-016 | Workers | Celery + Redis |
| ADR-017 | Graph library | Cytoscape.js |
| ADR-018 | Deployment | Docker Compose |
| ADR-019 | Object normalization | Correlation model |
| ADR-020 | Manager integration | Panorama / FortiManager = future work |
| ADR-021 | MongoDB | Not used in v1 |
| ADR-022 | LLM providers | Gemini, OpenAI, Ollama via abstraction |

## B. Implementation decisions (this team)

Each records context, the decision, and consequences. Status: **Accepted** unless noted.

### LFPM-IMPL-001 — Pull Schema v4 (mandate P3) earlier, alongside P0
**Context:** The mandate lists Schema v4 as P3, but acquisition (P1) and normalization (P2) cannot
persist without the v4 tables and the `(device_id, vdom_vsys, vendor_uuid)` constraint.
**Decision:** Implement Alembic + Schema v4 models in the P0/early window (consistent with V14 §17:
"freeze schema v4 before backend implementation"). Acquisition/normalization then build on a frozen schema.
**Consequence:** One initial migration carries the full v4 schema; later phases add data, not tables.

### LFPM-IMPL-002 — Adopt Alembic; retire `Base.metadata.create_all` from the runtime path
**Context:** Current app calls `create_all` on startup (V5 §14 forbids destructive auto-sync).
**Decision:** Introduce Alembic; run migrations before API start (V13 §7). Keep `create_all` only for
ephemeral test DBs.
**Consequence:** Existing dev DBs must be re-created or stamped to the initial revision.

### LFPM-IMPL-003 — Restructure backend toward the V2 §14.1 layout incrementally, not via big-bang rewrite
**Context:** Current layout is flat (`backend/api`, `backend/models`, `backend/services`). The target
is `app/{api,core,db,services,workers}`.
**Decision:** Add `core/` (config, logging, security) and `services/{acquisition,parsing,
normalization,anomaly,risk,cti,llm,reporting,graph}` packages; migrate existing modules into them
phase-by-phase, preserving import paths until each move is complete. No mass move in one commit
(mandate §10: "no huge blind rewrites").
**Consequence:** Temporary duplication during transition, recorded in EXECUTION_LOG.

### LFPM-IMPL-004 — Replace the mock anomaly engine; do not delete history blindly
**Context:** `backend/services/anomaly_engine.py` fabricates random anomalies (violates ADR-010/V6).
**Decision:** Build a deterministic engine (ANOMALY_ENGINE_SPEC) reading normalized data. The mock is
removed once the real shadowing/conflict/redundancy detectors pass atomic benchmarks; until then it is
**disabled** (not silently emitting), and its output table is reused (`rule_anomaly` extended).
**Consequence:** Anomaly endpoints return empty until real detectors land — acceptable and honest.

### LFPM-IMPL-005 — Realign "Lumina Threat Intel" (LTI) to API-based CTI; demote dark-web/Robin
**Context:** Large existing LTI + Robin (Tor/dark-web scraping) code is the **old** identity. Volumes
9/14 make API-based CTI primary and dark-web future/optional.
**Decision:** Salvage reusable parts (clearnet NVD/KEV connectors, correlation logic, LLM provider
plumbing) behind the new `CTIProvider`/`LLMProvider` abstractions; quarantine Tor/dark-web/Robin
behind an explicit, **disabled-by-default**, legally-gated feature flag (or move to `future/`). Remove
it from the default Docker Compose and from the API image dependency set.
**Consequence:** Default build is smaller and legal-by-default; dark-web remains a documented research
extension only.

### LFPM-IMPL-006 — Frontend migrates to TypeScript and Cytoscape.js incrementally
**Context:** Current frontend is plain JSX with an SVG topology (violates ADR-015/017).
**Decision:** Stand up a TS toolchain (tsconfig, typed API client) and introduce Cytoscape for the
graph via the `GET /api/graph/policy-relationships` contract. Re-skin pages into the required Centers
(Policy Explorer first per V11 §15). Convert file-by-file; keep the app runnable throughout.
**Consequence:** Mixed JS/TS during transition; tracked to completion in EXECUTION_LOG.

### LFPM-IMPL-007 — Real auth + RBAC + CORS lockdown before any networked deployment
**Context:** No backend auth, fake login, CORS `*`+credentials (V12 gaps).
**Decision:** Add session/JWT auth dependency on every router, RBAC roles (V12 Table 4), and a CORS
allowlist driven by `CORS_ALLOWED_ORIGINS`. Encrypt firewall/provider secrets.
**Consequence:** The cosmetic login is replaced; demo convenience accounts (if any) are seeded users,
not hardcoded client constants.

### LFPM-IMPL-008 — Credentials stored in an encrypted `device_credential` table
**Context:** Firewall API secrets must be encrypted at rest and never reach the frontend (V3/V12).
**Decision:** New `device_credential` table holding `secret_encrypted` (Fernet/`ENCRYPTION_KEY`),
decrypted only in backend/worker memory; the legacy `api_token` table is repurposed for platform API
tokens or removed.
**Consequence:** Connectors fetch secrets from the encrypted store, never from env/code.

### LFPM-IMPL-009 — Raw acquisition artifacts on the filesystem + metadata in DB
**Context:** V3 §8 requires storing raw outputs (with manifest + SHA-256) for replay/audit.
**Decision:** Store raw bytes under `/raw_acquisition/{vendor}/{device}/{job}/` with a DB
`raw_artifact` row per file; parser replays from stored artifacts without re-polling.
**Consequence:** A volume mount is added for raw artifacts; retention policy applies.

### LFPM-IMPL-010 — Separate vendor `service_object` table; add `rule_service_mapping` for rule↔service
**Context:** V4 §8 separates services into canonical `normalized_service`; V4 §8.1 allows the vendor
service to live in `network_object` *or* a dedicated `service_object`. We chose a dedicated
`service_object` table (cleaner protocol/port/app modeling). But the existing `rule_object_mapping`
references `network_object` only, so it cannot express rule→service links to `service_object`.
**Decision:** Keep `rule_object_mapping` for **source/destination** (network objects). Add a small
**`rule_service_mapping`** table (`rule_id`, `service_object_id`, `normalized_service_id`) in migration
`0002` for rule→service links. The pure normalization engine already resolves `service_keys`
(canonical) per rule, so persistence is a thin mapping write.
**Status:** Accepted; table + migration 0002 to be added in the persist step (Phase 4 completion).
**Consequence:** No change to the proven pure-normalization output; one additive migration.

### LFPM-IMPL-011 — Normalization split into a pure engine + a thin persist layer
**Context:** The normalized repository lives in PostgreSQL, but the canonical mapping + cross-vendor
correlation logic must be deterministic and unit-testable without a DB.
**Decision:** `services/normalization/engine.normalize_payloads()` is **pure** (returns a
`NormalizationResult`), validated by `test_normalization.py` against real lab data. A separate
`persist.py` (DB-dependent, idempotent upsert on `(device_id, vdom_vsys, vendor_uuid)`) writes the
result to Schema v4 and is validated against the live lab DB.
**Status:** Accepted; pure engine done + proven. Persist layer is the next concrete step.

> **Open items / risks to confirm with the client** are tracked in IMPLEMENTATION_ROADMAP §Risks.
