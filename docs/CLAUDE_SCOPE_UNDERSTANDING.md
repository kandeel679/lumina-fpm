# LuminaFPM — Scope Understanding (Authoritative Reading of Volumes 1–14)

> **Status:** Derived from the 14 binding specification volumes in `./Volumes/`.
> Where this document and the current codebase disagree, **the volumes win**.
> Last updated: 2026-06-22.

This document is the implementation team's restatement of the product scope. It exists so that
every later decision can be traced back to a binding requirement. Section numbers reference the
source volume (e.g. *V1 §3*, *V5 Table 4*).

---

## 1. Product identity (V1 §2–3, V14 §2)

**LuminaFPM is a read-only, multi-vendor _Firewall Anomaly Management Platform_.**

Its core innovation — the single thing the project is judged on — is:

> **Cross-vendor firewall policy normalization + deterministic anomaly detection.**

Vendor configurations are **acquired → parsed → normalized → analyzed by one deterministic engine**.
CTI and AI are *supporting* modules, never the identity.

### What it IS
- A multi-vendor firewall policy **acquisition + analysis** platform.
- A **normalized policy repository** (PostgreSQL, source of truth).
- A **deterministic anomaly detection engine** (46-category framework).
- A **cross-vendor inconsistency** detector.
- A **risk scoring + reporting** system.
- A **SOC-supporting report generator** (AI-assisted, evidence-grounded).

### What it is NOT (hard boundaries — V1 §2.2, Table 5)
- ❌ NOT a firewall management tool — it never pushes/commits/edits/reorders/enables/disables config.
- ❌ NOT packet inspection / live traffic / NetFlow / DPI / session analysis.
- ❌ NOT a vulnerability scanner.
- ❌ NOT a SIEM or SOAR replacement.
- ❌ NOT a dark-web scraping platform (that was an earlier draft; now future/optional only).
- ❌ NO Cisco in v1. NO AD/User-ID analysis. NO MongoDB.

---

## 2. Non-negotiable constraints (V1 §16, V12, V14 §17)

These are mandatory and any violation is a release blocker:

1. **Read-only against firewalls.** Connectors may only use GET/show/monitor/keygen/op-show. Code
   review must reject any `set/edit/delete/move/commit/enable/disable` firewall operation.
2. **No live traffic** — no NetFlow, packet capture, DPI, or session analysis. The graph is
   **logical policy relationships only**, never packet flow.
3. **PostgreSQL only** as source of truth. Normalized JSON is an interchange format, not the DB.
4. **No MongoDB** anywhere in v1.
5. **Anomaly engine analyzes normalized policies ONLY** — never raw FortiGate JSON / PAN-OS XML.
6. **LLM is never the anomaly authority.** Deterministic code decides anomalies; AI only generates
   CTI queries, reviews CTI, and writes SOC reports — always evidence-grounded.
7. **No uncontrolled dark-web scraping.** CTI is API-based, legal sources only, in v1.
8. **Credentials encrypted at rest**, never hardcoded, never exposed to the frontend, rotatable.
9. **Every finding is explainable** — evidence, severity, confidence, recommendation, timestamps.
10. **Postgres/Redis never exposed publicly.**

---

## 3. Locked technology stack (V1 Table 8, V2 Table 2)

| Layer | Approved technology |
|---|---|
| Backend API | FastAPI (Python) |
| ORM | SQLAlchemy |
| Migrations | **Alembic** (no `create_all` in real deployments — V5 §14) |
| Database | **PostgreSQL only** |
| Workers | Celery |
| Broker | Redis |
| Frontend | **React + TypeScript** |
| Graph | **Cytoscape.js** (logical graph only) |
| Deployment | Docker Compose |
| Firewall APIs | FortiGate REST API, Palo Alto **XML** API |
| LLM | Gemini / OpenAI / Ollama via **provider abstraction** |
| CTI | **API-based** providers (AbuseIPDB / OTX / VirusTotal / NVD-CVE / vendor advisories) |
| Anomaly engine | Deterministic rule-based |
| Risk engine | Separate scoring service |

---

## 4. The 8-layer pipeline (V2 §5–13, V4 §2)

Strict one-way layering — no layer bypasses the one below it:

```
1. Acquisition      (FortiGate REST / PAN-OS XML, read-only, async via Celery)
        ↓
2. Parsing          (vendor JSON/XML → vendor parser models; no anomaly logic)
        ↓
3. Normalization    (canonical rule/object/service model + correlation)
        ↓
4. Repository        (PostgreSQL normalized repo — SOURCE OF TRUTH)
        ↓
5. Analysis          (deterministic anomaly engine — normalized data ONLY)
        ↓
6. Risk + CTI        (separate risk scoring; API-based CTI enrichment)
        ↓
7. AI / LLM          (CTI query gen + SOC reports, evidence-grounded)
        ↓
8. Presentation      (React+TS dashboard, Policy Explorer, Centers, Cytoscape graph)
```

**Backend package layout (V2 §14.1) — target:**
```
backend/app/
  main.py
  api/         devices, policies, objects, anomalies, risks, cti, reports, benchmarks, graph, settings
  core/        config, security, logging
  db/          models, session, migrations(alembic)
  services/    acquisition, parsing, normalization, anomaly, risk, cti, llm, reporting, graph
  workers/     celery_app, tasks
```

**Celery queues split by job class (V2 §14.3, V3 Table 28, V13 Table 5):**
`acquisition · normalization(parsing) · analysis · cti · reporting`.

---

## 5. Lab architecture (V1 §8–9, V2 §16) — *Hybrid Parallel Shared-Network*

Both firewalls share the **same logical subnets** but are **independent policy engines** — not
inline, no packet path between them. The platform compares *configured intent*, not observed traffic.

| Network | Subnet | Purpose |
|---|---|---|
| LAN | 10.10.10.0/24 | Internal users |
| DMZ | 10.10.20.0/24 | Public services |
| DB | 10.10.30.0/24 | Database segment |
| ADMIN/API | 192.168.55.0/24 | Management + API |

| Device | Interface → IP |
|---|---|
| FortiGate | port1 10.10.10.1 · port2 10.10.20.1 · port3 10.10.30.1 · **port4 (mgmt) 192.168.55.10** |
| Palo Alto | **mgmt 192.168.55.20** · eth1/1 10.10.10.2 · eth1/2 10.10.20.2 · eth1/3 10.10.30.2 |
| Kali/API host | eth0 192.168.55.100 |

---

## 6. Data model direction (V5, V4) — *Schema v4*

- **Re-sync key (critical):** `(device_id, vdom_vsys, vendor_uuid)` — prevents duplicate policy
  rows on repeated polls and preserves anomaly history. Enforced as a UNIQUE constraint.
- **Object/service correlation model:** vendor-owned objects stay separate; canonical
  `normalized_object` / `normalized_service` sit above them via mapping tables. (Full merge rejected.)
- **New v4 tables:** `normalized_object`, `object_normalization_mapping`, `normalized_service`,
  `service_normalization_mapping`, `risk_assessment`, `anomaly_execution_log`, `benchmark_case`,
  `benchmark_result`, `cti_indicator`, `cti_observation`, `llm_report`, plus normalization support
  (`normalization_warning`, `rule_snapshot`, `normalized_content_hash`).
- **network_object gains ownership:** `device_id`, `vendor_id`, `vendor_object_id`, `vendor_uuid`,
  `raw_value`.
- **Soft deletion + snapshots** preferred over hard deletion (audit/drift/change-frequency).
- Full detail in [DATABASE_SCHEMA_V4.md](DATABASE_SCHEMA_V4.md).

---

## 7. Anomaly engine direction (V6) — 46-category taxonomy

- Deterministic, repeatable, explainable, benchmarkable. **Normalized data only.**
- 4 classes: `config_only` (fully implemented) · `conditional` · `benchmark_simulated` · `future_enhanced`.
- v1 ships the **config-only core first** (shadowing, redundancy, duplicate, conflict, overly-permissive,
  any-to-sensitive, missing logging, unprotected allow / weak profile, disabled-rule, missing description,
  temp-rule-without-schedule, wide port range, object/service sprawl, zone mismatch, **cross-device
  inconsistency** = policy conflict + security-posture difference).
- Every finding carries: `anomaly_type, rule_id, related_rule_id?, severity, confidence,
  technical_reason/description, evidence, recommendation, detection_mode, analysis_run_id, detected_at, status`.
- Full detail in [ANOMALY_ENGINE_SPEC.md](ANOMALY_ENGINE_SPEC.md).

---

## 8. Risk, CTI, AI (V8, V9, V10)

- **Risk** is a *separate* engine: 0–100, tiers (0 info / 1–39 low / 40–69 med / 70–89 high / 90–100 crit),
  additive factor model, factor breakdown persisted to `risk_assessment` (JSONB). "An anomaly explains
  what is wrong; risk explains what to fix first."
- **CTI** is API-based, separate from anomalies, contributes to risk. Extract public IPs/FQDNs/URLs/CVEs/
  firmware; **never send private RFC1918/internal data to external providers** unless explicitly configured.
  Provider abstraction (`CTIProvider`). Dark-web/Robin = future/optional only.
- **AI/LLM** provider abstraction (Gemini/OpenAI/Ollama). Used only for CTI query gen, CTI summary,
  SOC reports, executive summaries, explanations. Must cite DB evidence IDs and separate evidence from
  interpretation. Output stored in `llm_report` with provider/model/prompt-version/evidence-refs/confidence/ts.
  **If the LLM fails, deterministic anomalies + risk must still render.**

---

## 9. Visualization (V11)

React + TypeScript shell with these centers: **Dashboard, Device Inventory, Policy Explorer (build first),
Anomaly Center, Risk Center, CTI Threat Center, Benchmark Center, Reports Center, Settings**, and a
**Cytoscape.js logical graph** (`GET /api/graph/policy-relationships`). Graph nodes: vendor/firewall/
vdom-vsys/zone/interface/object/service/rule + risk/anomaly badges. Edges: allows/denies/uses_object/
uses_service/shadows/conflicts/duplicates/inconsistent_with/has_risk/correlates_with_threat. **The graph
must never claim live traffic/NetFlow/DPI.**

---

## 10. Security (V12) & deployment (V13)

- Real **authentication** (session/JWT, expiry) + **RBAC** roles: Platform Admin · Firewall Engineer ·
  SOC Analyst · Auditor · Viewer.
- Encrypted secrets, audit logging of security-relevant actions, restricted CORS, rate-limited login/
  job-creation, Pydantic validation, no stack traces to users.
- Docker Compose with split worker services, health checks, Alembic migrations run before API start,
  backup/restore, **Postgres/Redis internal-only**, Nginx-served frontend production build.
- Full detail in [SECURITY_MODEL.md](SECURITY_MODEL.md).

---

## 11. Implementation order (V14 §4–14)

Phase 0 Foundation → 1 Acquisition → 2 Normalization → 3 Database v4 → 4 Anomaly engine →
5 Benchmark → 6 Risk + CTI → 7 AI Reporting → 8 Visualization → 9 Security + Deployment.

> **Never sacrifice (V14 Table 1):** acquisition, normalization, anomaly detection. They are the foundation.

The mandate's P0…P10 ordering is consistent with this; where they differ, Schema v4 (P3) is pulled
**earlier** because acquisition/normalization cannot persist without it. See
[IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md).

---

## 12. Architectural decision registry

The 22 ADRs (ADR-001…ADR-022) from V1 Table 17 / V2 Table 19 are reproduced and extended with
implementation decisions in [ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md). Any deviation from a
binding ADR must be raised as a design change request **before** implementation (V1 §19).
