# LuminaFPM — Technical Documentation Source

> **Single source of truth for formal (LaTeX) technical documentation.**
> Intentionally exhaustive, precise, and self-contained: a reader who has not seen the code can author
> complete documentation from this file alone. Every statement is grounded in the actual codebase, the
> 14 specification volumes (`Volumes/_extracted/*.txt`), and the project's internal docs (`docs/*.md`).
> Documents the **current build state**, including both the volume-driven changes (Claude-implemented)
> and the manual / hand-made changes (the human team) — see §10 for the explicit split.

**Project:** LuminaFPM — strictly read-only, multi-vendor Firewall Anomaly Management Platform.
**v1 vendors:** Fortinet FortiGate (REST/JSON) + Palo Alto PAN-OS (XML API).
**Stack:** FastAPI · SQLAlchemy · PostgreSQL · Celery · Redis (backend); React + TypeScript + Vite (frontend); Docker Compose.
**Generated from branch** `analyze-project-todo-report` **at commit** `bdaab52` (covers all changes to date).

## Table of Contents

1. [1. Project Overview, Purpose & Scope](#1-project-overview-purpose--scope)
2. [2. Technology Stack & Key Dependencies](#2-technology-stack--key-dependencies)
3. [3. System Architecture](#3-system-architecture)
4. [4. Backend — Acquisition, Parsing & Normalization](#4-backend--acquisition-parsing--normalization)
5. [5. Backend — Anomaly, Risk, CTI, LLM & Benchmark Engines](#5-backend--anomaly-risk-cti-llm--benchmark-engines)
6. [6. Data Model, Database Schema & REST API](#6-data-model-database-schema--rest-api)
7. [7. Backend — Threat-Intelligence (LTI/Robin) Subsystem & Core Infrastructure](#7-backend--threat-intelligence-ltirobin-subsystem--core-infrastructure)
8. [8. Frontend Architecture & Components](#8-frontend-architecture--components)
9. [9. Build, Setup & Deployment](#9-build-setup--deployment)
10. [10. Change Log — Volume-Driven vs Manual Changes](#10-change-log--volume-driven-vs-manual-changes)
11. [11. Gap Analysis — Implemented vs Diverged vs Outstanding (against the 14 Volumes)](#11-gap-analysis--implemented-vs-diverged-vs-outstanding-against-the-14-volumes)

---

## 1. Project Overview, Purpose & Scope

### 1.1 What LuminaFPM Is

**LuminaFPM** (full title: *LuminaFPM — Proactive Multi-Vendor Firewall Policy Management*; platform family name: **Lumina**) is a **read-only, multi-vendor Firewall Anomaly Management Platform**. Its authoritative product classification is fixed in `Volume 1 §3` / `Table 3` and reaffirmed in `docs/ARCHITECTURE_DECISIONS.md` (ADR-001): the system's **primary identity is a Firewall Anomaly Management Platform**, and Cyber Threat Intelligence (CTI) and AI are explicitly *supporting modules, not the main identity* (`Volume_1 §3`).

Per the Executive Summary (`Volume_1 §1`), LuminaFPM is a *"proactive multi-vendor firewall policy management, anomaly detection, risk scoring, and threat-intelligence-assisted reporting platform"* that acquires firewall policies from different vendors, normalizes them into a unified internal repository, analyzes them for policy anomalies, compares behavior across vendors, and presents findings through dashboards, reports, and logical policy visualization.

The condensed **Core Delivery Statement** (`Volume_1 §1.1`) is the canonical one-line summary:

> *"LuminaFPM converts multi-vendor firewall configurations into normalized security intelligence. It identifies policy anomalies, cross-vendor inconsistencies, and risk-prioritized findings without modifying firewall devices."*

The implementation team's restatement (`docs/CLAUDE_SCOPE_UNDERSTANDING.md §1`) enumerates what it **is**: a multi-vendor firewall policy acquisition + analysis platform; a normalized policy repository (PostgreSQL, source of truth); a deterministic anomaly detection engine (46-category framework); a cross-vendor inconsistency detector; a risk-scoring + reporting system; and a SOC-supporting, AI-assisted, evidence-grounded report generator.

### 1.2 The Problem It Solves

LuminaFPM targets the operational and security debt that accumulates in firewall rulebases over time. The problem statement (`Volume_1 §5`, and the strategic-importance note in `§1.2`) is broken into five concrete drivers:

| Ref | Problem | Description |
|---|---|---|
| `§5.1` | Lack of unified visibility | Organizations run multiple firewall vendors, each representing policies, objects, zones, services, applications, logging, and inspection differently; without normalization, admins must manually compare incompatible structures and terminology. |
| `§5.2` | Policy anomalies | Rulebases accumulate shadowing, redundancy, conflicts, duplicate rules, overly broad access, missing logging, missing inspection, stale temporary rules, poor descriptions, and inconsistent cross-device behavior. |
| `§5.3` | Manual audit limitations | Manual audits are slow, inconsistent, and quickly outdated; they struggle with large rulebases, object expansion, rule-order reasoning, historical drift, and multi-vendor comparison. |
| `§5.4` | Cross-vendor blind spots | A FortiGate rule and a Palo Alto rule may look similar from a business view but differ in action, logging, inspection, schedule, or object definition — which LuminaFPM must surface as cross-device inconsistencies. |
| `§5.5` | Static risk vs dynamic threat context | A rule that looks safe today becomes risky if a referenced IP/FQDN turns malicious or a CVE emerges for the deployed firmware; this motivates a *separate* CTI risk engine, kept distinct from deterministic anomalies. |

The root cause (`§1.2`): *"Firewall rulebases grow organically over time. Temporary access rules, migration exceptions, vendor access, emergency changes, and outdated business requirements often remain in production long after their purpose has expired,"* producing security risk, operational confusion, and audit difficulty.

### 1.3 Core Innovation — Cross-Vendor Normalization → Deterministic, Explainable Anomaly Detection

The single technical contribution on which the project is judged (`Volume_1 §1`, `§3.1`, `Table 3` "Primary innovation", ADR-002, and `docs/CLAUDE_SCOPE_UNDERSTANDING.md §1`) is:

> **Cross-vendor firewall policy normalization + deterministic anomaly detection using a single normalized policy model.**

Vendor-specific configurations are **acquired → parsed → normalized → analyzed by one deterministic anomaly engine**. The defining architectural rule (`Volume_1 §12.3`, ADR-010) is absolute:

> *"The anomaly engine analyzes only normalized policies. It must not directly analyze raw FortiGate JSON or Palo Alto XML. Vendor-specific differences must be resolved before analysis through the parsing and normalization layers."*

Three properties distinguish this from ML- or heuristic-based approaches:

- **Deterministic, not ML / not statistical.** The anomaly engine is a **deterministic rule-based engine** (`Volume_1 Table 8`, "Anomaly engine"). It must remain *deterministic, repeatable, explainable, and benchmarkable* (`Volume_1 §14.4`, `§6.3`). AI is explicitly barred from being the anomaly authority: *"AI must not be the primary anomaly detection mechanism"* (`§14.4`, ADR-013).
- **Explainable.** Every finding must carry evidence, timestamp, affected rule, related rule (where applicable), severity, confidence, and recommended action (`Volume_1 §16.3`, `§19.1`; restated in `docs/CLAUDE_SCOPE_UNDERSTANDING.md §2.9` and `§7`).
- **Benchmark-validated.** Detection correctness is proven against a **ground-truth benchmark matrix** comparing expected anomalies to detected anomalies (`Volume_1 §13`, `§6.3`, `§17.1`).

The normalization itself uses a **correlation model** for objects/services (ADR-019, `Volume_1 §11.4`): vendor-owned objects remain separate, while canonical normalized objects are created *above* them and linked through mapping tables — enabling device ownership, vendor traceability, object-mismatch and duplicate detection, object drift analysis, and cross-vendor rule comparison.

**Secondary innovations** (`Volume_1 §3.2`), explicitly subordinate to the core: AI-assisted CTI query generation; AI-assisted SOC technical report generation; policy-derived *blast-radius-style* reasoning without live packet telemetry; logical policy-relationship visualization; and benchmark-driven validation against the 46-category anomaly framework.

### 1.4 The Strict READ-ONLY Mandate

LuminaFPM is **intentionally and strictly read-only** — a non-negotiable release-blocking constraint (`Volume_1 §1`, `§16.1`, `Table 5`; ADR-006; `docs/CLAUDE_SCOPE_UNDERSTANDING.md §2.1`). Per `Volume_1 §16.1`:

> *"LuminaFPM must operate strictly in read-only mode. It must not modify, push, delete, reorder, enable, disable, or commit any firewall configuration. Corrective actions remain fully under the control of authorized organization personnel."*

The platform is **config-only and never writes to firewalls**. The implementation team encodes this as a code-review gate (`docs/CLAUDE_SCOPE_UNDERSTANDING.md §2.1`): connectors may use only `GET/show/monitor/keygen/op-show` operations, and code review *must reject* any `set/edit/delete/move/commit/enable/disable` firewall operation. The lab is a **parallel shared-network VMware lab** (FortiGate at `192.168.55.10`, Palo Alto at `192.168.55.20`, both on `192.168.55.0/24`); the platform connects to firewalls solely to *read* configuration.

Related security principles (`Volume_1 §16.2`): API tokens/credentials encrypted at rest, never hardcoded, never committed to source control, never exposed to the frontend; token rotation supported; least-privilege read-only API accounts wherever possible.

### 1.5 v1 Vendor Scope — FortiGate + Palo Alto Only, and Why

v1 supports **exactly two vendors** (`Volume_1 Table 4`, ADR-003):

| Vendor | API surface (v1) |
|---|---|
| Fortinet FortiGate | **REST/JSON API** (`/api/v2/cmdb/...`, `/api/v2/monitor/...`) |
| Palo Alto Networks PAN-OS | **XML API** (`type=keygen`, `type=config&action=show`, `type=op`) |

Rationale and constraints:
- These two vendors were chosen as the first implementation because the lab already validates both acquisition paths end-to-end — FortiGate REST API validation and Palo Alto XML API validation are both confirmed (`Volume_1 §8.3`, `Volume_2 §6.3`/`§6.4`).
- Two heterogeneous API styles (REST/JSON vs XML) maximally exercise the normalization layer, making the cross-vendor contribution credible (`Volume_1 §6.3` academic objectives).
- The architecture is built so additional vendors can be added later *"through connector and parser extensions"* (`Volume_1 §6.4`), but only Fortinet + Palo Alto are implemented in v1 (`Table 5`, "Full vendor coverage").
- **Cisco is explicitly excluded** and Cisco examples must be removed from final v1 implementation documentation (`Volume_1 Table 5`, ADR-004).
- **Vendor managers** (Panorama, FortiManager) are *future work*, not required in v1; v1 uses **direct firewall APIs** (`Volume_1 §6.4`, `§10.2`, `Table 4`, ADR-020).

### 1.6 Intended Users

The primary audience (`Volume_1 Table 3`, "Primary audience") is **firewall administrators, SOC engineers, security auditors, and the cybersecurity development team**. The product's role is to *"provide high-confidence visibility, analysis, prioritization, and reporting so authorized firewall administrators and SOC engineers can make informed decisions"* (`Volume_1 §1`) — it informs human decisions but never enacts changes.

The RBAC role model (`Volume_1 §16.4` / `Table 16`) defines five roles and their read-centric permissions:

| Role | Expected permissions |
|---|---|
| Platform Admin | Manage platform settings, credentials, users, integrations, system configuration. |
| Firewall Engineer | View devices, policies, objects, anomalies, risk findings, reports. |
| SOC Analyst | View risks, CTI findings, reports, investigation context. |
| Auditor | View read-only evidence, reports, benchmarks, historical findings. |
| Viewer | View dashboards and summary pages only. |

### 1.7 High-Level Value Chain — The 8 Logical Layers

The approved system model is *layered and modular*; *"every component must respect the boundary of its layer"* and *"no layer should bypass the layer below it"* (`Volume_1 §10`, `Volume_2 §5`). The strategic system model in `Volume_1 §10` names seven pipeline stages; the implementation team's canonical restatement (`docs/CLAUDE_SCOPE_UNDERSTANDING.md §4`, sourced from `Volume_2 §5–13`) expresses the value chain as **8 named layers** with strict one-way flow:

| # | Layer | Responsibility (grounded) |
|---|---|---|
| 1 | **Acquisition** | Connect to FortiGate REST / PAN-OS XML, read-only, asynchronously via Celery; collect raw config (rules, objects, services, firmware/version), track poll status, store raw output (`Volume_2 §6`). Acquisition must not run inside the web request cycle (`Volume_2 §6.5`). |
| 2 | **Parsing** | Convert raw vendor JSON/XML into vendor-specific parser models (e.g. `FortiGateParsedPolicy`); understands vendor formats but performs **no anomaly logic** (`Volume_2 §7`). |
| 3 | **Normalization** | Map vendor parser models into the canonical rule/object/service model and apply the correlation model (`Volume_1 §11.4`, `Volume_2`). |
| 4 | **Normalized Policy Repository** | PostgreSQL, the authoritative **source of truth** for v1 (`Volume_1 §11.1`, ADR-008). |
| 5 | **Anomaly Detection Engine** | Deterministic 46-category engine operating on **normalized data only** (`Volume_1 §10`, `§12`, ADR-010). |
| 6 | **Risk + CTI** | Separate risk-scoring engine plus API-based CTI enrichment, kept distinct from deterministic anomalies (`Volume_1 §12`, `§14`, ADR-012). |
| 7 | **AI / LLM** | CTI query generation, CTI review/summary, and SOC/executive report generation — always evidence-grounded; never the anomaly authority (`Volume_1 §14`, ADR-013). |
| 8 | **Presentation & Reporting** | React + TypeScript dashboard, Policy Explorer, the various Centers, and a Cytoscape.js **logical** graph (`Volume_1 §10`, `§15`, ADR-015/017). |

> Note: `Volume_1 §10` lists the pipeline as a 7-stage strategic model (Acquisition → Parsing → Normalization → Normalized Policy Repository → Anomaly Detection Engine → Risk Scoring Engine → Presentation and Reporting Layer). The "8 logical layers" naming additionally separates **Risk + CTI** from the **AI / LLM** stage and treats the repository as its own layer, matching the layered breakdown in `Volume_2 §5–13`. Both are consistent; the 8-layer form is the implementation team's working decomposition.

A crucial cross-cutting rule applies to the output of this chain (`Volume_1 §9.3`, `§15.2`, ADR-007): the topology graph and analysis outputs describe **logical policy relationships, not real runtime packet forwarding**. *"LuminaFPM analyzes configured intent and policy posture, not observed network sessions,"* and this distinction *"must be explicit in all user-facing documentation."*

### 1.8 Lab & Architecture Position (Context for Scope)

The selected deployment model is the **Hybrid Parallel Shared-Network Architecture** (`Volume_1 §9.1`, `Volume_2 §3`, ADR-005): both firewalls connect to the same logical subnets but operate as **independent policy engines** — not inline, with no production traffic routed through each other. This is deliberately chosen because it is the best model for controlled cross-vendor anomaly detection under identical logical network conditions, avoids unnecessary routing complexity, and supports clean API extraction and benchmark-driven evaluation (`Volume_1 §9.2`). The lab is *primarily a controlled anomaly-generation environment, not a realistic enterprise routing simulation* (`Volume_1 §13.1`).

Logical subnets and device IP plan (`Volume_1 Tables 6–7`):

| Network | Subnet | Purpose |
|---|---|---|
| LAN | 10.10.10.0/24 | Internal user network |
| DMZ | 10.10.20.0/24 | Public services segment |
| DB | 10.10.30.0/24 | Database segment |
| ADMIN/API | 192.168.55.0/24 | Management & API access |

FortiGate: port1 `10.10.10.1`, port2 `10.10.20.1`, port3 `10.10.30.1`, port4 (mgmt) `192.168.55.10`. Palo Alto: mgmt `192.168.55.20`, eth1/1 `10.10.10.2`, eth1/2 `10.10.20.2`, eth1/3 `10.10.30.2`. Kali/API host: eth0 `192.168.55.100`.

### 1.9 Explicit IN-SCOPE for v1

Consolidated from `Volume_1 Table 4` (`§7.1`), the strategic objectives (`§6`), and the mandatory handoff rules (`§19.1`):

| Area | Included in v1 |
|---|---|
| Firewall vendors | Fortinet FortiGate + Palo Alto PAN-OS only |
| Acquisition | Direct firewall APIs (FortiGate REST, Palo Alto XML), read-only |
| Operation mode | Read-only extraction and analysis |
| Database | PostgreSQL only (authoritative source of truth) |
| Normalization | Unified canonical model + object/service correlation model, before any analysis |
| Analysis | 46-category anomaly framework (deterministic engine) |
| Cross-vendor detection | Policy conflicts **and** security-posture differences (object inconsistency via correlation model) |
| Runtime anomalies | Conditional if logs exist; **benchmark-simulated** when needed (`§12.5`, ADR-011) |
| Risk scoring | Rule-level and device-level risk scores, calculated and stored |
| Historical state | Historical snapshots + incremental re-synchronization (re-sync key `(device_id, vdom_vsys, vendor_uuid)`, `§11.3`) |
| CTI | API-based CTI enrichment (separate risk engine) |
| AI | LLM query generation, CTI review/summary, SOC technical report generation — evidence-grounded |
| Benchmarking | Atomic + compound benchmark matrix (`§13.3`, `Table 13`) |
| Visualization | Dashboard, policy table/explorer, anomaly reports, risk views, CTI center, benchmark center, **logical** Cytoscape graph |
| Security | Encrypted credentials, auditability of every run, RBAC (5 roles) |

### 1.10 Explicit OUT-OF-SCOPE / Future Work

Consolidated from `Volume_1 Table 5` (`§7.2`), `§2.2`, and the relevant ADRs. These boundaries are hard constraints; several "future" items are explicitly conditional on legal/ethical/operational approval.

| Area | Status | Source |
|---|---|---|
| Firewall modification (push/commit/edit objects/reorder rules) | **Excluded — permanently** (read-only mandate) | `§16.1`, `Table 5`, ADR-006 |
| Live traffic analysis — NetFlow, packet capture, session analysis, DPI | **Excluded** | `§2.2`, `Table 5`, ADR-006 |
| Real routed traversal (inline FortiGate↔Palo Alto packet path) | **Excluded** (parallel shared-network, not inline) | `Table 5`, `§9.1` |
| Vulnerability scanning | **Excluded** (not a scanner) | `§2.2`, `Table 5` |
| SIEM / SOAR replacement | **Excluded** (complements, does not replace) | `§2.2`, `Table 5` |
| Endpoint security (EDR / antivirus) | **Excluded** | `Table 5` |
| Full vendor coverage beyond Fortinet + Palo Alto | **Excluded from v1**; extensible later via connectors/parsers | `Table 5`, `§6.4` |
| Cisco implementation / examples | **Excluded; remove from final v1 docs** | `Table 5`, ADR-004 |
| User identity analysis (AD / User-ID) | **Excluded from v1** | `Table 5` |
| MongoDB | **Excluded** (PostgreSQL is sufficient/preferred) | `Table 5`, ADR-021, `Volume_2 §2` |
| Panorama / FortiManager manager integration | **Future work** (v1 uses direct APIs) | `§10.2`, ADR-020 |
| Dark-web scraping / Robin-style RAG / LTI dark-web orchestration | **Future / optional research only**, subject to legal, ethical, and operational approval; API-based CTI is primary in v1 | `§2.2`, `§14.6`, `docs/ARCHITECTURE_DECISIONS.md` LFPM-IMPL-005 |
| Topology-input mechanism (how logical topology/zone-asset context is supplied) | **Future / not a v1 acquisition path** — v1 derives logical relationships from configured policy intent, not an external topology feed | `§9.3`, `§15.2` (graph = logical intent only) |

**Notes on partial/ambiguous areas (stated plainly, per the read-only-honesty requirement):**

- **Dark-web / Robin / "Lumina Threat Intel" (LTI):** Earlier project drafts treated dark-web scraping as central; the final v1 position demotes it. `Readme.md` still advertises *"an integrated Dark Web Threat Intelligence engine"* — this is **stale relative to the binding volumes**. ADR LFPM-IMPL-005 (`docs/ARCHITECTURE_DECISIONS.md`) records the realignment: salvage clearnet connectors and provider plumbing behind `CTIProvider`/`LLMProvider`, and **quarantine Tor/dark-web/Robin behind an explicit, disabled-by-default, legally-gated feature flag** (or move to `future/`), removed from the default Docker Compose. Treat any dark-web capability as documented research extension only, not v1 scope.
- **Runtime anomalies** are not fully in-scope: v1 has no live telemetry, so runtime-dependent anomalies are labeled **telemetry-supported** or **benchmark-simulated** rather than fully implemented (`§12.5`, `Table 10`, ADR-011).
- **Topology input** is implicit, not an implemented ingestion feature: the platform reasons over *configured intent* (zones/interfaces/objects from acquired config), and the graph must never claim live traffic — there is no v1 mechanism for feeding an external/observed topology (`§9.3`, `§15.2`).
- **LLM providers:** the volumes approve Gemini, OpenAI, and Ollama behind one provider abstraction (`§14.5`, ADR-022). The platform's runtime default is Gemini with an offline fallback; OpenAI/Ollama are abstraction targets, not all necessarily wired in v1.

---

## 2. Technology Stack & Key Dependencies

LuminaFPM is a containerized multi-service application: a Python/FastAPI backend with a Celery worker pool, a React/TypeScript single-page frontend, and PostgreSQL + Redis as backing stores, all wired together via Docker Compose. The exact dependency manifests are `backend/requirements.txt`, `frontend/package.json`, and `docker-compose.yml`; the build images are defined in `backend/Dockerfile` and `frontend/Dockerfile`.

A key caveat that runs through this section: **the backend `requirements.txt` is unpinned** — every line names a package but not a version (the only version constraint anywhere is the Python base image `python:3.11-slim`). Frontend dependencies, by contrast, are pinned with caret (`^`) ranges in `package.json`. Where a version is stated below, it comes directly from a manifest; where it is not, the source file does not pin it and this is called out explicitly.

### 2.1 Backend Dependencies (`backend/requirements.txt`)

None of these packages are version-pinned in `backend/requirements.txt`; the "Version" column is therefore "unpinned (latest at build time)" for all rows. Resolution happens at image-build time via `pip install --no-cache-dir -r requirements.txt` (`backend/Dockerfile` line 20).

| Package | Version | Role |
|---|---|---|
| `fastapi` | unpinned | ASGI web framework; provides the REST API surface (routers, dependency injection, OpenAPI). |
| `uvicorn` | unpinned | ASGI server that runs the FastAPI app (invoked with `--reload` in the dev entrypoint). |
| `sqlalchemy` | unpinned | ORM / database toolkit; models and session management for PostgreSQL. |
| `alembic` | unpinned | Database schema migrations. Comment in file: "schema migrations (V5 §14, V13 §7) — replaces create_all". |
| `pydantic` | unpinned | Data validation / serialization models (request/response schemas, normalized policy models). |
| `pydantic-settings` | unpinned | Typed environment-variable configuration. Comment: "typed env-based config (core/config.py, V13 §6)". |
| `cryptography` | unpinned | Fernet symmetric encryption for stored device credentials. Comment: "Fernet encryption for device credentials (V12 §6)". |
| `defusedxml` | unpinned | Hardened XML parsing for PAN-OS (Palo Alto) XML-API responses. Comment: "hardened XML parsing for PAN-OS responses (V12 §10)". |
| `psycopg2-binary` | unpinned | PostgreSQL driver (DB-API) used by SQLAlchemy/Alembic. |
| `python-dotenv` | unpinned | Loads `.env` files into the environment. |
| `celery[redis]` | unpinned | Distributed task queue (with the Redis extra) for acquisition/normalization/analysis/CTI/reporting jobs. |
| `redis` | unpinned | Redis client library (broker/result backend transport for Celery). |
| `watchdog` | unpinned | Dev-only filesystem watcher; `watchmedo auto-restart` reloads the Celery worker on `.py` changes (worker has no native `--reload`). Comment confirms this. |
| `requests` | unpinned | HTTP client; used for FortiGate REST/JSON API calls and CTI/API fetches. |
| `beautifulsoup4` / `bs4` | unpinned | HTML parsing. `bs4` is the meta-package alias; both are listed (effectively the same library). |
| `pysocks` | unpinned | SOCKS proxy support (used with the Tor proxy for dark-web/OSINT scraping). |
| `defusedxml` | unpinned | (see above). |
| `sse-starlette` | unpinned | Server-Sent Events responses for Starlette/FastAPI (streaming endpoints, e.g. LLM token streaming). |
| `streamlit` | unpinned | Present in requirements but only used by the commented-out "Robin" dark-web OSINT UI (`robin_ui`/`robin_api` services are disabled in `docker-compose.yml`). Not part of the core read-only platform path. |

**LLM / AI provider libraries** (all unpinned). The platform uses a provider abstraction with Gemini as the documented default and an offline fallback. The installed libraries are broader than the documented default, indicating multiple pluggable providers:

| Package | Version | Role |
|---|---|---|
| `google-generativeai` | unpinned | Google Gemini SDK — the default LLM provider. |
| `langchain_google_genai` | unpinned | LangChain binding for Google Gemini. |
| `langchain-openai` | unpinned | LangChain binding for OpenAI-compatible providers. |
| `langchain-anthropic` | unpinned | LangChain binding for Anthropic Claude. |
| `langchain-ollama` | unpinned | LangChain binding for local Ollama models (offline-capable). |
| `langchain_community` | unpinned | Community LangChain integrations (shared loaders/utilities). |
| `backports.tarfile` | unpinned | Backport of the stdlib `tarfile` (transitive/compatibility shim, likely pulled in to satisfy a dependency). |

Notes / caveats:
- `bs4` and `beautifulsoup4` are duplicates of the same library.
- The presence of `langchain-openai`, `langchain-anthropic`, and `langchain-ollama` alongside `google-generativeai` shows the LLM layer is multi-provider even though Gemini is the default; the exact provider-selection logic is in backend code (e.g. `core/config.py` / an LLM provider module), not in `requirements.txt`.
- `streamlit`, `pysocks`, `beautifulsoup4` relate to the Tor-proxied OSINT/"Robin" subsystem, which is **commented out** in `docker-compose.yml` and described in-file as "kept for testing" — it is not an active platform service.
- The complete absence of version pins is a reproducibility risk worth flagging in formal documentation: builds are not deterministic across time.

### 2.2 Frontend Dependencies (`frontend/package.json`)

The frontend is an ES-module project (`"type": "module"`, `version: 0.1.0`, `private: true`). All versions are caret (`^`) ranges, reproduced verbatim below. Scripts: `dev` → `vite`; `build` → `vite build`; `lint` → `eslint .`; `typecheck` → `tsc --noEmit`; `preview` → `vite preview`.

**Runtime dependencies:**

| Package | Version | Role |
|---|---|---|
| `react` | `^19.2.4` | UI library (React 19). |
| `react-dom` | `^19.2.4` | React DOM renderer. |
| `react-router-dom` | `^7.14.1` | Client-side routing (React Router v7). |
| `recharts` | `^3.8.1` | Charting library for dashboards/analytics visualizations. |
| `lucide-react` | `^1.8.0` | Icon component set. |
| `cytoscape` | `^3.33.2` | Graph/network visualization core. **See caveat below.** |
| `cytoscape-dagre` | `^2.5.0` | Dagre layout extension for Cytoscape (directed-graph layout). |
| `react-cytoscapejs` | `^2.0.0` | React wrapper component for Cytoscape. |

**Dev dependencies:**

| Package | Version | Role |
|---|---|---|
| `vite` | `^8.0.4` | Build tool / dev server. |
| `@vitejs/plugin-react` | `^6.0.1` | Vite React plugin (JSX/Fast Refresh). |
| `typescript` | `^5.7.2` | TypeScript compiler (type-checking only; Vite/esbuild does transpilation). |
| `@types/react` | `^19.2.14` | React type definitions. |
| `@types/react-dom` | `^19.2.3` | React DOM type definitions. |
| `tailwindcss` | `^4.2.2` | Utility-first CSS framework (Tailwind v4). |
| `@tailwindcss/vite` | `^4.2.2` | Tailwind v4 Vite plugin. |
| `eslint` | `^9.39.4` | Linter. |
| `@eslint/js` | `^9.39.4` | ESLint's bundled JS rule configs. |
| `eslint-plugin-react-hooks` | `^7.0.1` | Lint rules for React Hooks. |
| `eslint-plugin-react-refresh` | `^0.5.2` | Lint rules for React Fast Refresh. |
| `globals` | `^17.4.0` | Predefined global identifiers for ESLint. |

**Cytoscape caveat (verified):** Although `cytoscape ^3.33.2`, `cytoscape-dagre ^2.5.0`, and `react-cytoscapejs ^2.0.0` are all installed as runtime dependencies, the prompt's note that the current topology view is hand-rolled SVG rather than Cytoscape-based is consistent with the dependency manifest alone (which cannot tell us which component renders the topology). The recent git history corroborates the SVG approach — commit `99ec9ca` "frontend(P10 final pass): de-mock topology assets/zones" and `1cb66cb` "fix... topology label overlap" — and the prior commit set is frontend-topology work. **Confirmation that Cytoscape is unused in the live topology requires inspecting the topology component source (under `frontend/src/`), which is outside this section's assigned file scope.** Documented status: the Cytoscape stack is *installed but, per project notes, not the active topology renderer* — this should be flagged as a potential candidate for dependency removal.

**Tailwind note:** Tailwind v4 is integrated via its Vite plugin (`@tailwindcss/vite`), the modern v4 setup, not the legacy PostCSS pipeline. However, `vite.config.js` (below) registers **only** `@vitejs/plugin-react` and does *not* list the Tailwind Vite plugin — so either Tailwind is wired in elsewhere (e.g. a CSS-side `@import "tailwindcss"`) or its Vite integration is incompletely configured. This discrepancy is worth verifying against the actual CSS entrypoint; it cannot be resolved from the files in this section's scope.

### 2.3 Build & Tooling Configuration

**`frontend/vite.config.js`** — Vite config uses `@vitejs/plugin-react` and defines a dev-server proxy: all `/api/v1` requests are proxied to `apiTarget`, where `apiTarget = process.env.VITE_API_PROXY || 'http://localhost:8000'` with `changeOrigin: true`. In Docker Compose the `frontend` service sets `VITE_API_PROXY=http://api:8000` (reach the backend by service name); on a bare host it defaults to the published backend port `http://localhost:8000`. Note this config file is JavaScript (`.js`), not `.ts`.

**`frontend/tsconfig.json`** — `target` ES2022; `lib` = ES2022 + DOM + DOM.Iterable; `module` ESNext; `moduleResolution` `bundler`; `jsx` `react-jsx`; `noEmit: true` (type-check only — Vite/esbuild transpiles). `strict: true` is on, but `noUnusedLocals`/`noUnusedParameters` are `false`. Critically, `allowJs: true` with `checkJs: false`: this is an **incremental TS migration** — existing `.js`/`.jsx` files compile un-type-checked while new code is authored in `.ts`/`.tsx` (per the in-file comment, `allowJs`/`checkJs` are to be dropped once migration completes). `include` is `["src"]`. Implication for documentation: the frontend is a mixed JS/TS codebase mid-migration, not fully typed.

### 2.4 Infrastructure (`docker-compose.yml`, Dockerfiles, nginx)

Docker Compose orchestrates the stack. Services (numbered as in the file):

| Service | Image / Build | Host Ports | Role & Notes |
|---|---|---|---|
| `db` | `postgres:16-alpine` | none (`expose: 5432` only) | PostgreSQL 16. **Not** published to host (security: V12 §12 / V13 Table 4); reachable only on the internal Docker network. Healthcheck via `pg_isready`. Persistent volume `postgres_data`. Credentials injected from `.env` (`env_file`). |
| `tor-proxy` | build `./tor-proxy/Dockerfile` | `9050:9050` | Tor SOCKS proxy for dark-web/OSINT scraping. Supports the (currently disabled) Robin subsystem. `restart: always`. |
| `redis` | `redis:7-alpine` | none (`expose: 6379` only) | Redis 7 — Celery broker/result backend. Not published to host (internal only). Healthcheck via `redis-cli ping`. Persistent volume `redis_data`. |
| `api` | build `./backend` (`python:3.11-slim`) | `8000:8000` | FastAPI backend via Uvicorn. `entrypoint.sh` (chmod+exec) runs Uvicorn with `--reload` for live reload. Code bind-mounted (`./backend:/app`). `dns: 8.8.8.8, 1.1.1.1`. Depends on `db` and `redis` being healthy. Env: `LTI_TOR_SOCKS_HOST=tor-proxy`, `LTI_TOR_SOCKS_PORT=9050`. |
| `celery_worker` | build `./backend` (`python:3.11-slim`) | none | Celery worker. Launched under `watchmedo auto-restart` (watchdog) watching `*.py` for dev hot-reload. Consumes queues `-Q acquisition,normalization,analysis,cti,reporting,celery` (without `-Q` it would only drain the default `celery` queue and the routed acquisition/normalization/analysis tasks would never run). Same env/DNS/deps as `api`. |
| `frontend` | build `./frontend` (`node:22-slim`) | `5173:5173` | React/Vite dev server (`npm run dev -- --host`). Code bind-mounted; named volume `frontend_node_modules` masks host `node_modules` ("trap killer"). `CHOKIDAR_USEPOLLING=true` for Windows file-change detection. `VITE_API_PROXY=http://api:8000`. Depends on `api`. |
| `robin_ui` / `robin_api` | build `./backend/services/robin` | (5000 / 8501) | **Commented out / disabled** — Streamlit + Uvicorn dark-web OSINT tool, "kept for testing". Not part of the running stack. |

Named volumes: `postgres_data`, `redis_data`, `frontend_node_modules`.

**Backend image (`backend/Dockerfile`):** base `python:3.11-slim`; installs OS packages `tor`, `build-essential`, `curl`, `libssl-dev`, `libffi-dev` (the latter two support the `cryptography` build; `tor` supports the OSINT path); `WORKDIR /app`; installs Python deps via `pip install --no-cache-dir -r requirements.txt`; default `CMD ["./entrypoint.sh"]` (overridden by Compose entrypoint for the `api` service).

**Frontend image (`frontend/Dockerfile`):** base `node:22-slim` (Node 22); `WORKDIR /app`; `npm install`; `EXPOSE 5173`; `CMD ["npm","run","dev","--","--host"]`. **This is a development image** — it serves the Vite dev server, not a production build.

**nginx (`frontend/nginx.conf`):** an nginx config exists for production-style static serving — `listen 80`, root `/usr/share/nginx/html`, SPA fallback `try_files $uri $uri/ /index.html`, and 1-year `immutable` cache headers for static assets (`js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot`). **Caveat:** neither `frontend/Dockerfile` nor `docker-compose.yml` references this nginx config or an nginx image — the active Compose frontend runs the Vite dev server on `5173`, not nginx. The nginx config is therefore present but **not wired into the current Compose deployment**; it implies an intended (but not Compose-integrated) production build/serve path. This should be flagged as a gap if formal docs describe production deployment.

### 2.5 LLM & CTI Providers (stack-level summary)

- **LLM:** provider-abstraction model. Default provider is **Google Gemini** (`google-generativeai`, `langchain_google_genai`). Additional installed providers — OpenAI (`langchain-openai`), Anthropic (`langchain-anthropic`), and local Ollama (`langchain-ollama`) — back the documented "offline fallback" and pluggable-provider design. `langchain_community` supplies shared integrations. The selection/fallback logic resides in backend source (referenced by the `pydantic-settings` config in `core/config.py`), not in any file in this section's scope, so the precise provider-resolution rules are not documented here.
- **CTI:** described as API-based. The `requests` library is the HTTP transport; the Tor `tor-proxy` service (port 9050, with `pysocks`) and `beautifulsoup4` exist to support a dark-web/OSINT path, but that path (the "Robin" `robin_ui`/`robin_api` services) is **commented out** in Compose. The concrete CTI provider endpoints are defined in backend code, not in these stack files.

**Overall stack caveats for the formal author:** (1) backend dependencies are entirely unpinned — non-reproducible builds; (2) the frontend runs as a *dev* container (Vite, Node 22) in Compose, with the production nginx path defined but not integrated; (3) the Cytoscape graph stack is installed but reportedly not the active topology renderer; (4) Tailwind v4's Vite plugin is installed but not registered in `vite.config.js`; (5) several heavyweight deps (`streamlit`, `pysocks`, `beautifulsoup4`, `tor`) serve a disabled OSINT subsystem. Each of these should be presented as a known state, not smoothed over.

---

## 3. System Architecture

LuminaFPM implements the **Hybrid Parallel Shared-Network Architecture** mandated by *Volume 2 — Complete System Architecture Specification* (`Volumes/_extracted/LuminaFPM_Volume_2_System_Architecture_Specification.txt`, §3.1). The platform is a strictly read-only, multi-vendor firewall policy intelligence system: it extracts configuration from FortiGate (REST/JSON) and Palo Alto PAN-OS (XML API) devices, normalizes their heterogeneous rulebases into a single canonical model, runs a deterministic anomaly engine over that normalized model, computes risk, enriches it with API-based CTI, and renders SOC-grade reports and a logical policy graph. The architecture rests on a single, non-negotiable principle (Volume 2 §3.2): the system does **not** depend on live packet traversal between the firewalls — it depends entirely on *extracting and comparing normalized policy intent*.

### 3.1 The End-to-End Layered Pipeline

The platform follows a strict layered model (Volume 2 §5: "no layer should bypass the layer below it"). Each layer has a single responsibility and hands a well-defined data structure to the next. The eight layers below are realized as concrete Python packages under `backend/services/` (per implementation decision LFPM-IMPL-003 in `docs/ARCHITECTURE_DECISIONS.md`).

| # | Layer (Volume 2) | Code package / module | Responsibility | Output handed downstream |
|---|---|---|---|---|
| 1 | Acquisition | `services/acquisition/` (`base.py`, `fortigate.py`, `paloalto.py`, `registry.py`, `storage.py`, `errors.py`, `models.py`) | Authenticate to the firewall API, poll read-only endpoints, store raw artifacts to disk with SHA-256 manifest, track job lifecycle | A `bundle` of raw vendor responses + `RawArtifact` rows on disk/DB |
| 2 | Parsing | `services/parsing/` (`fortigate.py`, `paloalto.py`, `registry.py`, `models.py`) | Convert raw vendor JSON/XML into structured vendor-tagged parser models; understands vendor formats but performs **no** anomaly detection | `ParsedDevicePayload` (vendor-specific) |
| 3 | Normalization | `services/normalization/` (`engine.py`, `canonical.py`, `model.py`, `persist.py`, `loader.py`) | Convert parsed vendor models into one canonical policy/object/service model, preserving vendor traceability; correlation-model object mapping | `NormalizationResult` (pure, DB-free) |
| 4 | Repository | PostgreSQL (Schema v4) via SQLAlchemy; written by `normalization/persist.py`, read by `normalization/loader.py` | Durable, queryable source of truth for all normalized + operational data | Rows in `policy_rule`, `network_object`, `normalized_object`, etc. |
| 5 | Analysis (Anomaly) | `services/anomaly/` (`engine.py`, `detectors.py`, `model.py`) | Deterministic, explainable, repeatable detection over the **normalized repository only** | `list[Finding]` → `rule_anomaly` rows |
| 6a | Risk | `services/risk/` (`runner.py`, `scorer.py`) | Aggregate anomaly findings into a 0–100 risk score + tier per rule and per device | `risk_assessment` rows |
| 6b | CTI | `services/cti/` (`extract.py`, `providers.py`, `runner.py`) | Extract indicators, query CTI APIs, correlate to rules, update risk | `cti_indicator` / threat-correlation rows |
| 7 | AI / LLM Reporting | `services/llm/` (`providers.py`, `prompts.py`, `reporter.py`) | Generate CTI queries and SOC/executive reports via a provider abstraction (offline fallback) | `llm_report` content |
| 8 | Presentation | React + TypeScript + Vite frontend (`frontend/`), Cytoscape.js graph | Dashboard, Policy Explorer, Anomaly/Risk/CTI/Benchmark Centers, logical graph | Rendered UI over the REST API |

#### Layer 1 — Acquisition
The acquisition layer (Volume 2 §6) is the only layer that touches a firewall, and it does so **read-only**. The connector for a device is selected at runtime by `services.acquisition.get_connector(config)` / `resolve_device_vendor_type(device)` (see `backend/tasks/acquisition.py`). A `ConnectorConfig` is assembled from the device record and the decrypted credential, then `connector.collect()` returns a bundle. Raw artifacts are persisted via `storage.store_bundle(job_id, bundle)`, and a `RawArtifact` row (`job_id`, `device_id`, `type`, `path`, `sha256`) is written per file (implementation decision LFPM-IMPL-009: raw bytes under `/raw_acquisition/{vendor}/{device}/{job}/` with a DB metadata row, for replay/audit). FortiGate acquisition uses REST endpoints under `/api/v2/cmdb/firewall/*` and `/api/v2/monitor/system/status`; Palo Alto uses the XML API (`type=keygen`, `type=config&action=show`, `type=op`) against the `vsys/.../rulebase/security`, `address`, `address-group`, `service`, `service-group` trees (Volume 2 §6.3–6.4).

**Job state machine** (Volume 2 Table 6, mapped in `_ERROR_TO_STATUS` of `tasks/acquisition.py`): `queued → running → {success | partial_success | failed | timeout | authentication_failed | authorization_failed | connection_failed | rate_limited | parsing_failed}`. On `success`/`partial_success` the device's `last_poll_time`, `status="online"` and `firmware_version` are updated.

#### Layer 2 — Parsing
`services.parsing.parse_artifacts(vendor_type, device_id, {artifact_type: text})` (invoked from `tasks/normalization.py`) replays the stored artifacts and produces a `ParsedDevicePayload`. The parser is vendor-aware (FortiGate JSON → FortiGate parser model; Palo Alto XML → Palo Alto parser model, per Volume 2 §7.1) but must not run anomaly logic. Parser output captures device/vendor identity, firmware, VDOM/VSYS, rule name, vendor rule ID, vendor UUID, rule order, source/destination zones, source/destination/service objects, action, logging, security profile group, schedule, NAT, description, tags, and enabled state (Volume 2 §7.3).

#### Layer 3 — Normalization
Normalization is split (implementation decision LFPM-IMPL-011) into a **pure engine** and a **thin persist layer**:
- `services.normalization.normalize_payloads([payload])` is pure and DB-free; it returns a `NormalizationResult`. It maps vendor actions to canonical ones (e.g. `accept/allow/permit → allow`, Volume 2 §8.4) while retaining the original vendor value for audit, and builds the **correlation-model** object mapping (ADR-019): vendor-owned objects stay separate, canonical normalized objects sit above them, mapping tables connect the two.
- `services.normalization.persist.persist_result(db, result, [payload])` performs an idempotent upsert keyed on `(device_id, vdom_vsys, vendor_uuid)` (LFPM-IMPL-001).

This realizes ADR-009/ADR-010: the normalized JSON is the *interchange/model* format, and the anomaly engine analyzes **only** normalized policies, never raw vendor output.

#### Layer 4 — Repository
PostgreSQL is the single v1 source of truth (ADR-008; MongoDB explicitly excluded by ADR-021). Schema is owned by **Alembic migrations**, not `Base.metadata.create_all` — `backend/main.py`'s `lifespan` explicitly retires `create_all` from the runtime path (LFPM-IMPL-002; comment cites "no destructive auto-sync"). Core tables (Volume 2 Tables 9–10) include `policy_rule`, `network_object`, `rule_object_mapping`, `normalized_object`, `object_normalization_mapping`, `normalized_service`, `service_normalization_mapping`, `rule_anomaly`, `anomaly_execution_log`, `risk_assessment`, `cti_indicator`/`cti_observation`, `benchmark_case`/`benchmark_result`, and `llm_report`. The repository is read back into a `NormalizationResult` by `services.normalization.loader.load_normalized_result(db, device_ids=...)` for analysis.

#### Layer 5 — Analysis (Deterministic Anomaly Engine)
`services.anomaly.analyze(result)` consumes a reconstructed `NormalizationResult` and returns a deterministic `list[Finding]` — **no randomness, no mock data, no LLM, no network** (`tasks/anomaly.py` module docstring; LFPM-IMPL-004 records the removal of the earlier random mock engine). The Volume 5 anomaly framework defines 46 anomaly categories (shadowing, redundancy, conflict, over-permissive, missing logging, weak profiles, cross-device inconsistency, compliance violation, asymmetric rules, etc.; Volume 2 §10.1). Every finding carries the full evidence contract (Volume 2 §10.4): `anomaly_type`, `severity`, `confidence`, `description`, `evidence`, `recommendation`, `detection_mode`, the affected rule and (when applicable) related rule, and the `analysis_run_id`. Findings are written as `RuleAnomaly` rows tied to one `AnomalyExecutionLog` run (`engine_version = "anomaly-engine/1.0.0"`).

#### Layer 6 — Risk and CTI
**Risk** (`services/risk/runner.run_risk`, `scorer.py`) is a separate engine that does not replace anomaly detection. It scores each active rule from its findings and aggregates a device-level score on a **0–100 scale** (`calculation_version = RISK_VERSION = "1.0.0"`), persisting `risk_assessment` rows for both `rule` and `device` scope, idempotent per run (it deletes that run's prior rows but keeps cross-run history). Tier thresholds (`scorer.tier_of`, matching Volume 2 Table 11): **90–100 Critical, 70–89 High, 40–69 Medium, 1–39 Low, 0 Informational**. Risk is triggered as a best-effort step at the end of each anomaly run (`tasks/anomaly.py` calls `run_risk(db, run.run_id)`; a risk failure must never fail the analysis).

**CTI** (`services/cti/runner.run_cti`, ADR-012 "separate risk engine") extracts indicators (public IPs / FQDNs / firmware/CVEs), generates CTI queries (via LLM), calls CTI APIs, normalizes responses, correlates them to rules, generates threat observations, and updates the risk score before handing results to the LLM reporter (Volume 2 §11.3, flow §15.4).

#### Layer 7 — AI / LLM Reporting
AI is **not** an anomaly authority (ADR-013). The LLM layer exposes a provider abstraction (`services/llm/providers.py`): `LLMProvider` (abstract) with `GeminiProvider` and an `OfflineProvider` deterministic, network-free fallback. `build_provider(provider_name, api_key, model)` selects the provider from config and falls back to offline when unkeyed (Volume 10 §11). Its role is bounded to query generation, CTI review, and SOC/executive report generation (Volume 2 §12.1).

#### Layer 8 — Presentation
React + TypeScript + Vite (ADR-015) with a Cytoscape.js logical-policy graph (ADR-007/ADR-017). The graph represents **logical policy relationships only** — never runtime traffic, NetFlow, packet forwarding, live sessions, or DPI (Volume 2 §13.2). The UI is composed of the Centers in Volume 2 Table 12 (Dashboard, Device Inventory, Policy Explorer, Anomaly Center, Risk Center, CTI Threat Center, Benchmark Center, Graph View, Reports, Admin Settings).

### 3.2 Runtime Topology: FastAPI Request Cycle vs. Celery Workers

The runtime is split into a **synchronous API tier** and an **asynchronous worker tier**, mediated by Redis (broker) and PostgreSQL (state + result backend). The hard rule (Volume 2 §6.5) is: *acquisition must never run inside the web request cycle; the frontend must never wait for firewall polling synchronously.*

**FastAPI (`backend/main.py`).** A single FastAPI app (`title="LuminaFPM Backend API"`, `version="0.1.0"`) mounts routers for vendors, devices, network objects, rules, jobs, anomalies, benchmark, risk, cti, reports, plus the threat-intel router. CORS is a **restricted allowlist** from `settings.cors_allowed_origins` (default `http://localhost:5173`) — wildcard-with-credentials is explicitly rejected (LFPM-IMPL-007). The API does only fast, transactional work: validate the request, create a job/log row, enqueue a Celery task, and serve reads from PostgreSQL. Health/diagnostic endpoints: `GET /`, `GET /health`, `GET /checkdbconnection`.

**Celery (`backend/celery_app.py`).** A single `Celery("lumina_fpm")` app with **Redis as broker** (`REDIS_URL`, default `redis://redis:6379/0`) and **PostgreSQL as the result backend** (`db+<DATABASE_URL>`, durable result persistence). Reliability tuning: `task_acks_late=True` (ACK only after completion — crash-safe), `worker_prefetch_multiplier=1` (no greedy prefetch), `task_track_started=True`, JSON serialization, UTC, `result_expires=86400` (24h). **Per-job-type queue routing** (`task_routes`, per Volume 2 §14.3) so slow firewall polling never blocks analysis/CTI/reporting:

| Task name | Queue | Module |
|---|---|---|
| `acquisition.poll_device` | `acquisition` | `tasks/acquisition.py` |
| `normalization.normalize_device` | `normalization` | `tasks/normalization.py` |
| `analysis.run_anomaly_analysis` | `analysis` | `tasks/anomaly.py` |
| `cti.*` | `cti` | (CTI tasks) |
| `reporting.*` | `reporting` | (reporting tasks) |
| `tasks.run_scan_pipeline` | (default `celery`) | `tasks/threat_intel.py` |

Registered task modules: `tasks.acquisition`, `tasks.normalization`, `tasks.threat_intel`, `tasks.anomaly`. Each task opens its **own** DB session via `SessionLocal = get_db()` because the worker is a separate process/container.

**Implementation note (single worker, all queues).** Volume 2 §14.3 recommends *splitting* workers by job type (`worker-acquisition`, `worker-normalization`, `worker-analysis`, `worker-cti`, `worker-reporting`). The current `docker-compose.yml` runs **one** `celery_worker` container that consumes *all* routed queues with `-Q acquisition,normalization,analysis,cti,reporting,celery`. The queue routing exists and is correct, but horizontal split-by-queue scaling is not yet provisioned — this is a partial realization of the spec and is called out plainly here.

### 3.3 How a Sync/Analyze Request Flows (API → Task → Worker → DB → API read)

The canonical end-to-end flow chains acquisition → normalization → analysis → risk automatically, each stage enqueuing the next on a different queue.

**1. Trigger (API, synchronous).** `POST /api/devices/{device_id}/poll` (`backend/api/routes/devices.py`, status `202 Accepted`) verifies the device exists and that a credential is configured (`credentials.has_credential`; `409` if absent), inserts an `AcquisitionJob` row (`requested_by="api"`, status defaults to queued), then dispatches `poll_device.delay(job_id=job.job_id)` to the `acquisition` queue. It returns `{job_id, status:"queued", device_id}` immediately — no firewall I/O in the request.

**2. Acquisition (worker, `acquisition` queue).** `poll_device` decrypts the credential (`credentials.get_decrypted_secret`), resolves the vendor type, sets the job `running`, builds the connector, calls `connector.collect()`, stores raw artifacts, updates device freshness/firmware, sets the job `success`/`partial_success`, and — on either success state — chains `normalize_device.delay(job_id)`.

**3. Normalization (worker, `normalization` queue).** `normalize_device` loads the job's `RawArtifact` rows, reads each file from disk (`storage.load_artifact`, skipping the manifest), then runs `parse_artifacts → normalize_payloads → persist_result` (idempotent upsert into Schema v4). It then chains `run_anomaly_analysis_task.delay(device_id=device_id)`.

**4. Analysis (worker, `analysis` queue).** `run_anomaly_analysis_task(device_id=None|int)` opens an `AnomalyExecutionLog` (`status="running"`), reconstructs the `NormalizationResult` via `load_normalized_result`, runs `analyze(result)`, maps each `Finding` `(device_id, rule_uuid) → PolicyRule.rule_id` (skipping rules absent from the repository rather than guessing), inserts `RuleAnomaly` rows, finalizes the log (`completed`, `findings_count`), and best-effort triggers `run_risk(db, run.run_id)`. `device_id=None` analyzes **all** devices — required for cross-device detectors. Analysis can also be triggered directly via the API (`api/routes/rules.py:141` and `api/routes/anomalies.py:67` both call `run_anomaly_analysis_task.delay(...)`).

**5. Read-back (API, synchronous).** The frontend polls job status through read-only endpoints `GET /api/v1/jobs`, `/api/v1/jobs/{job_id}`, and `/api/v1/jobs/{job_id}/artifacts` (`backend/api/routes/jobs.py`), which expose lifecycle and artifact metadata (type/path/sha256) but never secrets. Findings, risk, CTI, and reports are then read from PostgreSQL via the anomalies/risk/cti/reports routers.

A parallel asynchronous path exists for threat-intel scans: `run_scan_task.delay(report_id, ...)` (`tasks/threat_intel.py`) opens its own session, runs the `orchestrator.run_scan()` pipeline, and publishes progress to a **Redis Pub/Sub** channel `sse_events:{report_id}` that an SSE endpoint relays to the UI (hard `time_limit=1800s`, soft `1500s`).

```
                       SYNC (FastAPI request cycle)
  POST /api/devices/{id}/poll  ──▶  insert AcquisitionJob ──▶ 202 {job_id}
                                          │  .delay()
                                          ▼
        ┌───────────────────────── Redis broker ─────────────────────────┐
        │  queue:acquisition   queue:normalization   queue:analysis ...   │
        └───────┬─────────────────────┬───────────────────────┬──────────┘
                ▼                      ▼                       ▼
   ASYNC   poll_device  ──delay──▶ normalize_device ──delay──▶ run_anomaly_analysis
 (workers) read-only API     parse→normalize→persist     analyze→RuleAnomaly→run_risk
                │                      │                       │
                ▼                      ▼                       ▼
         RawArtifact(+disk)     Schema v4 repository     rule_anomaly + risk_assessment
                └──────────────────────┴───────────────────────┘
                                       ▼
                          PostgreSQL  (state + Celery result backend)
                                       ▲   SYNC read-back
  GET /api/v1/jobs/{id} , /api/anomalies , /api/risks , /api/cti , /api/reports
```

### 3.4 The Read-Only Boundary

LuminaFPM is **config-only** and must never modify a firewall (ADR-006; Volume 2 §18.1 forbids push/delete/reorder/commit/enable/disable rule and modify object/service). The enforcement is structural:

- **In Lumina (this platform): read-only poll keys only.** Connectors call only read endpoints (FortiGate `cmdb`/`monitor` GETs; Palo Alto `keygen`/`config show`/`op`). There is **no** write/commit code path. Device secrets live encrypted at rest in the `device_credential` table (`secret_encrypted`, Fernet via `core.security.encrypt_secret`/`decrypt_secret`, LFPM-IMPL-008) and are decrypted **only in backend/worker memory** by `services.credentials.get_decrypted_secret` — never returned to the frontend, never logged (`backend/services/credentials.py`). Valid auth types: `fortigate_api_token`, `panos_api_key`, `panos_userpass`. The frontend may create/rotate/test a credential but receives status only.
- **In the lab provisioner: write keys only.** The firewall write/admin keys that build the lab rulebases live with the parallel-lab provisioning tooling, **outside** Lumina's trust boundary, so that even a compromised Lumina instance holds no key capable of altering a firewall. (The two firewalls share logical networks but never forward production traffic through each other — Volume 2 §3.1.)

### 3.5 Key Architecture Decisions (ADR Summary)

The binding ADRs (`docs/ARCHITECTURE_DECISIONS.md` §A; Volume 2 Table 19) that shape this architecture:

| ID | Decision | Architectural consequence |
|---|---|---|
| ADR-005 | **Hybrid Parallel Shared-Network lab** | FortiGate (.10) + Palo Alto (.20) on shared logical nets, independent policy engines, no inline traffic |
| ADR-006 | **No live traffic analysis** | Config-only; no NetFlow/packet capture anywhere |
| ADR-007 | **Logical policy graph** | Cytoscape graph models policy relationships, not packet flow |
| ADR-008 | **PostgreSQL = source of truth** | Single relational store; structured joins across devices/rules/objects/anomalies/threats/benchmarks |
| ADR-009 | **Normalized JSON = interchange only** | Canonical model is a transport/compute format, not the DB authority |
| ADR-010 | **Anomaly input = normalized only** | Engine never reads raw vendor data |
| ADR-011 | **Runtime anomalies = conditional + benchmark-simulated** | No live runtime telemetry; simulated via benchmark cases |
| ADR-012 | **CTI = separate risk engine** | CTI decoupled from deterministic anomaly detection |
| ADR-013 | **AI = query gen / CTI review / SOC reporting** | LLM is never an anomaly authority |
| ADR-014/015/016/017/018 | FastAPI / React+TS / Celery+Redis / Cytoscape.js / Docker Compose | The runtime stack of §3.2 and §3.6 |
| ADR-019 | **Object correlation model** | Vendor objects preserved; canonical objects + mapping tables above them |
| ADR-021 | **No MongoDB** | PostgreSQL-only persistence |
| ADR-022 | **LLM providers via abstraction** | Gemini/OpenAI/Ollama swappable; offline fallback (§3.1 Layer 7) |

Implementation-level decisions (LFPM-IMPL-001…011) record how these were realized — notably Alembic-owned schema (no `create_all`), the pure-normalization/persist split, encrypted `device_credential`, raw-artifact filesystem storage with DB metadata, the deterministic engine replacing the random mock, and the de-emphasis of dark-web/Robin CTI in favor of API-based CTI.

### 3.6 Container Topology (Docker Compose)

Deployment is Docker Compose (ADR-018). The actual `docker-compose.yml` defines the services below (note: the spec's Volume 2 §17.1 ideal of separate per-queue worker containers is collapsed into one `celery_worker`, and a `tor-proxy` exists only to support the quarantined dark-web research path of LFPM-IMPL-005).

| Service | Image / build | Ports | Role |
|---|---|---|---|
| `db` | `postgres:16-alpine` | `expose 5432` (no host publish) | Repository / Celery result backend |
| `redis` | `redis:7-alpine` | `expose 6379` (no host publish) | Celery broker + SSE Pub/Sub |
| `api` | build `./backend` | `8000:8000` | FastAPI (uvicorn `--reload` via entrypoint) |
| `celery_worker` | build `./backend` | — | Consumes `acquisition,normalization,analysis,cti,reporting,celery` (watchmedo auto-restart) |
| `frontend` | build `./frontend` | `5173:5173` | React + Vite dev server (`VITE_API_PROXY=http://api:8000`) |
| `tor-proxy` | build `./tor-proxy` | `9050:9050` | SOCKS proxy for the (disabled-by-default) dark-web research path |

**Security-relevant topology:** `db` and `redis` are bound with `expose` only — **not** published to the host (comments cite Volume 12 §12 / Volume 13 Table 4) — so PostgreSQL and Redis are reachable solely on the internal Docker network. Secrets are injected from a `.env` file (`env_file: .env`), never hardcoded. The worker shares the backend image and bind-mounts `./backend`, restarting on `*.py` changes via `watchmedo auto-restart` (without it the worker would run stale in-memory code). Named volumes `postgres_data`, `redis_data`, and `frontend_node_modules` provide persistence/isolation.

```
┌───────────────────────── Docker Compose host ─────────────────────────┐
│                                                                        │
│  frontend (5173) ──HTTP──▶ api (8000) ──┬── SQLAlchemy ──▶ db (5432*)  │
│   React+Vite              FastAPI/uvicorn │                  Postgres   │
│                                           │                            │
│                                .delay()   ▼                            │
│                              redis (6379*) ◀── result/progress ── db   │
│                                Redis broker                            │
│                                   │ consume Q                          │
│                                   ▼                                    │
│                          celery_worker ──▶ read-only firewall APIs     │
│                       (acq/norm/analysis/cti/reporting)   (192.168.55.*)│
│                                                                        │
│  tor-proxy (9050)  [dark-web research path, disabled by default]       │
│                                                                        │
│  * = internal-only (expose, not published)                            │
└────────────────────────────────────────────────────────────────────────┘
                                    │ read-only HTTPS/HTTP (config-only)
                                    ▼
        Parallel VMware lab — FortiGate .10 / Palo Alto .20 on 192.168.55.0/24
```

The lab firewalls are reached over the ADMIN/API network `192.168.55.0/24` (Volume 2 Table 14). Lumina's connectors negotiate scheme per device — HTTPS by default, falling back to HTTP only for hosts in `settings.firewall_insecure_http_hosts` (a documented FortiGate-HTTPS-broken lab quirk; `tasks/acquisition.py` lines 79–81) — and in all cases issue read-only requests, preserving the config-only / no-write boundary of §3.4.

---

## 4. Backend — Acquisition, Parsing & Normalization

This section documents the read-only data pipeline that turns live firewall configuration into the canonical normalized repository the anomaly engine consumes. The pipeline has three sequential layers, each in its own package under `backend/services/`:

```
FortiGate REST JSON / Palo Alto XML
        │  (acquisition: connectors → AcquisitionBundle → raw artifacts on disk)
        ▼
   Vendor Parsers (parsing: raw text → ParsedDevicePayload, vendor-tagged)
        │
        ▼
 Normalization Engine (normalization: ParsedDevicePayload[] → NormalizationResult → PostgreSQL Schema v4)
        ▼
 Deterministic Anomaly Engine (reads the NORMALIZED repository only — ADR-010, V4 Table 1)
```

Binding architectural rule (`docs/NORMALIZATION_MODEL.md` §1, V4 Table 1): **the anomaly engine analyzes normalized records only**; raw FortiGate JSON and Palo Alto XML are acquisition/parser inputs and are never analyzed directly. Every connector is strictly read-only — it issues only GET / `show` / `monitor` / `keygen` / op-`show` calls and never `set`/`edit`/`delete`/`move`/`commit` (V3 Table 24, V12 §3). The platform is config-only and never writes to firewalls.

### 4.1 Acquisition layer (`backend/services/acquisition/`)

Read-only extraction of firewall configuration from FortiGate (FortiOS REST/JSON) and Palo Alto (PAN-OS XML). Connectors collect data only — no anomaly logic, no write/commit. Acquisition runs asynchronously via Celery workers, never inside the FastAPI request cycle (`__init__.py` docstring).

#### 4.1.1 `base.py` — connector abstraction & `ConnectorConfig`

- **Responsibility:** defines the read-only vendor connector contract (V3 §5) plus the connection-parameter dataclass.
- **`ConnectorConfig` (dataclass):** connection parameters resolved from the device record + the decrypted credential. Fields:

  | Field | Type | Default | Notes |
  |---|---|---|---|
  | `device_id` | `int` | — | |
  | `vendor_type` | `str` | — | `fortinet` \| `paloalto` |
  | `management_ip` | `str` | — | |
  | `secret` | `str` | — | decrypted token / api-key / user:pass — in-memory only |
  | `auth_type` | `str` | — | `fortigate_api_token` \| `panos_api_key` \| `panos_userpass` |
  | `verify_tls` | `bool` | `True` | |
  | `timeout_seconds` | `int` | `60` | |
  | `scheme` | `str` | `"https"` | **the scheme/HTTP-override field** — `"http"` only as a lab escape hatch (see §4.1.8) |

- **`ConnectorInterface(abc.ABC)`:** abstract base. Class attributes `vendor_type = "unknown"`, `connector_version = "1.0.0"`. Constructor stores `config`. Abstract methods:
  - `authenticate() -> None` — establish/validate auth, no config changes.
  - `validate_connection() -> bool` — lightweight read confirming connectivity + auth.
  - `collect() -> AcquisitionBundle` — full read-only extraction. Contract (docstring): call ONLY read endpoints, capture each response as a `RawArtifact`; failure of an *optional* endpoint → warning + `partial_success`; failure of a *required* endpoint (policies) → raise an `AcquisitionError`.

#### 4.1.2 `models.py` — acquisition data contracts (V3 §11)

Vendor-neutral bundle handed to the parser layer.

- **`AcquisitionStatus(str, Enum)`:** `queued`, `running`, `success`, `partial_success`, `failed`, `timeout`, `authentication_failed`, `authorization_failed`, `connection_failed`, `rate_limited`, `parsing_queued`, `parsing_failed`.
- **`ErrorCode(str, Enum)`:** `AUTH_FAILED`, `AUTHZ_FAILED`, `CONNECTION_FAILED`, `TIMEOUT`, `TLS_FAILED`, `RATE_LIMITED`, `UNSUPPORTED_ENDPOINT`, `MALFORMED_RESPONSE`, `PARTIAL_DATA`.
- **Canonical raw-artifact type constants (V3 Table 11):** `ARTIFACT_POLICIES="policies"`, `ARTIFACT_ADDRESS_OBJECTS="address_objects"`, `ARTIFACT_ADDRESS_GROUPS="address_groups"`, `ARTIFACT_SERVICE_OBJECTS="service_objects"`, `ARTIFACT_SERVICE_GROUPS="service_groups"`, `ARTIFACT_DEVICE_METADATA="device_metadata"`, `ARTIFACT_INTERFACES="interfaces"`, `ARTIFACT_ZONES="zones"`, `ARTIFACT_SCHEDULES="schedules"`, `ARTIFACT_MANIFEST="acquisition_manifest"`.
- **`RawArtifact` (dataclass):** one raw API response captured for replay/audit (V3 §8). Fields `type`, `content` (raw text — JSON for FortiGate, XML for Palo Alto), `content_type="application/json"`, `sha256: Optional[str]`, `path: Optional[str]` (set once persisted).
- **`AcquisitionWarning` (dataclass):** `type`, `message`, `reference: Optional[str]`.
- **`AcquisitionBundle` (dataclass):** vendor-neutral acquisition result. Fields: `device_id`, `vendor_type` (`fortinet`|`paloalto`), `management_ip`, `connector_version`, `status` (default `RUNNING`), `firmware_version`, `device_metadata: Dict`, `raw_artifacts: List[RawArtifact]`, `warnings: List[AcquisitionWarning]`, `error_code`, `error_message`. Helper methods `add_artifact(artifact)` and `add_warning(type_, message, reference=None)`.

#### 4.1.3 `errors.py` — error taxonomy (V3 §13.1, Table 23)

`AcquisitionError(Exception)` is the base. Each subclass carries a normalized `code` and a `retryable` flag (drives retry policy). Messages must be SAFE — never include secrets (V3 §14.2). Constructor accepts `message` and an optional `retryable` override.

| Exception class | `code` | `retryable` | Trigger |
|---|---|---|---|
| `AcquisitionError` | `ACQUISITION_ERROR` | `False` | base class |
| `AuthenticationError` | `AUTH_FAILED` | `False` | bad token/key (no hammering — lockout risk, V3 §13.2) |
| `AuthorizationError` | `AUTHZ_FAILED` | `False` | token lacks permission |
| `ConnectionFailedError` | `CONNECTION_FAILED` | `True` | network / generic HTTP ≥400 |
| `TimeoutError` (domain alias) | `TIMEOUT` | `True` | request timed out |
| `TLSError` | `TLS_FAILED` | `False` | TLS verification failed |
| `RateLimitedError` | `RATE_LIMITED` | `True` | rate-limited by device |
| `UnsupportedEndpointError` | `UNSUPPORTED_ENDPOINT` | `False` | 404 / endpoint absent |
| `MalformedResponseError` | `MALFORMED_RESPONSE` | `False` | unparseable body |
| `PartialDataError` | `PARTIAL_DATA` | `False` | incomplete extraction |
| `UnsupportedVendorError` | `UNSUPPORTED_VENDOR` | `False` | no connector for vendor_type |

#### 4.1.4 `fortigate.py` — FortiGate connector (FortiOS REST, V3 §9)

- **Responsibility:** read-only FortiOS REST acquisition. Class `FortiGateConnector(ConnectorInterface)`, `vendor_type="fortinet"`, `connector_version="1.0.0"`.
- **Auth:** Bearer API token via `_headers()` → `{"Authorization": f"Bearer {secret}", "Accept": "application/json"}` (dedicated read-only API admin account; token in memory only). `authenticate()` simply calls `validate_connection()` (stateless token auth). `validate_connection()` does a cheap GET of `/api/v2/monitor/system/status`.
- **`_base_url()`:** `f"{self.config.scheme}://{self.config.management_ip}"` — this is where the `scheme` override (http/https) takes effect for FortiGate.
- **`_get(path) -> (status_code, text)`:** the single read-only HTTP helper — there is no write verb anywhere in the module, which is how read-only is enforced (V3 Table 24, V12 §3). `requests` is imported lazily. Exception → error mapping:
  - `requests.exceptions.SSLError` → `TLSError`
  - `requests.exceptions.Timeout` → `AcqTimeoutError`
  - `requests.exceptions.ConnectionError` → `ConnectionFailedError`
  - HTTP `401` → `AuthenticationError`; `403` → `AuthorizationError`; `404` → `UnsupportedEndpointError`; any other `>= 400` → `ConnectionFailedError`.
- **Endpoint table `_ENDPOINTS`** (V3 Table 13) — `(artifact_type, path, required)`:

  | Artifact | Path | Required |
  |---|---|---|
  | policies | `/api/v2/cmdb/firewall/policy` | yes |
  | address_objects | `/api/v2/cmdb/firewall/address` | yes |
  | address_groups | `/api/v2/cmdb/firewall/addrgrp` | yes |
  | service_objects | `/api/v2/cmdb/firewall.service/custom` | yes |
  | service_groups | `/api/v2/cmdb/firewall.service/group` | yes |
  | device_metadata | `/api/v2/monitor/system/status` | yes |
  | interfaces | `/api/v2/cmdb/system/interface` | no |
  | schedules | `/api/v2/cmdb/firewall.schedule/recurring` | no |

- **`collect()`:** iterates `_ENDPOINTS`. A required endpoint raising `UnsupportedEndpointError` re-raises (fatal); an optional one is swallowed → `add_warning("unsupported_endpoint", …)` and `had_optional_failure=True`. Each successful response is appended as a `RawArtifact` (`content_type="application/json"`). For `device_metadata`, `_extract_firmware()` pulls `results.version` / `results.os_version` (fallback top-level `version`) into `bundle.firmware_version` and `device_metadata["firmware_version"]`. Final status = `PARTIAL_SUCCESS` if any optional endpoint failed, else `SUCCESS`.

#### 4.1.5 `paloalto.py` — Palo Alto connector (PAN-OS XML API, V3 §10)

- **Responsibility:** read-only PAN-OS XML-API acquisition. Class `PaloAltoConnector(ConnectorInterface)`, `vendor_type="paloalto"`, `connector_version="1.0.0"`. Instance state: `self.vsys="vsys1"`, `self._api_key`.
- **`_base_url()`:** `f"https://{self.config.management_ip}/api/"` — **note: PAN-OS hardcodes `https://` and ignores `config.scheme`**, so the HTTP escape hatch (§4.1.8) applies to FortiGate only.
- **Auth:** API key via `X-PAN-KEY` header. `authenticate()`:
  - `auth_type == "panos_userpass"`: `secret` is `"user:password"` (must contain `:`, else `AuthenticationError`); issues a read-only `type=keygen` request and regex-extracts `<key>…</key>` to obtain an ephemeral key.
  - otherwise: `secret` IS the API key.
- **`_request(params, with_key=True) -> str`:** lazy `requests.get` against `_base_url()` with params. Same connection-error mapping as FortiGate (SSL→`TLSError`, Timeout→`AcqTimeoutError`, ConnectionError→`ConnectionFailedError`). HTTP `403` → `AuthenticationError`; any `>= 400` → `ConnectionFailedError`. PAN-OS returns HTTP 200 with `status="error"` in the XML body for bad auth, so the body is additionally inspected for `status="error"` + `Invalid credential` → `AuthenticationError`.
- **`_vsys_xpath(vsys, leaf)`:** returns `/config/devices/entry/vsys/entry/{leaf}` — the *unqualified* xpath proven working against the lab single-vsys PAN-OS (no `[@name=...]` predicate). Multi-vsys predicates can be reintroduced later.
- **`_config_show(leaf)`:** `type=config&action=show&xpath=<vsys_xpath(leaf)>`.
- **`validate_connection()`:** authenticates if needed, then op-command `<show><system><info></info></system></show>`.
- **`collect()`:** authenticates if needed, then:
  - Required op command: system info (`<show><system><info>…`) → `device_metadata` artifact (`application/xml`); firmware extracted via `_extract_firmware()` regex on `<sw-version>…</sw-version>`.
  - Required config leaves (V3 Table 18): `rulebase/security`→policies, `address`→address_objects, `address-group`→address_groups, `service`→service_objects, `service-group`→service_groups.
  - Recommended: `zone`→zones; on `ConnectionFailedError` → `add_warning("unsupported_endpoint", …)` rather than failing.
  - Sets status `SUCCESS` (note: unlike FortiGate it does not downgrade to `PARTIAL_SUCCESS` when the optional zones leaf fails).

#### 4.1.6 `registry.py` — connector dispatch (V3 §5.2)

- `_CONNECTORS = {"fortinet": FortiGateConnector, "paloalto": PaloAltoConnector}`.
- `normalize_vendor_type(value)`: lowercases/strips; `"forti"` substring → `fortinet`; `"palo"`/`"pan-os"`/`"panos"` → `paloalto`; otherwise passes the value through.
- `resolve_device_vendor_type(device)`: duck-typed (no models import) — reads `device.vendor_type`, falling back to the related `vendor.name` / `vendor.api_type`; returns `""` if indeterminable.
- `get_connector(config) -> ConnectorInterface`: looks up `config.vendor_type` (lowercased); raises `UnsupportedVendorError` if absent.
- `supported_vendors()` → sorted keys. Never hardcodes IPs or credentials.

#### 4.1.7 `storage.py` — raw acquisition persistence (V3 §8)

Persists each raw response to disk so the parser can replay without re-polling, and writes a manifest with per-artifact SHA-256 hashes.

- **Layout (V3 §8.2):** `{settings.acquisition_raw_dir}/{vendor_type}/{device_id}/{job_id}/<type>.json|.xml` + `acquisition_manifest.json`. `acquisition_raw_dir` defaults to `/app/raw_acquisition` (env `ACQUISITION_RAW_DIR`).
- `_sha256(text)`: hex SHA-256 of UTF-8 bytes. `_ext_for(content_type)`: `"xml"` if `"xml"` in the content-type else `"json"`.
- **`store_bundle(job_id, bundle) -> List[{type, path, sha256}]`:** creates the job dir; for each `RawArtifact` writes the content to `<type>.<ext>`, sets `art.sha256`/`art.path`, and collects metadata. Writes `acquisition_manifest.json` containing `job_id`, `device_id`, `vendor_type`, `management_ip`, `connector_version`, `firmware_version`, `status`, the per-artifact list (`type`, relative `path`, `sha256`), and serialized `warnings`. The manifest itself is appended to the returned list as an `ARTIFACT_MANIFEST` entry. The caller persists these dicts as `raw_artifact` rows.
- **`load_artifact(path) -> str`:** reads a stored artifact back for parser replay (V3 §11.1).

#### 4.1.8 FortiGate HTTP-over-80 lab workaround

The lab FortiGate VM's `httpsd` will not bind 443, so the management API is reachable only over plain HTTP (`lab-environment.md`). The escape hatch is implemented end-to-end:

- `core/config.py` adds `firewall_insecure_http_hosts_raw` (env `FIREWALL_INSECURE_HTTP_HOSTS`, CSV) exposed as the list property `firewall_insecure_http_hosts`. Documented as **lab-only — NEVER set in production, since API tokens would traverse unencrypted** (V3 Table 25).
- Both call sites that build a `ConnectorConfig` choose the scheme per-host:
  - `tasks/acquisition.py`: `scheme = "http" if device.management_ip in settings.firewall_insecure_http_hosts else "https"`, passed to `ConnectorConfig(..., verify_tls=settings.firewall_tls_verify, scheme=scheme)`.
  - `api/routes/devices.py` (connectivity test): identical scheme selection, with a clamped `timeout_seconds=min(15, settings.acquisition_timeout_seconds)`.
- `FortiGateConnector._base_url()` honors `scheme`; `PaloAltoConnector._base_url()` does not (PAN-OS is always HTTPS), so the override is FortiGate-specific.

### 4.2 Parsing layer (`backend/services/parsing/`)

Converts raw vendor API responses (FortiGate JSON / Palo Alto XML) into structured, **vendor-tagged** parser models. Parsers extract and structure data ONLY — no anomaly logic and no canonicalization (that belongs to normalization). Raw vendor values are deliberately preserved at this stage (e.g. action `accept`/`allow`, `logtraffic` `utm`). Parsers can replay from stored raw artifacts without re-polling (`__init__.py`, V2 §7, V3 §11).

#### 4.2.1 `models.py` — parser output models (V2 §7.3, V3 §11)

Uniformly-shaped dataclasses so normalization can consume both vendors:

- **`ParsedAddressObject`:** `name`, `type` (`ip_address`|`cidr`|`fqdn`|`any`|`unknown`), `value` (canonical-ish, e.g. `10.10.10.0/24`), `raw_value`, `vendor_uuid`.
- **`ParsedAddressGroup`:** `name`, `members: List[str]`, `vendor_uuid`.
- **`ParsedServiceObject`:** `name`, `protocol` (`tcp`|`udp`|`icmp`|`application`|`any`|`unknown`), `port_start`, `port_end`, `app_id`, `raw_value`.
- **`ParsedServiceGroup`:** `name`, `members: List[str]`.
- **`ParsedRule`:** `vendor`, `rule_name`, `rule_order`, `vendor_rule_id`, `vendor_uuid`, `vdom_vsys`, `enabled`, `src_zones`, `dst_zones`, `src_addrs`, `dst_addrs`, `services`, `applications`, `action` (raw vendor action), `logging_raw`, `security_profiles: Dict`, `schedule`, `nat_enabled`, `description`, `src_negate`, `dst_negate`, `raw: Dict`.
- **`ParsedDevicePayload`:** `device_id`, `vendor`, `firmware_version`, `vdom_vsys`, plus lists `rules`, `address_objects`, `address_groups`, `service_objects`, `service_groups`, and `warnings`.

#### 4.2.2 `fortigate.py` — FortiOS JSON parser

Validated against a real FortiOS v7.0.5 `firewall/policy` response.

- **Helpers:** `_results(text)` decodes JSON and returns the `results` list (empty on any error). `_names(items)` flattens FortiGate object refs `[{"name": …}]` (or bare strings) to a name list. `_subnet_to_cidr("A.B.C.D MASK")` converts FortiGate dotted-mask subnets to CIDR via `ipaddress.ip_network(..., strict=False)`. `_int`/`_firmware` are tolerant helpers; `_firmware` scans `device_metadata`/`policies`/`address_objects` for `results.version` or top-level `version`.
- **`_parse_addresses`:** maps FortiGate `type` → canonical-ish: `iprange`→`range` (`start-ip`-`end-ip`), `ipmask`/`ipprefix`→`cidr` (via `_subnet_to_cidr`), `fqdn`→`fqdn`, else `unknown`. Captures `uuid` as `vendor_uuid`.
- **`_parse_services`:** picks `tcp-portrange`→`tcp`, `udp-portrange`→`udp`, or `protocol==ICMP`→`icmp`; splits the first range token on `-` into `port_start`/`port_end`.
- **`_parse_addrgrps` / `_parse_service_groups`:** name + `member` list.
- **`_parse_rules`:** enumerates `results` with 1-based `rule_order`. Builds a `security_profiles` dict (`utm_status`, `profile_group`, `profile_type`, `av_profile`, `ips_sensor`, `webfilter_profile`, `application_list`, `ssl_ssh_profile`). Maps `srcintf`/`dstintf`→zones, `srcaddr`/`dstaddr`→addrs, `service`→services. `enabled = (status=="enable")`, `nat_enabled` from `nat`, negates from `srcaddr-negate`/`dstaddr-negate`. `rule_name` falls back to `policy-{policyid}`; raw record kept in `raw`. `action` kept raw.
- **`parse(device_id, artifacts)`:** reads `vdom` from the top level of the policy response, assembles a `ParsedDevicePayload(vendor="fortinet")`.

#### 4.2.3 `paloalto.py` — PAN-OS XML parser

Validated against a real PAN-OS `rulebase` config-show response. Uses `defusedxml.ElementTree.fromstring` when available (hardened against entity-expansion, V12 §10), falling back to stdlib `xml.etree.ElementTree`.

- **Helpers:** `_members(entry, path)` collects `{path}/member` text; `_text(entry, path)` returns a stripped element text; `_to_int`; `_firmware` finds `.//sw-version`.
- **`_parse_rules`:** finds `.//security/rules/entry` (fallback `.//rules/entry`), 1-based order. `enabled = not (disabled=="yes")`. Logging: `logging_raw="yes"` if `log-start` or `log-end` is `yes`, else `"no"`. `security_profiles = {"has_profile": <profile-setting has children>, "profile_group": <group/member text>}`. Maps `from`/`to`→zones, `source`/`destination`→addrs, `service`→services, `application`→`applications`. `nat_enabled=None` (PAN NAT is a separate policy type — future, V4 Table 7). Negates from `negate-source`/`negate-destination`. `raw` stores only `{name, uuid}`.
- **`_parse_addresses`:** `ip-netmask`→`cidr` if it contains `/` else `ip_address`; `fqdn`→`fqdn`; `ip-range`→`cidr`; else `unknown`.
- **`_parse_addrgrps`:** members from `static`. `_parse_services`: reads `protocol/tcp` or `protocol/udp`, first comma-separated port token, `-` split into start/end. `_parse_service_groups`: members from `members`.
- **`parse(device_id, artifacts, vsys="vsys1")`:** assembles a `ParsedDevicePayload(vendor="paloalto")`.

#### 4.2.4 `registry.py` — parser dispatch

`parse_artifacts(vendor_type, device_id, artifacts)` dispatches: `fortinet`→`fortigate.parse`, `paloalto`→`paloalto.parse`; otherwise raises `ValueError`.

### 4.3 Normalization layer (`backend/services/normalization/`)

Converts vendor-tagged parser models into the canonical normalized policy model and the object/service correlation model. **Deterministic and idempotent** — same input → same output (`__init__.py`, V4). The anomaly engine consumes ONLY this layer's output (ADR-010), never raw vendor data.

#### 4.3.1 `canonical.py` — pure canonical mapping rules (V4 §5–11)

Pure functions (no DB, no I/O) converting vendor-native values into canonical LuminaFPM values; deterministic and unit-testable.

- **Canonical action (V4 Table 6):** `_FGT_ACTION = {accept→allow, deny→deny, ipsec→ipsec}`; `_PAN_ACTION = {allow→allow, deny→deny, drop→drop, reset-client/reset-server/reset-both→reset}`. `canonical_action(vendor, raw)` lowercases, looks up by vendor, else `"unknown"`.
- **`canonical_logging(vendor, rule)` → `true`|`false`|`unknown`:** FortiGate: `all`/`utm`→`true`, `disable`→`false`, empty→`unknown`; Palo Alto: `yes`→`true`, `no`→`false`; else `unknown`.
- **`canonical_inspection(vendor, rule)` → `true`|`false`|`unknown`:** FortiGate inspection is `true` when `utm_status=="enable"` OR any of `_FGT_PROFILE_KEYS = (profile_group, av_profile, ips_sensor, webfilter_profile, application_list)` is set; otherwise `false` if the canonical action is `allow`, else `unknown`. Palo Alto: `true` when `has_profile`; else `false` for `allow`, else `unknown`. This drives the unprotected-allow detector.
- **`canonical_profile_strength(inspection, rule)`:** `true`→`strong`, `false`→`missing`, else `unknown`.
- **`canonical_schedule_scope(schedule)`:** none→`unknown`; `always`→`always`; else `limited`.
- **ANY object detection (V4 Table 13):** `_ANY_NAMES={"all","any"}`, `_ANY_VALUES={"0.0.0.0/0","::/0","0.0.0.0 0.0.0.0","0.0.0.0/0.0.0.0"}`. `is_any_object(name, value)` true if name in `_ANY_NAMES` or value in `_ANY_VALUES`. `canonical_object(name, otype, value)` → `("any","0.0.0.0/0")` for ANY, else `(otype or "unknown", value.strip())`.
- **Service canonicalization (the ANY-service handling):**
  - `PREDEFINED_SERVICES` (PAN-OS predefined names so rules referencing them resolve): `service-http→(tcp,80,80)`, `service-https→(tcp,443,443)`, `any→(any,None,None)`, `application-default→(application,None,None)`.
  - `service_key(protocol, port_start, port_end, app_id=None)`: `app:{app_id}` if an app-id; else `{proto}:any` when both ports are `None`, else `{proto}:{ps}-{pe}`.
  - `_ANY_SERVICE_NAMES={"all","any"}`. **`_BROAD_SERVICES`** (the map): `all→(any,None,None)`, `all_tcp→(tcp,1,65535)`, `all_udp→(udp,1,65535)`, `all_icmp→(icmp,None,None)`, `all_icmp6→(icmp6,None,None)`. Rationale (in-code): FortiGate's predefined `ALL` carries no port range, so without this it would key as `unknown:any` and the coverage/shadowing/redundancy logic would not treat it as the ANY sentinel (whereas PAN's `any` resolves via `PREDEFINED_SERVICES`); the `ALL_TCP`/`ALL_UDP`/`ALL_ICMP` predefined services are also expanded to full ranges.
  - `is_any_service(name)`: name in `_ANY_SERVICE_NAMES`.
  - **`canonical_service(name, protocol, port_start, port_end)`:** if the lowercased name is in `_BROAD_SERVICES`, returns the mapped `(proto, ps, pe)`; otherwise passes `(protocol, port_start, port_end)` through unchanged — so deterministic coverage and wide-port logic recognize broad services.
- **Keys & hashing:** `object_key(canonical_type, canonical_value)` → `"{type}:{value}"`. `content_hash(*parts)` → SHA-256 of `"|".join(parts)` (None→`""`), the deterministic normalized-content hash (V4 §13.1, Table 8). `derive_vendor_uuid(device_id, vdom_vsys, vendor_rule_id, rule_name, vendor_path="")` → stable hash for rules lacking a vendor UUID (V4 Table 8).
- **`infer_sensitivity(name, value)`:** keyword heuristic on the uppercased name → `admin` (ADMIN/MGMT), `database` (DB/DATABASE/SQL), `dmz` (DMZ/WEB/MAIL), `critical` (MALICIOUS/THREAT/BAD), `public` (ANY object), else `internal`.

#### 4.3.2 `model.py` — pure normalization-result models

DB-independent dataclasses mirroring Schema v4 but carrying correlation keys so the persist layer can resolve FKs deterministically:

- **`NormalizedObjectRec`:** `key` (`object_key`), `canonical_name`, `canonical_type`, `canonical_value`, `sensitivity`.
- **`ObjectMappingRec`:** `device_id`, `vendor`, `object_name` (vendor name), `normalized_key`, `match_method` (`exact_name_value`|`exact_value`|`name_similarity`|`derived`), `confidence: float`, `reason`.
- **`NormalizedServiceRec`:** `key` (`service_key`), `canonical_name`, `protocol`, `port_start`, `port_end`, `app_id`.
- **`ServiceMappingRec`:** `device_id`, `vendor`, `service_name`, `normalized_key`, `match_method` (`exact_port`|`exact_name_port`|`app_id`|`derived`), `confidence`, `reason`.
- **`NormalizedRule`:** full canonical rule — `device_id`, `vendor`, `rule_name`, `rule_order`, `vendor_rule_id`, `vendor_uuid` (real or derived), `vdom_vsys`, `enabled`, `src_zone`, `dst_zone`, `action` (canonical), `logging_enabled`/`security_inspection_enabled` (`true`/`false`/`unknown`), `security_profile_group`, `security_profile_strength`, `schedule`, `schedule_scope`, `nat_enabled`, `description`, `src_negate`, `dst_negate`, plus correlation key lists `src_object_keys`/`dst_object_keys`/`service_keys`, vendor name lists `src_object_names`/`dst_object_names`/`service_names`, and `normalized_content_hash`.
- **`NormalizationResult`:** aggregate — `normalized_objects: Dict[key,Rec]`, `object_mappings: List`, `normalized_services: Dict[key,Rec]`, `service_mappings: List`, `rules: List[NormalizedRule]`, `warnings: List[str]`.

#### 4.3.3 `engine.py` — deterministic correlation engine (V4 §13)

`normalize_payloads(payloads: List[ParsedDevicePayload]) -> NormalizationResult` — pure and idempotent. Building four in-memory indexes keyed by `(device_id, name)`, it runs object correlation, then service correlation, then rule normalization.

- **`_correlate_objects`:** groups address records by canonical key (`object_key(*canonical_object(...))`); address-groups key as `object_key("group", name)`. For each key, the **canonical name** is the most frequent vendor name (`max(set(names), key=names.count)`); the representative record's `(ctype, cvalue)` seed a `NormalizedObjectRec` with `infer_sensitivity`. Per vendor record it emits an `ObjectMappingRec`: matching the canonical name → `exact_name_value`, confidence **1.00**; otherwise `exact_value`, confidence **0.90** plus a naming-inconsistency warning (`"naming inconsistency: device … '<name>' == '<canonical>' (value …)"`). This is **correlation, not merge** — vendor objects stay separate (V4 §7).
- **`_correlate_services`:** groups service objects by `service_key(*canonical_service(...), app_id)`; service-groups recorded in an index. Canonical name = most frequent. Mapping: name match → `exact_name_port` (1.00), else `exact_port` (0.90), reason `"same protocol/port"`.
- **`_ensure_predefined_service(name, result)`:** resolves a `PREDEFINED_SERVICES` name (e.g. PAN `service-https`) into a normalized key, lazily inserting the `NormalizedServiceRec` if absent.
- **`_resolve_objects` / `_resolve_services`:** turn a rule's vendor name references into canonical keys against the indexes. Unresolved references fall back to: ANY object → `object_key("any","0.0.0.0/0")` (sensitivity `public`); ANY service → `service_key("any",None,None)`; otherwise an `unknown:<name>` key plus an `unresolved … reference` warning. Predefined-service names are resolved via `_ensure_predefined_service`.
- **Rule normalization loop:** per parsed rule it computes canonical `action`, `logging_enabled`, `inspection`, `strength`; `vendor_uuid` (real or `derive_vendor_uuid`); resolves src/dst object keys and service keys; computes `normalized_content_hash = content_hash(vendor, device_id, vdom_vsys, action, sorted src/dst/svc keys, logging, inspection, src_zones, dst_zones)`. Zones default to `"any"` when empty. Emits one `NormalizedRule` per parsed rule.

#### 4.3.4 `persist.py` — idempotent write into Schema v4

`persist_result(db, result, payloads) -> Dict[str,int]` writes the result into PostgreSQL idempotently (re-running with the same input must not duplicate rows). Returns per-table insert/seen counts. Strategy: resolve every canonical key to a concrete PK first, then write mappings; NEVER stores secrets.

**Idempotency natural keys (module docstring):**

| Table | Upsert natural key |
|---|---|
| `NormalizedObject` | `canonical_name` when type==`group`, else `(canonical_type, canonical_value)` |
| `NormalizedService` | `app_id` when present, else `(protocol, port_start, port_end)` |
| `NetworkObject` | `(device_id, name)` |
| `ServiceObject` | `(device_id, name)` |
| `ObjectNormalizationMapping` / `ServiceNormalizationMapping` | `(object_id|service_object_id, normalized_*_id)` |
| `PolicyRule` | `(device_id, vdom_vsys, vendor_uuid)` (the V4 re-sync key) |
| `RuleObjectMapping` | `(rule_id, object_id, mapping_type)` |
| `RuleServiceMapping` | `(rule_id, service_object_id|normalized_service_id, mapping_type)` |

**Phases:** (1) upsert canonical objects/services → `key→PK` maps; (2) upsert vendor `NetworkObject` rows per `object_mapping` and write `ObjectNormalizationMapping`; (3) same for `ServiceObject`/`ServiceNormalizationMapping`; (4) upsert `PolicyRule` (via `_upsert_policy_rule`, mapping `NormalizedRule` → columns `is_active`, `src_zone_interface`/`dst_zone_interface`, etc., clearing `deleted_at` on re-sync), then `RuleObjectMapping` (source/destination) and `RuleServiceMapping`. Objects referenced by a rule but with no vendor row (implicit ANY/unresolved) are **materialized** as a `NetworkObject` with a `derived` mapping (confidence 1.0, reason `"materialized from rule reference"`). Rules with no explicit service reference imply the ANY service — a `RuleServiceMapping` is written against `_ANY_SERVICE_KEY = service_key("any", None, None)`. Final `db.commit()`.

#### 4.3.5 `loader.py` — reconstruct `NormalizationResult` from Schema v4

`load_normalized_result(db, device_ids=None)` rebuilds the pure `NormalizationResult` dataclasses from persisted rows so the anomaly engine analyzes the normalized repository (ADR-010) without touching raw vendor data. When `device_ids is None`, all non-deleted rules across all devices load (required for cross-device detectors).

Critical contract (docstring): the canonical keys rebuilt here **must be byte-identical** to those emitted by `engine.py`, so set logic composes across a persist→load round-trip — `_norm_object_key` uses `object_key("group", canonical_name)` for groups else `object_key(canonical_type, canonical_value)`; `_norm_service_key` uses `service_key(protocol, port_start, port_end, app_id)`. The loader: resolves device→vendor name; loads `NormalizedObject`/`NormalizedService` rows into `*Rec` records and id→key maps; scopes vendor `NetworkObject`/`ServiceObject` rows and their `ObjectNormalizationMapping`/`ServiceNormalizationMapping` rows into `*MappingRec`s; loads `PolicyRule` rows (filtered `deleted_at IS NULL`, ordered by `device_id, rule_order`) with their `RuleObjectMapping` (source/destination) and `RuleServiceMapping` rows, falling back to `object_key("unknown", name)` for any vendor object lacking a normalization mapping.

### 4.4 Canonical / normalized data model & vendor↔canonical correlation

The canonical normalized rule model is frozen before anomaly development (V14 §17; `docs/NORMALIZATION_MODEL.md`). The interchange JSON shape lives in `NORMALIZATION_MODEL.md` §3; the authoritative persistent state is PostgreSQL (`policy_rule` + mapping tables), with JSON generated from / written into the relational tables.

**Vendor → canonical field mapping (V4 Table 7; `NORMALIZATION_MODEL.md` §4):** key correspondences as implemented: `vendor_rule_id` ← FortiGate `policyid` / PAN sequence-name; `vendor_uuid` ← `uuid` or derived hash; `vdom_vsys` ← FortiGate `vdom` / PAN `vsys`; `source_zone`/`destination_zone` ← FortiGate `srcintf`/`dstintf` (interfaces) vs PAN `from`/`to` (zones) — zone normalization is a logical graph only and must not imply routed traversal (V4 §10); `action` via the action enum above; `nat_enabled` is FortiGate-only in v1 (PAN-OS NAT is a separate policy type, future).

**Correlation model (not merge):** vendor objects/services remain separate rows for ownership/traceability; canonical `normalized_object` / `normalized_service` records sit above them, connected by `object_normalization_mapping` / `service_normalization_mapping`. Matching confidences (V4 Table 11/12, `NORMALIZATION_MODEL.md` §5–6) as implemented in `engine.py`: exact name+value → 1.00; same value, different name → 0.90 + naming-inconsistency candidate; same name/different value → **do not merge** (spec 0.30); group drift (spec 0.40); ANY → canonical ANY (1.00); unknown → kept, low confidence (spec 0.20). The codebase implements the 1.00/0.90 paths and the `derived` (materialized) path; the 0.30/0.40/0.20 confidence values and recursive group cycle-detection are specified (V4 §9) but **not** present as distinct branches in `engine.py` (groups are keyed but not expanded with cycle detection in the engine).

**Known partial/ambiguous items (stated plainly):**
- The PAN-OS connector ignores `ConnectorConfig.scheme` (always HTTPS); the HTTP escape hatch is FortiGate-only.
- The Palo Alto connector keeps status `SUCCESS` even when the optional `zone` leaf fails (no `PARTIAL_SUCCESS` downgrade), unlike FortiGate.
- Group expansion with cycle detection, `group_cycle` / `group-drift` warnings, App-ID-to-port preservation nuances, and the 0.30/0.40/0.20 confidence tiers from V4 §7–9 are specified but not implemented in the engine reviewed here.
- `vendor_path` is passed as the connector vendor string into `derive_vendor_uuid` (engine.py), not an explicit hierarchical path.

---

## 5. Backend — Anomaly, Risk, CTI, LLM & Benchmark Engines

This section documents the five deterministic-first analysis engines that run after normalization, each implemented as a self-contained package under `backend/services/`. The unifying architectural rule (ADR-010, Volume 6 Table 1) is that **detection is deterministic and reads the normalized model only**; AI may *explain* but is never the authoritative detector; and the platform is config-only / read-only against firewalls. Each engine separates a **pure scoring/logic module** (no DB, no I/O) from a **DB-backed runner** that persists rows for an `analysis_run_id` and is idempotent per run.

### 5.1 Anomaly Engine

Files: `backend/services/anomaly/engine.py`, `detectors.py`, `model.py`. Spec: Volume 6, `docs/ANOMALY_ENGINE_SPEC.md`.

#### 5.1.1 Engine entry point and determinism

`engine.py::analyze(result: NormalizationResult) -> List[Finding]` iterates the fixed-order tuple `detectors.ALL_DETECTORS` and concatenates each detector's findings. It reads the **normalized model only** (`services.normalization.model.NormalizationResult`) — no DB, no network, no LLM. Determinism is guaranteed by: (a) a fixed detector order, (b) a stable rule sort via `detectors._sorted_rules()` keyed on `(device_id, rule_order, vendor_uuid or "", rule_name or "")`, and (c) `itertools.combinations` over the sorted list for pairwise detectors so the "earlier" rule always has the lower `rule_order`. No randomness, wall-clock, or nondeterministic dict iteration is used.

The mock predecessor `backend/services/anomaly_engine.py` (random anomalies on random rules) is explicitly flagged as a spec violation in `docs/ANOMALY_ENGINE_SPEC.md` and is replaced by this package.

#### 5.1.2 The Finding model

`model.py::Finding` is a pure dataclass (DB-independent). The anomaly task maps each `Finding` onto a `RuleAnomaly` row via `device_id + rule_uuid -> PolicyRule.rule_id`. Fields:

| Field | Type | Notes |
|---|---|---|
| `anomaly_type` | str | A taxonomy value (see 5.1.4) |
| `device_id` | int | Owning device |
| `rule_uuid` | str | `NormalizedRule.vendor_uuid` |
| `severity` | str | `critical \| high \| medium \| low` |
| `confidence` | float | 0.0–1.0 |
| `description` | str | Technical reason |
| `recommendation` | str | Remediation text |
| `evidence` | `Dict[str,Any]` | Concrete facts (default `{}`) |
| `related_device_id` | `Optional[int]` | Pairwise/cross-device peer |
| `related_rule_uuid` | `Optional[str]` | Pairwise/cross-device peer |
| `detection_mode` | str | Defaults to `"config_only"` |

Every Finding is explainable: `evidence` carries the facts that produced it, built for most detectors via `_rule_evidence(r)` (`device_id, vendor, rule_name, rule_order, vendor_uuid, action`).

#### 5.1.3 Detection-mode concept

The contract (`docs/ANOMALY_ENGINE_SPEC.md` §3–4, Volume 6 line 130) defines four/five `detection_mode` values: **`config_only`** (from configuration only — fully implemented, ships first), **`conditional`** (needs logs/hit-counts/history), **`simulated`** / `benchmark_simulated` (simulated via lab metadata, must be labeled), and **`future_enhanced`** (needs enterprise telemetry). The CTI runner adds a fifth runtime mode, **`cti`** (see 5.3). In the implemented code, **all 14 detectors in `ALL_DETECTORS` emit `config_only`** (the `Finding.detection_mode` default); the only non-`config_only` finding produced is `threat_exposure` with `detection_mode="cti"`, written by the CTI runner. `conditional`, `simulated`, and `future_enhanced` modes are defined in the spec/schema but **not yet emitted by any detector** — this is a deliberate v1 scope limit, not an omission.

#### 5.1.4 Implemented anomaly_type values (the 46-type taxonomy)

Volume 6 / `docs/ANOMALY_ENGINE_SPEC.md` §5 define a **46-anomaly taxonomy**; v1 ships the "config-only core". The 14 detectors in `ALL_DETECTORS` emit the following **14 distinct `anomaly_type` values** (plus `threat_exposure` from CTI = 15 total persisted types):

| `anomaly_type` | Detector fn | Severity | Confidence | Scope | Taxonomy # |
|---|---|---|---|---|---|
| `unprotected_allow` | `detect_unprotected_allow` | high | 0.95 | single-rule | 5 |
| `missing_logging` | `detect_missing_logging` | medium | 0.9 | single-rule | 6 / 32 |
| `any_to_sensitive` | `detect_any_to_sensitive` | critical | 0.9 | single-rule | 7 |
| `overly_permissive` | `detect_overly_permissive` | critical | 0.95 | single-rule | 4 |
| `wide_port_range` | `detect_wide_port_range` | medium | 0.8 | single-rule | 8 |
| `missing_description` | `detect_missing_description` | low | 0.7 | single-rule | 18 |
| `disabled_rule_review` | `detect_disabled_rule_review` | low | 0.6 | single-rule | 20 |
| `object_sprawl` | `detect_object_sprawl` | low | 0.6 | single-rule | 34 |
| `duplicate_rules` | `detect_duplicate_rules` | medium | 0.95 | intra-device pair | 10 |
| `redundancy` | `detect_redundancy` | medium | 0.85 | intra-device pair | 2 |
| `shadowing` | `detect_shadowing` | high | 0.9 | intra-device pair | 1 |
| `conflict` | `detect_conflict` | high | 0.8 | intra-device pair | 3 / 12 |
| `cross_device_inconsistency` | `detect_cross_device_inconsistency` | **critical** | 0.85 | cross-device | 44 |
| `cross_device_security_posture_inconsistency` | `detect_cross_device_security_posture_inconsistency` | medium | 0.8 | cross-device | 44 |
| `threat_exposure` | (CTI runner, not a detector) | from CTI verdict | from CTI verdict | CTI | 36 |

The remaining taxonomy entries (e.g. ordering anomaly #9, temporary-rules #15, poor naming #19, zone mismatch #27, NAT risk #30, asymmetric rule #46, plus all `conditional`/`future_enhanced` rows) are **specified but not implemented** in v1.

#### 5.1.5 Constants and set logic

Defined at module top of `detectors.py`:
- `ANY_OBJECT_KEY = C.object_key("any", "0.0.0.0/0")`, `ANY_SERVICE_KEY = C.service_key("any", None, None)` — canonical "any" sentinels.
- `_BLOCKING_ACTIONS = {"deny", "drop", "reset"}`; `_ALLOW_ACTIONS = {"allow", "ipsec"}`.
- `_WIDE_PORT_THRESHOLD = 1024` (a single canonical service spanning `> 1024` ports is "wide").
- `_SPRAWL_THRESHOLD = 50` (distinct objects on one side of a rule).
- `_SENSITIVE = {"admin", "database", "critical"}` (object sensitivity classes).

Set operations use `NormalizedRule.src_object_keys / dst_object_keys / service_keys` (canonical correlation keys). Key helpers: `_has_any_src/dst/svc` (treats empty set OR presence of the ANY sentinel as "any"); `_covers(a,b,any_key)` (ANY or empty `a` covers everything, else `b.issubset(a)`); `_sets_overlap(a,b,any_key)` (true if either is ANY/empty or they intersect); `_same_access(a,b)` (equal src AND dst AND service sets).

#### 5.1.6 Detector logic summary

- **`unprotected_allow`**: enabled allow rule with `security_inspection_enabled == "false"`.
- **`missing_logging`**: enabled rule with `logging_enabled == "false"`.
- **`any_to_sensitive`**: enabled allow with ANY source and ≥1 destination key whose `NormalizedObjectRec.sensitivity ∈ _SENSITIVE`.
- **`overly_permissive`**: enabled allow with ANY src **and** ANY dst **and** ANY service (any/any/any).
- **`wide_port_range`**: enabled allow referencing a service where `port_end - port_start > 1024`.
- **`missing_description`**: rule with empty/whitespace `description` (no `enabled` guard — fires on disabled rules too).
- **`disabled_rule_review`**: `not r.enabled`.
- **`object_sprawl`**: any side (source/destination/service) with `> 50` distinct keys.
- **`duplicate_rules`** (intra-device): same `action` AND `_same_access`; attributed to the later rule with `related_*` = earlier.
- **`redundancy`** (intra-device): same action, **not** exact-duplicate, and earlier rule `_covers` all three sets of the later rule.
- **`shadowing`** (intra-device): an earlier **blocking** rule (`_is_blocking`) with `rule_order <= later` whose three sets cover the later rule → later never matches.
- **`conflict`** (intra-device): **different** actions with all three sets overlapping (`_sets_overlap`).

#### 5.1.7 Cross-device detectors (Volume 6 §8 Table 6, Volume 7 §8)

`_cross_device_pairs()` yields all sorted-rule combinations whose `device_id` differs. Two detectors:

- **`detect_cross_device_inconsistency`** → `cross_device_inconsistency`: equal canonical src/dst/service sets (`_same_access`) but **different action** across devices (e.g. FortiGate allows, Palo Alto denies the same canonical access). Severity = **`critical`** — inline comment cites *V6 Table 7; V7 §8* ("conflicting access decision across devices"). Confidence 0.85.
- **`detect_cross_device_security_posture_inconsistency`** → `cross_device_security_posture_inconsistency`: equal sets, **both allow**, but differing `logging_enabled` or `security_inspection_enabled`. Severity = **`medium`**, confidence 0.8.

Equivalence is established through normalized correlation keys, never raw vendor names (Volume 6 §8). This is the platform's core cross-vendor innovation surfaced as a detector.

### 5.2 Risk Scorer

Files: `backend/services/risk/scorer.py` (pure), `runner.py` (DB-backed). Spec: Volume 8.

> Naming note: the prompt refers to this as "V8". The code constant is `RISK_VERSION = "1.0.0"` (persisted as `calculation_version`); the comments reference *Volume 8* ("V8") sections/tables. There is no "V8" string literal in the code — `calculation_version == "1.0.0"`.

#### 5.2.1 Composite rule formula

```
risk_score = min(100, anomaly + exposure + asset_sensitivity + security_posture
                      + logging + cross_vendor + cti + lifecycle)
```

`score_rule(findings)` takes `[{'anomaly_type', 'severity'}, ...]` and builds a `factors` dict (only non-zero factors appear), summing and clamping to 100. The eight factors map to the formula terms above. Each factor is taken as a **MAX across findings** so it stays inside its Volume 8 Table 4 range regardless of how many findings hit it.

**Severity-point constants** (`_SEVERITY_POINTS`, V8 Table 4):

| severity | points |
|---|---|
| critical | 35 |
| high | 22 |
| medium | 12 |
| low | 4 |

The **anomaly factor** = `max(sev_points) + min(8, 2*(len(findings)-1))` — dominant severity plus a small "stacked findings" compound bonus capped at +8.

**Factor contribution map** (`_FACTOR_CONTRIB`, `anomaly_type -> (factor, points)`):

| anomaly_type | factor | points |
|---|---|---|
| `overly_permissive` | exposure | 20 |
| `wide_port_range` | exposure | 10 |
| `any_to_sensitive` | asset_sensitivity | 15 |
| `unprotected_allow` | security_posture | 20 |
| `missing_logging` | logging | 15 |
| `cross_device_inconsistency` | cross_vendor | 28 |
| `cross_device_security_posture_inconsistency` | cross_vendor | 18 |
| `disabled_rule_review` | lifecycle | 6 |

Additional rules: an `any_to_sensitive` finding also widens **exposure** to `max(exposure, 8)` (V8 Table 5 breadth). The **CTI factor** is added if any finding is `threat_exposure`, scaled by the verdict severity via `_CTI_POINTS = {"critical": 38, "high": 28, "medium": 18, "low": 10}` (V8 Table 4: CTI match 10–40; V9 §10). `lifecycle` is only populated by `disabled_rule_review` in v1 (no history/age factors yet).

#### 5.2.2 Risk tiers

`tier_of(score)` (V8 Table 2):

| Condition | tier |
|---|---|
| `>= 90` | critical |
| `>= 70` | high |
| `>= 40` | medium |
| `>= 1` | low |
| else (0) | informational |

`score_rule` returns `{risk_score, risk_tier, factor_breakdown, calculation_version}`.

#### 5.2.3 Device-risk blend

`score_device(rule_scores)` (V8 §8): takes the **top-5** rule scores (`sorted(...)[:5]`), then:

```
blend    = 0.6 * max_rule + 0.4 * avg(top5)
crit_count = count of rules with score >= 90
modifier  = min(10, crit_count * 4)
device_score = min(100, round(blend + modifier))
```

Weighted toward the worst rule so a single critical rule isn't diluted. Empty input returns score 0 / `informational`. `factor_breakdown` for a device = `{max_rule_risk, top_rules_avg (rounded 1dp), critical_rule_count, modifier}`.

#### 5.2.4 Risk runner

`runner.py::run_risk(db, run_id=None)`: defaults `run_id` to `max(RuleAnomaly.analysis_run_id)`. Loads findings per rule (`_findings_by_rule`, only rows with non-null `rule_id`), scores **every active `PolicyRule`** (`is_active is True`), and is **idempotent per run** — it deletes that run's prior `RiskAssessment` rows but keeps other runs as history. Persists `RiskAssessment(scope_type="rule"|"device", scope_id, risk_score, risk_tier, factor_breakdown, calculation_version=RISK_VERSION, analysis_run_id)`. Returns `{analysis_run_id, calculation_version, rules_scored, tier_counts, devices (sorted desc), top_rules[:10]}`. Read-only against firewalls.

### 5.3 CTI (Threat Intelligence)

Files: `backend/services/cti/extract.py`, `providers.py`, `runner.py`. Spec: Volume 9, Volume 12 §10 (security/data-minimization).

#### 5.3.1 Indicator extraction & data minimization

`extract.py::Indicator(type, value, is_public, object_id, device_id)` where `type ∈ {ip_address, cidr, fqdn}`. Three pure functions enforce **data minimization** (V9 §4, V12 §10):

- `is_public_ip(value)`: parses via `ipaddress.ip_network(strict=False)`; returns `net.is_global` — so **RFC1918 / loopback / link-local / reserved are False (private)**. The **ANY-sentinel guard**: `0.0.0.0/0` and `::/0` (`network_address == 0 and prefixlen == 0`) return `False` and are never indicators.
- `classify(value)`: returns `None` for empty or the ANY tokens (`"any"`, `"0.0.0.0/0"`, `"::/0"`, `"0.0.0.0/0.0.0.0"`). For IPs/CIDRs it returns `"cidr"` if `"/"` present and not `/32`, else `"ip_address"`. Otherwise a crude FQDN check (contains `.`, no spaces, not `*`-prefixed) → `"fqdn"`.
- `extract_indicators(objects, allow_internal=False)`: dedupes by value; **`if not is_public and not allow_internal: continue`** — internal/RFC1918 indicators are **never sent to external providers** unless `allow_internal` is explicitly set. FQDNs are treated as public. **/32 (and /128) canonicalization**: a single-host `ip_address` indicator with a `/` is stripped to its bare IP (`norm.split("/",1)[0]`).

#### 5.3.2 Provider abstraction

`providers.py::CtiProvider` (ABC) with `lookup_ip()` (abstract) and optional `lookup_domain()`. Verdict dataclass `CtiVerdict(provider, malicious, severity ∈ {critical,high,medium,low,info}, confidence, threat_type, summary, reference, raw_hash)`.

- **`LabOfflineProvider`** (`name="lab_offline"`): deterministic, **network-free**. `KNOWN_BAD` dict maps `"185.220.101.1" -> ("tor_exit", "high", 0.85, summary)` (a real long-standing Tor exit / abuse source), reference `"lab:static-known-bad"`, `raw_hash = sha256("lab_offline:<value>")`. Always present so CTI is demonstrable offline.
- **`AbuseIPDBProvider`** (`name="abuseipdb"`): real REST lookups to `https://api.abuseipdb.com/api/v2/check`, **activated only when keyed**. `__init__(api_key, malicious_threshold=25, timeout=15)`. Maps `abuseConfidenceScore` → `malicious = score >= 25`; severity = `critical (>=90) / high (>=50) / medium (>=25) / low`; `confidence = score/100`. Provider outages and non-200 responses log a warning and return `None` (never break enrichment).

`build_providers(provider_keys_raw)` always includes `LabOfflineProvider()` and appends `AbuseIPDBProvider` when `abuseipdb=` is parsed from the `=,`-delimited key string (`_parse_provider_keys`). OTX/VirusTotal plug in at the same point. Provider keys come from `settings.cti_provider_keys_raw`.

#### 5.3.3 CTI runner — correlation across all devices

`runner.py::run_cti(db, run_id=None)`: extracts indicators from **all** `NetworkObject` rows (`allow_internal = settings.cti_allow_internal_indicators`), enriches each via every active provider, and picks the **worst verdict** by `max(key=(malicious, _SEV_RANK[severity], confidence))` where `_SEV_RANK = {critical:4, high:3, medium:2, low:1, info:0}`. Persists `CtiIndicator` (upserted by `value + source_object_id`; re-runs drop stale `CtiObservation` rows) and `CtiObservation(provider, provider_reference, severity, confidence, threat_type, summary, raw_response_hash)`.

`_correlate_threat()` is the **cross-device correlation**: for a malicious indicator it finds `NetworkObject`s whose value matches `[ind.value, ind.value/32, ind.value/128]`, then every `RuleObjectMapping.rule_id` referencing them, **across ALL devices**, and raises a `RuleAnomaly` of `anomaly_type="threat_exposure"`, `detection_mode="cti"`, `status="open"` **only on rules whose `action == "allow"`** (a rule that permits traffic to/from the known-bad indicator). Severity/confidence come from the verdict; evidence carries `{indicator, provider, confidence, threat_type, reference}`.

Crucially, **CTI is NOT an anomaly by default**: it is a separately-labeled `threat_exposure` finding in `cti` mode (excluded from the config-only benchmark, see 5.5) that **feeds risk** — after correlation, `run_cti` calls `services.risk.runner.run_risk(db, run_id)` so the `cti` factor lands (V9 §10), wrapped in a try/except that only warns on failure. The runner is idempotent (deletes the run's prior `threat_exposure` rows first) and returns `{analysis_run_id, providers, indicators_enriched, malicious_indicators, threat_exposure_findings, internal_indicators_sent}`. Read-only against firewalls; internal indicators never leave the platform.

### 5.4 LLM (AI Reporting)

Files: `backend/services/llm/providers.py`, `prompts.py`, `reporter.py`. Spec: Volume 10.

#### 5.4.1 Provider abstraction

`providers.py::LLMProvider` (ABC) with `generate(system, user) -> LlmResult`. `LlmResult(output, provider, model, status ∈ {complete,partial,failed}, error)`.

- **`OfflineProvider`** (`name="offline"`, `model="deterministic-render/1.0"`): deterministic, **network-free fallback**. Renders the evidence prompt verbatim under a header explicitly labeled "*deterministic rendering — no LLM configured … not an AI analysis*", returning `status="complete"`. Guarantees the platform still reports when no key is configured (V10 §11).
- **`GeminiProvider`** (`name="gemini"`, default `model="gemini-2.5-flash"`, `timeout=60`): calls `https://generativelanguage.googleapis.com/v1beta/models/<model>:generateContent`. `generationConfig` = `{temperature: 0.2, maxOutputTokens: 4096, thinkingConfig: {thinkingBudget: 0}}`. **`thinkingBudget=0`** is load-bearing: 2.5 models otherwise spend the token budget on internal reasoning and can return no text part. **Retry hardening**: up to **3 attempts** with backoff `time.sleep(2*(attempt+1))` on network exceptions and on transient HTTP **429/503**; other non-200 → `failed`; malformed/empty response → `failed` (empty case reports `finishReason`).

`build_provider(provider_name, api_key, model)`: returns `GeminiProvider` only when name is `gemini` **and** a key is present; otherwise falls back to `OfflineProvider()` (V10 §11). Config comes from `settings.llm_provider`, `settings.llm_api_key`, `settings.llm_model`.

#### 5.4.2 Guardrail system prompt (LLM explains, never detects)

`prompts.py::PROMPT_VERSION = "soc-report/1.0"`. `SYSTEM_PROMPT` enforces (verbatim intent): use **ONLY** evidence supplied in the user message; **do NOT invent CVEs**, exploit claims, threat-intel verdicts, IP reputations, or remediations unsupported by evidence; **SEPARATE evidence from interpretation**; attribute every threat-intel claim to its provider; "**The deterministic engine — not you — decides what is an anomaly; your job is to explain and prioritize.**" This codifies the "LLM EXPLAINS never DETECTS" mandate (Volume 10).

#### 5.4.3 Evidence-grounded prompts

`render_rule_prompt(ctx)` embeds rule scope, the risk score/tier/factor_breakdown with `risk_id`, deterministic findings each tagged `[anomaly_id=…] type (severity, mode): description` (`_fmt_findings`), and CTI evidence each tagged `[observation_id=…] … provider=…` (`_fmt_cti`) — clearly separated as "CTI PROVIDER EVIDENCE (separate from the engine)". The TASK asks for Summary / Why-risky (citing the IDs) / remediation grounded only in evidence. `render_executive_prompt(ctx)` produces a run-level summary citing `risk_id`s of the top rules.

#### 5.4.4 Reporter (graceful failure)

`reporter.py::generate_report(db, scope_type, scope_id=None)` supports `scope_type ∈ {"rule","executive"}`. `_rule_context` assembles findings, the rule-scope `RiskAssessment`, and CTI observations for objects the rule references, building an **`evidence_refs`** dict = `{anomaly_ids, risk_id, cti_observation_ids}` (executive: `{risk_ids, analysis_run_id}`). It calls the provider, then **always persists** an `LlmReport(provider, model, prompt_version=PROMPT_VERSION, evidence_refs, output, confidence_note, status)`. **Graceful failure**: even when the provider returns `status="failed"`, the report is stored (deterministic data is unchanged and remains available, V10 §11). `confidence_note` distinguishes AI ("grounded in the referenced evidence IDs; not itself evidence") from offline ("Deterministic rendering of evidence"). Returns report metadata incl. `prompt_version`, `evidence_refs`, `output`, `error`.

### 5.5 Benchmark Framework (the acceptance gate)

Files: `backend/services/benchmark/scorer.py` (pure), `ground_truth.py`, `runner.py`. Spec: Volume 7, `docs/BENCHMARK_FRAMEWORK.md`.

#### 5.5.1 Purpose

The benchmark **proves the engine works against ground truth, not visual inspection** (V7 §2) and is the **acceptance gate** (V7 Table 7 — see 5.5.5). It scores deterministic engine output against an authoritative expected-anomaly matrix.

#### 5.5.2 Scorer (TP/FP/FN, precision/recall/F1, severity-match)

`scorer.py` dataclasses: `ExpectedCase(anomaly_type, rules[1 or 2], expected_severity, case_type ∈ {atomic,compound}, kind ∈ {intra,cross_device}, reason)`; `CaseResult(detected, matched_rule, detected_severity, detected_anomaly_id, severity_match, match_quality ∈ {exact,partial,none})`; `BenchmarkScore(results, false_positives, tp, fp, fn, precision, recall, f1, severity_match_rate)`.

`score(expected, actual)` where `actual` = `rule_name -> {anomaly_type -> {severity, anomaly_id}}`:
- Match granularity is **(rule, anomaly_type) presence** (not count). A **cross-device** case matches if the anomaly appears on **either** paired rule (engine attributes the finding to one side).
- `severity_match` = `expected_severity is None OR detected severity == expected`; `match_quality = "exact"` if severity matches else `"partial"`.
- `tp` = detected cases; `fn` = undetected cases; `false_positives` = `actual_index - consumed` (reported `(rule,type)` not expected); `fp = len(false_positives)`.
- `precision = TP/(TP+FP)` (1.0 if denom 0); `recall = TP/(TP+FN)` (1.0 if denom 0); `f1 = 2PR/(P+R)` (0.0 if denom 0); `severity_match_rate = sev_ok/TP` (1.0 if TP 0). All rounded to 4 dp.

#### 5.5.3 Ground-truth matrix

`ground_truth.py` is the authoritative expected matrix (mirrors `lab/benchmark_dataset.py`; kept in-backend because `lab/` is not mounted into the API container). Severity is per **anomaly TYPE** (V6 Table 7), independent of the engine — so `severity_match_rate` is a real check on the engine's severity assignment. `EXPECTED_SEVERITY` (13 types): `any_to_sensitive/overly_permissive/cross_device_inconsistency = critical`; `unprotected_allow/shadowing/conflict = high`; `redundancy/duplicate_rules/missing_logging/wide_port_range/cross_device_security_posture_inconsistency = medium`; `missing_description/disabled_rule_review = low`.

`INTRA` maps each rule_name (per vendor `fortinet`/`paloalto`) to its expected config_only anomalies — e.g. `FGT_ANY_ANY -> [overly_permissive, unprotected_allow, missing_logging, missing_description, conflict]`, `FGT_ANY_DB -> [any_to_sensitive, unprotected_allow, missing_logging, missing_description]`. Some entries are documented but "not deployed on the eval FGT (10-policy cap)" (`FGT_ADMIN_DB_NOLOG`, `FGT_DISABLED_RISKY`). `CROSS_DEVICE` lists 3 pairs: one `cross_device_inconsistency` (`FGT_DB_ACCESS_XDEV` vs `PA_DB_ACCESS_XDEV` — FortiGate allows / Palo Alto denies same canonical MySQL access) and two `cross_device_security_posture_inconsistency` pairs (equivalent LAN→WEB HTTPS allow; FortiGate inspected vs Palo Alto unprotected).

#### 5.5.4 Runner & config_only filtering

`runner.py::run_benchmark(db, run_id=None)`: `_deployed_rules` loads active `PolicyRule`s by name; `_build_expected` resolves `INTRA`+`CROSS_DEVICE` **only against deployed rules** (intra cases skip rules not in `policy_rule`; cross-device cases require **both** paired rules deployed). `_actual_findings` joins `RuleAnomaly`→`PolicyRule` filtered by `analysis_run_id` **and `detection_mode == "config_only"`** — this is the key filter: the config_only benchmark scores **only config_only findings**; `cti`/`conditional`/`simulated` findings (notably `threat_exposure`) are excluded and evaluated separately. `case_type` is `compound` when a rule has `>1` expected anomalies else `atomic`.

`_persist` rebuilds `BenchmarkCase` (with `detection_mode="config_only"`, expected_severity, device/rule a+b ids) and `BenchmarkResult` (detected, detected_anomaly_id, match_quality, `false_negative = not detected`) fresh each run (deletes all prior rows). Returns `{analysis_run_id, metrics: {tp,fp,fn,precision,recall,f1,severity_match_rate,expected_cases}, by_type, missed, false_positives}`.

#### 5.5.5 Acceptance criteria

Per `docs/BENCHMARK_FRAMEWORK.md` §8 / Volume 7 Table 7, acceptance is **qualitative, not a numeric F1 threshold** in code: all core config_only anomalies detected in atomic cases; **both** cross-device policy-conflict **and** security-posture-difference detected; compound major findings appear; simulated cases clearly labeled; every finding shows the affected rule (+ related rule) + reason. False negatives must be fixed **before** UI polish (V14 §10). The runner exposes the raw metrics; no hard-coded pass/fail gate value exists in `scorer.py`/`runner.py`.

---

Notes on gaps / partial implementation (grounded, not invented):
- `RISK_VERSION` literal is `"1.0.0"`, not "V8"; "V8" appears only in comments referencing Volume 8.
- Of the four spec `detection_mode` values, only `config_only` is emitted by detectors; `cti` is emitted by the CTI runner; `conditional`/`simulated`/`future_enhanced` are defined but unused in v1.
- The implemented taxonomy is **14 detector types + `threat_exposure` (15 persisted types)** out of the 46-type spec taxonomy; the rest are documented-only.
- The risk `lifecycle` factor is fed only by `disabled_rule_review`; no history/age/drift factors are implemented yet.

---

## 6. Data Model, Database Schema & REST API

This section documents the persistence layer and HTTP surface of the LuminaFPM backend. The ORM is **SQLAlchemy** (`declarative_base`) with a **PostgreSQL** target; JSON columns use the PostgreSQL `JSONB` dialect type. Schema management is via **Alembic** (`backend/alembic/versions/`). The API is **FastAPI** with one router per resource, all mounted under the base prefix `/api/v1` (the threat-intel router uses `/api/v1/threat-intel`). Every endpoint is **read-only with respect to firewalls** — no route pushes or commits configuration to a device; the few `POST`s that trigger work either enqueue Celery tasks or run pure-DB analysis.

Two model modules coexist under one shared `Base`:
- **Core Schema v4/v8** — `backend/models/models.py` (28 tables).
- **Threat-intel (LTI) module** — `backend/services/lumina_threat_intel/db_models.py` (3 tables: reports, findings, IOCs) plus a 4th raw-scrape table; both modules register on the same `models.models.Base`. The internal `docs/EXECUTION_LOG.md` records the combined live schema as **31 tables** (28 core + 3 LTI findings tables; the raw-scrape table brings the literal `Base` count slightly higher — see the Database Schema subsection note).

### 6.1 Database Schema

#### 6.1.1 ORM/engine plumbing

Defined in `backend/models/models.py`:
- `Base = declarative_base()` — shared metadata for both model modules.
- `utcnow()` — timezone-aware UTC `datetime` helper (replaces deprecated `datetime.utcnow`); used as the default/`onupdate` for all v4 `DateTime(timezone=True)` columns. NOTE: the older v3 tables (`AdminDeviceAssignment.assigned_at`, `APIToken.created_at`, `AuditLog.timestamp`, `SavedSearch.created_at`) still use the naive `datetime.utcnow`.
- `get_engine()` — lazily builds a singleton engine from the `DATABASE_URL` env var, `echo=False`.
- `get_db()` — returns a `sessionmaker(autocommit=False, autoflush=False)`; the FastAPI dependency `get_db_session()` in `backend/api/deps.py` yields a session and closes it in `finally`.

`backend/models/crud.py` exposes **generic, model-agnostic CRUD** used by nearly every router: `create_database(engine)`/`drop_database(engine)` (metadata `create_all`/`drop_all`); `get_all(db, model_class, skip, limit)`; `get_by_id(db, model_class, pk_name, pk_value)`; `insert_data`; `update_data`; `delete_data`; `delete_data_composite(db, model_class, key_mapping)` (for composite-PK association tables). Thin named wrappers (`create_vendor`, `delete_external_node`, `create_threat_feed`, etc.) delegate to the generics.

#### 6.1.2 Core operational / inventory tables

| Table (`__tablename__`) | Model class | PK | Purpose / key columns | Important FKs / relationships |
|---|---|---|---|---|
| `vendor` | `Vendor` | `vendor_id` | Firewall vendor catalog. `name`, `api_type` (e.g. FortiOS-REST / PAN-OS-XML), `support_contact`. | `devices` → `FirewallDevice` (cascade delete). |
| `administrator` | `Administrator` | `admin_id` | RBAC user store. `first_name`, `last_name`. | `assignments` → `AdminDeviceAssignment`. |
| `firewall_device` | `FirewallDevice` | `device_id` | Managed firewall. `vendor_id` FK, `vendor_type` (`'fortinet'`|`'paloalto'`, nullable; resolved from vendor when absent — V3 Table 8), `hostname`, `firmware_version`, `management_ip` VARCHAR(45), `location`, `uptime`, `throughput`, `last_poll_time`, `status` (default `"unknown"`). | `vendor` (back_populates), `rules` → `PolicyRule`, `assignments`. |
| `admin_device_assignment` | `AdminDeviceAssignment` | composite (`admin_id`,`device_id`) | M:N admin↔device with `role`, `assigned_at`. | FKs to `administrator`, `firewall_device`. |
| `network_object` | `NetworkObject` | `object_id` | Vendor-owned address/object (v4 ownership-extended). `device_id` FK (nullable), `vendor_id` FK (nullable), `vendor_object_id`, `vendor_uuid`, `name`, `type` (`ip_address|cidr|fqdn|group|any|application|url_category`), `value` (canonical), `raw_value`, timestamps. Indexes: `idx_netobj_device_type_value (device_id,type,value)`, `idx_netobj_type`. | `rule_mappings` → `RuleObjectMapping`; `normalization_mappings` → `ObjectNormalizationMapping`. |
| `policy_rule` | `PolicyRule` | `rule_id` | Core normalized rule. Identity: `device_id` FK, `vendor_rule_id`, `vendor_uuid`, `vendor_type` (NOT NULL), `vdom_vsys`. Evaluation: `rule_order`, `action`, `is_active`. Direction: `src_zone_interface`, `dst_zone_interface`. Posture/canonical (tri-state strings `true|false|unknown`): `logging_enabled`, `logging_mode` (`all|security-event|profile|disabled|unknown`), `security_inspection_enabled`, `security_profile_strength` (`strong|weak|missing|unknown`), `schedule_scope` (`always|limited|unknown`). Plus `nat_enabled`, `log_setting`, `security_profile_group`, `schedule_name`, `src_negate`/`dst_negate` (NOT NULL, default false), `rule_type`, `tags`, `description`. Change detection / soft delete: `normalized_content_hash` (CHAR-64), `deleted_at` (nullable), `created_at`, `updated_at`. | `device`; `object_mappings` → `RuleObjectMapping`; `anomalies` → `RuleAnomaly` (via `RuleAnomaly.rule_id`, disambiguated FK). |
| `rule_object_mapping` | `RuleObjectMapping` | composite (`rule_id`,`object_id`,`mapping_type`) | Rule↔address/object selector link. `direction` (default `"both"`). | FKs to `policy_rule`, `network_object`. |

**Re-sync identity key (`policy_rule`):** the canonical dedupe/re-sync identity is `UNIQUE (device_id, vdom_vsys, vendor_uuid)` enforced by partial index `idx_rule_vendor_uuid` (`unique=True, postgresql_where=vendor_uuid IS NOT NULL`). Additional indexes: `idx_rule_device_order (device_id, vdom_vsys, rule_order)` for ordered analysis and `idx_rule_vendor_type`. Per `docs/DATABASE_SCHEMA_V4.md` §2.3, when a vendor exposes no UUID the parser derives a stable hash from `device_id + vdom_vsys + vendor_rule_id + rule_name + vendor_path`.

#### 6.1.3 Normalization / correlation (canonical ↔ vendor) tables

The platform's core innovation — cross-vendor normalization — is realized by a **vendor-object → canonical-object** correlation pair and a parallel **service** pair:

| Table | Model class | PK | Purpose / key columns | FKs |
|---|---|---|---|---|
| `normalized_object` | `NormalizedObject` | `normalized_object_id` | Canonical object above vendor `network_object` rows. `canonical_name`, `canonical_type` (`ip_address|cidr|fqdn|group|any|unknown`), `canonical_value`, `sensitivity` (`public|internal|dmz|database|admin|critical|unknown`), `description`. | `mappings` → `ObjectNormalizationMapping`. |
| `object_normalization_mapping` | `ObjectNormalizationMapping` | `mapping_id` | **Canonical↔vendor object correlation.** `match_method` (`exact_name_value|exact_value|name_similarity|manual|derived`), `confidence` (0.00–1.00). Index `idx_objnorm_normalized`; `UniqueConstraint(object_id, normalized_object_id)`. | `object_id`→`network_object`, `normalized_object_id`→`normalized_object`. |
| `service_object` | `ServiceObject` | `service_object_id` | Vendor-owned service (protocol/port/App-ID). `device_id`/`vendor_id` FK, `vendor_service_id`, `name`, `protocol` (`tcp|udp|icmp|application|any|unknown`), `port_start`/`port_end`, `app_id` (PAN-OS App-ID), `raw_value`. Index `idx_serviceobj_device (device_id,name)`. No ORM relationships declared. | FKs to device/vendor. |
| `normalized_service` | `NormalizedService` | `normalized_service_id` | Canonical service. `canonical_name` (e.g. HTTPS, MYSQL), `protocol`, `port_start`/`port_end`, `app_id`. | `mappings` → `ServiceNormalizationMapping`. |
| `service_normalization_mapping` | `ServiceNormalizationMapping` | `mapping_id` | **Canonical↔vendor service correlation.** `match_method` (`exact_port|exact_name_port|app_id|manual|derived`), `confidence`. Index `idx_svcnorm_normalized`; `UniqueConstraint(service_object_id, normalized_service_id)`. | `service_object_id`→`service_object`, `normalized_service_id`→`normalized_service`. |
| `rule_service_mapping` | `RuleServiceMapping` | `mapping_id` | Rule↔service link (service axis; mirrors `rule_object_mapping`). Either `service_object_id` (vendor) **or** `normalized_service_id` (canonical) may be set. `mapping_type` (default `"service"`), `direction` (default `"service"`). Index `idx_rulesvcmap_rule`. **Added by migration 0002.** No ORM relationships (FK-only). | FKs to `policy_rule`, `service_object`, `normalized_service`. |
| `normalization_warning` | `NormalizationWarning` | `warning_id` | Unsupported/ambiguous/low-confidence transformation record (V4 §14.1). `warning_type` (`unsupported_field|ambiguous_mapping|group_cycle|unknown_service|missing_uuid`), `severity` (`low|medium|high`), `message`, `raw_reference`. | nullable FKs to device/rule/object. |
| `rule_snapshot` | `RuleSnapshot` | `snapshot_id` | Historical normalized rule version for drift/audit. `normalized_content_hash`, `snapshot` (`JSONB`, full normalized rule), `job_id` FK. Index `idx_rulesnap_rule (rule_id, created_at)`. | FKs to `policy_rule`, device, `acquisition_job`. |

#### 6.1.4 Anomaly tables

| Table | Model class | PK | Purpose / key columns | FKs |
|---|---|---|---|---|
| `rule_anomaly` | `RuleAnomaly` | `anomaly_id` | Durable anomaly finding (full V6 output contract). `rule_id` FK; **`related_rule_id` is a real FK to `policy_rule.rule_id`** (nullable; was previously a String — see Pydantic note); `anomaly_type` (taxonomy), `severity_level` (`critical|high|medium|low`), `confidence` Float (0.00–1.00), `description` (technical reason), `evidence` `JSONB`, `recommendation`, `detection_mode` (`config_only|conditional|simulated|future_enhanced`), `analysis_run_id` FK, `status` (`open|resolved|suppressed|accepted_risk|false_positive`, default `open`), `suppression_reason`, `suppressed_by` FK→`administrator`, `suppression_expires_at`, `detected_at`. Indexes `idx_anomaly_rule`, `idx_anomaly_run`. | Two FKs to `policy_rule` (`rule_id`, `related_rule_id`) — disambiguated via explicit `foreign_keys`; `execution_run` → `AnomalyExecutionLog`. |
| `anomaly_execution_log` | `AnomalyExecutionLog` | `run_id` | One anomaly-engine run. `scope_type` (`device|all|benchmark`), `scope_id`, `started_at`/`completed_at`, `status` (`running|completed|failed|partial`, default `running`), `findings_count`, `error_log` `JSONB`, `engine_version`. | `findings` → `RuleAnomaly`. |

#### 6.1.5 Risk, CTI, LLM-report, Benchmark tables

| Table | Model class | PK | Purpose / key columns | FKs |
|---|---|---|---|---|
| `risk_assessment` | `RiskAssessment` | `risk_id` | Deterministic 0–100 risk score (V8 §11). `scope_type` (`rule|device|object`), `scope_id`, `risk_score` (0–100), `risk_tier` (`critical|high|medium|low|informational`), `factor_breakdown` `JSONB`, `calculated_at`, `calculation_version`, `analysis_run_id`. Index `idx_risk_scope (scope_type, scope_id, calculated_at)`. | `analysis_run_id`→`anomaly_execution_log` (nullable). |
| `cti_indicator` | `CtiIndicator` | `indicator_id` | Extracted threat indicator (V9 §7). `type` (`ip_address|cidr|fqdn|url|cve|firmware_version|vendor_version_keyword`), `value`, `source_object_id`/`source_device_id` provenance, `is_public`, `first_seen`/`last_seen`. Index `idx_cti_type_value (type,value)` (dedupe). | `observations` → `CtiObservation`; provenance FKs. |
| `cti_observation` | `CtiObservation` | `observation_id` | Provider result for an indicator. `provider` (`abuseipdb|otx|virustotal|nvd|vendor_advisory|...`), `provider_reference`, `severity`, `confidence` Float, `threat_type` (`malware|c2|scanner|exploit|botnet|vulnerability|...`), `summary`, `raw_response_hash`, `observed_at`. | `indicator_id`→`cti_indicator`. |
| `llm_report` | `LlmReport` | `report_id` | Evidence-grounded AI report (V10 §9). `scope_type` (`rule|device|scan|executive`), `scope_id`, `provider` (`gemini|openai|ollama`), `model`, `prompt_version`, `evidence_refs` `JSONB` (DB evidence IDs), `output`, `confidence_note`, `status` (`complete|partial|failed`, default `complete`). | none. |
| `benchmark_case` | `BenchmarkCase` | `case_id` | Ground-truth expected anomaly (V7). `case_type` (`atomic|compound`), `anomaly_type`, `device_a_id`/`rule_a_id`, `device_b_id`/`rule_b_id` (pairwise/cross-device), `expected_severity`, `expected_reason`, `detection_mode`, `required_fields` `JSONB`. | FKs to device/rule (A/B); `results` → `BenchmarkResult`. |
| `benchmark_result` | `BenchmarkResult` | `result_id` | Detected-vs-expected outcome (V7). `case_id` FK, `analysis_run_id` FK, `detected` bool, `detected_anomaly_id` FK→`rule_anomaly`, `match_quality` (`exact|partial|none`), `false_positive`, `false_negative`, `notes`. | FKs to case/run/anomaly. |

#### 6.1.6 Acquisition & credential tables

| Table | Model class | PK | Purpose / key columns | FKs |
|---|---|---|---|---|
| `acquisition_job` | `AcquisitionJob` | `job_id` | Async firewall extraction job (V3 §7). `device_id` FK, `vendor_type`, `requested_by` (admin id / `'scheduler'` / `'api'`), `status` (default `queued`; full lifecycle: `queued|running|success|partial_success|failed|timeout|authentication_failed|authorization_failed|connection_failed|rate_limited|parsing_queued|parsing_failed`), `started_at`/`completed_at`, `duration_ms`, `connector_version`, `error_code`, `error_message` (safe summary — NO secrets). Index `idx_acqjob_device_status`. | `artifacts` → `RawArtifact`. |
| `raw_artifact` | `RawArtifact` | `artifact_id` | Stored raw API response for replay/audit (V3 §8). `type` (`policies|address_objects|...|device_metadata|manifest`), `path`, `sha256`. | `job_id`→`acquisition_job`, `device_id`. |
| `device_credential` | `DeviceCredential` | `credential_id` | Encrypted per-device firewall credential (V3 §6.2, V12 §6). `auth_type` (`fortigate_api_token|panos_api_key|panos_userpass`), `secret_encrypted` (Fernet/`ENCRYPTION_KEY` ciphertext — NEVER returned to frontend, NEVER logged), `created_at`/`rotated_at`/`last_used_at`. Index `idx_devcred_device`. | `device_id`→`firewall_device`. |

#### 6.1.7 Legacy / auxiliary tables (kept from v3)

| Table | Model class | PK | Purpose / notes |
|---|---|---|---|
| `external_node` | `ExternalNode` | `node_id` | `name`, `ip_address`, `node_type`, `description`. Legacy (dark-web direction); candidate for repurpose/removal per `DATABASE_SCHEMA_V4.md` §1. |
| `threat_feed` | `ThreatFeed` | `feed_id` | `name`, `url`, `status` (default `active`), `last_sync`. Legacy. |
| `api_token` | `APIToken` | `token_id` | `admin_id` FK, `name`, `token_hash`, `created_at`/`expires_at`/`last_used`. Per v4 design notes this is the platform-API token store; firewall secrets live in `device_credential` instead. |
| `audit_log` | `AuditLog` | `log_id` | `admin_id` FK (nullable), `action`, `target_type`, `target_id`, `details`, `timestamp` (V12 audit logging). |
| `saved_search` | `SavedSearch` | `search_id` | `admin_id` FK, `name`, `query_string`, `created_at` (Policy Explorer saved filters). |

#### 6.1.8 Threat-intel (LTI) module tables

Defined in `backend/services/lumina_threat_intel/db_models.py`; single-tenant (no `tenant_id`); registered on the shared `Base`. These use **SQLAlchemy `Enum`** columns (named PostgreSQL enum types) and naive `datetime.utcnow` defaults.

| Table | Model class | PK | Purpose / key columns | FKs |
|---|---|---|---|---|
| `threat_intel_reports` | `ThreatIntelReport` | `id` | One row per scan invocation. `trigger_type` enum `ti_trigger_type` (`scheduled|manual|on_import`), `triggered_by_admin_id` FK, `status` enum `ti_scan_status` (`running|completed|failed|partial`), `scan_started_at`/`scan_completed_at`/`scan_duration_seconds`, `input_keywords` `JSONB`, `queries_generated_count`, `onion_pages_scraped_count`, `scanned_device_ids` `JSONB` (null = all), `narrative_summary`, `clean` bool, `coverage_note`, `stats` `JSONB`, `llm_model_name`/`llm_input_tokens`/`llm_output_tokens`, `error_log` `JSONB`, `archived` (indexed). Indexes on started/archived. | `findings`, `raw_scrapes`. |
| `threat_intel_findings` | `ThreatIntelFinding` | `id` | Individual finding. `report_id` FK (CASCADE), `category` enum `ti_category` (`exploit|credential|c2|ransomware|iab`), `severity` enum `ti_severity`, `criticality` enum `ti_criticality` (`info|low|medium|high|critical`), `relevance_score`/`relevance_band` (`none|low|medium|high`)/`relevance_reason`, `confidence` (default 50), `title`, `description`, `recommended_actions`/`tags` `JSONB`, source-provenance columns, correlation: `matched_rule_ids`/`matched_device_ids` `JSONB`, `correlation_match_reason`, diff tracking `is_new_since_last_scan`/`first_seen_in_scan_id`, `finding_hash` (SHA-256, indexed), `parse_error`. | `report_id` + `first_seen_in_scan_id` → `threat_intel_reports`; `iocs`. |
| `threat_intel_iocs` | `ThreatIntelIOC` | `id` | IOC extracted from a finding. `finding_id` FK (CASCADE), `ioc_type` enum `ti_ioc_type` (`ipv4|ipv6|domain|url|sha256|md5|sha1|cve|email|wallet|username|asn`), `ioc_value` (VARCHAR 2048). Index `idx_ti_ioc_type_value`. | `finding_id`→`threat_intel_findings`. |
| `threat_intel_raw_scrapes` | `ThreatIntelRawScrape` | `id` | Temporary raw scraped content, 7-day retention. `report_id` FK (CASCADE), `onion_url`, `search_engine`, `scraped_at`, `http_status`, `content_length`, `raw_text`. | `report_id`→`threat_intel_reports`. |

**Schema-size note:** `docs/EXECUTION_LOG.md` states the live schema is **31 tables, 13 routers mounted**. Counting the literal model classes gives 28 in `models.py` + 4 LTI classes = 32 `Base`-registered tables; the "31" figure (and the V8 "~31 tables" framing) reflects the three primary LTI findings tables alongside the 28 core tables. Wherever an exact table count matters, prefer the enumerated lists above over the round figure.

#### 6.1.9 Alembic migrations

Located in `backend/alembic/versions/`. The chain is `0001 → 0002 → 0003`. Note that `alembic/env.py` also imports the LTI `db_models`, so the baseline metadata includes the threat-intel tables.

| Revision | File | down_revision | What it does |
|---|---|---|---|
| `0001_schema_v4_baseline` | `0001_schema_v4_baseline.py` | `None` | Baseline that converts from `Base.metadata.create_all` to managed migrations. `upgrade()` calls `Base.metadata.create_all(bind)` — creating **every** registered table (all core v4 + the wired LTI tables). On a pre-existing create_all DB, operators are told to `alembic stamp 0001_schema_v4_baseline` rather than upgrade. `downgrade()` = `drop_all`. |
| `0002_rule_service_mapping` | `0002_rule_service_mapping.py` | `0001_schema_v4_baseline` | Adds the `rule_service_mapping` table (rule↔service correlation, mirroring `rule_object_mapping`; either `service_object_id` or `normalized_service_id`). FKs to `policy_rule`, `service_object`, `normalized_service`; index `idx_rulesvcmap_rule`. **Idempotent** — returns early if the table already exists (since 0001's create_all already builds it). |
| `0003_device_vendor_type` | `0003_device_vendor_type.py` | `0002_rule_service_mapping` | Adds `firewall_device.vendor_type` VARCHAR(20) nullable (semantic connector dispatch `'fortinet'|'paloalto'`, V3 Table 8). **Idempotent** — returns early via `_has_column` if already present. |

### 6.2 Pydantic Schemas

Request/response models live in `backend/schemas/pydantic_schemas.py`. The convention per resource is a `*Base` (shared fields), `*Create` (POST body), `*Update` (all-`Optional`, used with `model_dump(exclude_unset=True)` for PATCH), and `*Response` (adds the surrogate PK + server timestamps, with `model_config = ConfigDict(from_attributes=True)` for ORM serialization). Pydantic v2 is in use (`ConfigDict`, `model_dump`).

Main models: `VendorBase/Create/Update/Response`; `AdministratorBase/Create/Update/Response`; `DeviceBase/Create/Update/Response` (`DeviceBase.vendor_type` Optional — derived from vendor if omitted); `AdminDeviceAssignmentBase/Create/Response`; `NetworkObjectBase/Create/Update/Response`; `PolicyRuleBase/Create/Update/Response` (`PolicyRuleResponse` adds `created_at`/`updated_at`); `RuleObjectMappingBase/Create/Response`; `RuleAnomalyBase/Create/Update/Response`; `ExternalNodeBase/Create/Update/Response`; `ThreatFeedBase/Create/Update/Response`; `APITokenBase/Create/Update/Response` (write model has only `admin_id`+`name`; the response never includes `token_hash`); `AuditLogBase/Create/Response`; `SavedSearchBase/Create/Update/Response`.

**Notable typing fix:** in `RuleAnomalyBase`/`RuleAnomalyUpdate`, **`related_rule_id` is `Optional[int]`** (FK to `policy_rule.rule_id`) — matching the model change from a `String` to a real integer FK (cross-device/shadowing pair). This is the one explicitly documented correctness fix in the schema layer.

**Schemas NOT in `pydantic_schemas.py`:** the analysis routers (anomalies, benchmark, risk, cti, reports, jobs) define small inline `BaseModel` request bodies in their own router files and return **plain `dict`s** (hand-assembled, not Pydantic response models). Examples: `anomalies.AnalyzeRequest{device_id}`, `anomalies.SuppressRequest{status, reason, admin_id}`, `benchmark.RunRequest{analysis_run_id}`, `risk.RunRequest{analysis_run_id}`, `cti.RunRequest{analysis_run_id}`, `reports.GenerateRequest{scope_type, scope_id}`, `devices.CredentialIn{auth_type, secret}` (write-only — secret never returned). The LTI module has its own schema file (`backend/services/lumina_threat_intel/schemas.py`) with enums (`IOCType`, `Severity`, `ThreatCategory`, `TriggerType`, `ScanStatus`) and response models (`ScanRequest`, `ScanCreatedResponse`, `PaginatedResponse`, `ReportSummaryResponse`, `ReportDetailResponse`, `FindingResponse`, `IOCResponse`, `DashboardStatsResponse`, `ReportStatsResponse`, `ScanStatus`).

### 6.3 REST API

All routers are registered in `backend/main.py` (the LTI router first, then the 14 core routers). The app also exposes three non-resource endpoints: `GET /` (welcome), `GET /health`, `GET /checkdbconnection`. CORS is restricted to `CORS_ALLOWED_ORIGINS` (default `http://localhost:5173`) with credentials. **Read-only semantics:** no endpoint writes to a firewall. POSTs that trigger background work do so via Celery `.delay()` and return `202 Accepted` with a `task_id`/`job_id`/run id; the benchmark/risk/cti/reports POSTs run synchronous **pure-DB** analysis (no firewall contact). The anomaly suppression PATCH only mutates LuminaFPM's own DB.

#### 6.3.1 Resource CRUD endpoints

| Method | Path | Router file | Purpose |
|---|---|---|---|
| GET | `/api/v1/vendors/` | `vendors.py` | List vendors (skip/limit). |
| GET | `/api/v1/vendors/{vendor_id}` | `vendors.py` | Get vendor (404 if missing). |
| POST | `/api/v1/vendors/` | `vendors.py` | Create vendor (201). |
| PATCH | `/api/v1/vendors/{vendor_id}` | `vendors.py` | Update vendor. |
| DELETE | `/api/v1/vendors/{vendor_id}` | `vendors.py` | Delete vendor (204). |
| GET | `/api/v1/devices/` | `devices.py` | List firewall devices. |
| GET | `/api/v1/devices/{device_id}` | `devices.py` | Device detail. |
| POST | `/api/v1/devices/` | `devices.py` | Register device (201). |
| PATCH | `/api/v1/devices/{device_id}` | `devices.py` | Update device. |
| DELETE | `/api/v1/devices/{device_id}` | `devices.py` | Delete device (204). |
| GET | `/api/v1/devices/admins/all` | `devices.py` | List administrators (co-located). |
| GET | `/api/v1/devices/admins/{admin_id}` | `devices.py` | Get administrator. |
| POST | `/api/v1/devices/admins/` | `devices.py` | Create administrator (201). |
| PATCH | `/api/v1/devices/admins/{admin_id}` | `devices.py` | Update administrator. |
| DELETE | `/api/v1/devices/admins/{admin_id}` | `devices.py` | Delete administrator (204). |
| GET | `/api/v1/devices/{device_id}/admins` | `devices.py` | List admin assignments for device. |
| POST | `/api/v1/devices/{device_id}/admins` | `devices.py` | Assign admin to device (201). |
| DELETE | `/api/v1/devices/{device_id}/admins/{admin_id}` | `devices.py` | Remove assignment (204). |
| GET | `/api/v1/network-objects/` | `network_objects.py` | List network objects. |
| GET | `/api/v1/network-objects/{object_id}` | `network_objects.py` | Get network object. |
| POST | `/api/v1/network-objects/` | `network_objects.py` | Create network object (201). |
| PATCH | `/api/v1/network-objects/{object_id}` | `network_objects.py` | Update network object. |
| DELETE | `/api/v1/network-objects/{object_id}` | `network_objects.py` | Delete network object (204). |
| GET | `/api/v1/rules/` | `rules.py` | List policy rules. |
| GET | `/api/v1/rules/{rule_id}` | `rules.py` | Get policy rule. |
| POST | `/api/v1/rules/` | `rules.py` | Create rule (201). |
| PATCH | `/api/v1/rules/{rule_id}` | `rules.py` | Update rule. |
| DELETE | `/api/v1/rules/{rule_id}` | `rules.py` | Delete rule (204). |
| GET | `/api/v1/rules/{rule_id}/objects` | `rules.py` | List rule→object mappings. |
| POST | `/api/v1/rules/{rule_id}/objects` | `rules.py` | Create rule→object mapping (201). |
| DELETE | `/api/v1/rules/{rule_id}/objects/{object_id}/{mapping_type}` | `rules.py` | Delete mapping (204). |
| GET | `/api/v1/rules/{rule_id}/anomalies` | `rules.py` | List anomalies for a rule. |
| POST | `/api/v1/rules/{rule_id}/anomalies` | `rules.py` | Create anomaly for a rule (201). |
| PATCH | `/api/v1/rules/{rule_id}/anomalies/{anomaly_id}` | `rules.py` | Update a rule's anomaly. |
| DELETE | `/api/v1/rules/{rule_id}/anomalies/{anomaly_id}` | `rules.py` | Delete a rule's anomaly (204). |
| POST | `/api/v1/rules/device/{device_id}/analyze` | `rules.py` | **Triggers Celery** `run_anomaly_analysis_task.delay(device_id=...)`; returns `{status, task_id}`. |
| GET | `/api/v1/external-nodes/` | `external_nodes.py` | List external nodes. |
| GET | `/api/v1/external-nodes/{node_id}` | `external_nodes.py` | Get external node. |
| POST | `/api/v1/external-nodes/` | `external_nodes.py` | Create external node (201). |
| PATCH | `/api/v1/external-nodes/{node_id}` | `external_nodes.py` | Update external node. |
| DELETE | `/api/v1/external-nodes/{node_id}` | `external_nodes.py` | Delete external node (204). |
| GET | `/api/v1/threat-feeds/` | `threat_feeds.py` | List threat feeds. |
| GET | `/api/v1/threat-feeds/{feed_id}` | `threat_feeds.py` | Get threat feed. |
| POST | `/api/v1/threat-feeds/` | `threat_feeds.py` | Create threat feed (201). |
| PATCH | `/api/v1/threat-feeds/{feed_id}` | `threat_feeds.py` | Update threat feed. |
| DELETE | `/api/v1/threat-feeds/{feed_id}` | `threat_feeds.py` | Delete threat feed (204). |
| GET | `/api/v1/api-tokens/` | `api_tokens.py` | List API tokens. |
| GET | `/api/v1/api-tokens/{token_id}` | `api_tokens.py` | Get API token. |
| POST | `/api/v1/api-tokens/` | `api_tokens.py` | Create API token (201). |
| PATCH | `/api/v1/api-tokens/{token_id}` | `api_tokens.py` | Update API token. |
| DELETE | `/api/v1/api-tokens/{token_id}` | `api_tokens.py` | Delete API token (204). |
| GET | `/api/v1/audit-logs/` | `audit_logs.py` | List audit logs. |
| GET | `/api/v1/audit-logs/{log_id}` | `audit_logs.py` | Get audit log. |
| POST | `/api/v1/audit-logs/` | `audit_logs.py` | Create audit log (201). |
| DELETE | `/api/v1/audit-logs/{log_id}` | `audit_logs.py` | Delete audit log (204). (No PATCH — logs are append/delete only.) |
| GET | `/api/v1/saved-searches/` | `saved_searches.py` | List saved searches. |
| GET | `/api/v1/saved-searches/{search_id}` | `saved_searches.py` | Get saved search. |
| POST | `/api/v1/saved-searches/` | `saved_searches.py` | Create saved search (201). |
| PATCH | `/api/v1/saved-searches/{search_id}` | `saved_searches.py` | Update saved search. |
| DELETE | `/api/v1/saved-searches/{search_id}` | `saved_searches.py` | Delete saved search (204). |

#### 6.3.2 Acquisition & jobs

| Method | Path | Router file | Purpose |
|---|---|---|---|
| POST | `/api/v1/devices/{device_id}/credentials` | `devices.py` | Create/rotate encrypted firewall credential (204; returns no secret; 422 on invalid `auth_type`). |
| POST | `/api/v1/devices/{device_id}/test-connection` | `devices.py` | Validate API connectivity read-only (authenticate + `validate_connection`); returns status only, never the secret. Uses HTTP vs HTTPS per `firewall_insecure_http_hosts`. |
| POST | `/api/v1/devices/{device_id}/poll` | `devices.py` | **Triggers Celery.** Creates an `AcquisitionJob` (status `queued`), dispatches `tasks.acquisition.poll_device.delay(job_id=...)`, returns `202 {job_id, status, device_id}`. 409 if no credential. |
| GET | `/api/v1/jobs` and `/api/v1/jobs/` | `jobs.py` | List acquisition jobs (optional `device_id`, `limit` 1–200), newest first; `{items, count}`. |
| GET | `/api/v1/jobs/{job_id}` | `jobs.py` | Acquisition job detail (no secrets). |
| GET | `/api/v1/jobs/{job_id}/artifacts` | `jobs.py` | List raw artifacts (metadata only: `artifact_id`, `type`, `path`, `sha256`). |

#### 6.3.3 Anomaly engine (Volume 6)

| Method | Path | Router file | Purpose |
|---|---|---|---|
| POST | `/api/v1/anomalies/run` | `anomalies.py` | **Triggers Celery** `run_anomaly_analysis_task.delay(device_id=...)`; omit `device_id` for an all-scope (cross-device) run. Returns `202 {status, task_id, scope, device_id}`. 404 if a named device is missing. |
| GET | `/api/v1/anomalies` and `/api/v1/anomalies/` | `anomalies.py` | List findings; filters `severity`, `anomaly_type`, `status`, `device_id`, `analysis_run_id`; paginated (`page`, `page_size` 1–200). Joins `policy_rule` for device/rule context; returns `{items, total, page, page_size}`. |
| GET | `/api/v1/anomalies/runs` | `anomalies.py` | List anomaly execution runs (observability; `limit` 1–100). |
| GET | `/api/v1/anomalies/{anomaly_id}` | `anomalies.py` | Finding detail (+ evidence + rule context). |
| PATCH | `/api/v1/anomalies/{anomaly_id}` | `anomalies.py` | Analyst lifecycle: set `status` ∈ {open, resolved, suppressed, accepted_risk, false_positive}; a `reason` is **required** for suppressed/accepted_risk/false_positive (422 otherwise). DB-only; never deletes history. |

#### 6.3.4 Benchmark / Risk / CTI / Reports (pure-DB analysis)

| Method | Path | Router file | Purpose |
|---|---|---|---|
| POST | `/api/v1/benchmark/run` | `benchmark.py` | Score an analysis run vs ground truth via `services.benchmark.runner.run_benchmark(db, analysis_run_id)`; persists `benchmark_case`/`benchmark_result`. Synchronous, DB-only. |
| GET | `/api/v1/benchmark/report` | `benchmark.py` | Read persisted results; returns recall, severity-match rate, per-case detail. |
| POST | `/api/v1/risk/run` | `risk.py` | Recalculate risk via `services.risk.runner.run_risk(db, analysis_run_id)`; persists `risk_assessment` (rule + device). DB-only. |
| GET | `/api/v1/risk` | `risk.py` | Latest risk assessments for the most recently scored run; `scope_type` ∈ {rule, device}, `limit` 1–200; highest score first; resolves rule names for rule scope. |
| POST | `/api/v1/cti/run` | `cti.py` | Enrich indicators / persist observations / correlate / recalc risk via `services.cti.runner.run_cti(db, analysis_run_id)`. API-based CTI; read-only against firewalls. |
| GET | `/api/v1/cti` | `cti.py` | Threat Center: enriched indicators + provider observations; flags `malicious` when any observation confidence ≥ 0.25. |
| POST | `/api/v1/reports/generate` | `reports.py` | Generate evidence-grounded SOC report via `services.llm.reporter.generate_report(db, scope_type, scope_id)` (`scope_type` = rule|executive). 400 on input error; an LLM failure still returns a stored report with `status='failed'`. |
| GET | `/api/v1/reports` | `reports.py` | List `llm_report` entries (`limit`, default 20). |
| GET | `/api/v1/reports/{report_id}` | `reports.py` | Report detail (output + evidence_refs + provider/model/prompt_version + confidence_note). |

#### 6.3.5 Threat-intel router (LTI module)

Mounted from `backend/services/lumina_threat_intel/api.py` (prefix `/api/v1/threat-intel`). Has its own DB-session dependency (`get_session`) and an in-memory + **Redis-backed sliding-window rate limiter** (`RATE_LIMIT_PER_USER_HOUR = 10`, `RATE_LIMIT_PER_TENANT_DAY = 50`).

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/threat-intel/scans` | **Triggers Celery** `tasks.threat_intel.run_scan_task.delay(...)`; pre-creates a `ThreatIntelReport` (status `running`) and returns its id. 409 if a scan is already running; 404 if a requested device id is unknown; 429 on rate limit. |
| GET | `/api/v1/threat-intel/scans` | List reports (paginated; `archived`, `status` filters; excludes archived by default). |
| GET | `/api/v1/threat-intel/scans/{report_id}` | Full report with all findings + IOCs + error log. |
| DELETE | `/api/v1/threat-intel/scans/{report_id}` | Soft-archive a report (`archived=true`; not a hard delete). |
| GET | `/api/v1/threat-intel/scans/{report_id}/stream` | **SSE** stream of pipeline progress (Redis pub/sub `sse_events:{report_id}`). |
| GET | `/api/v1/threat-intel/devices` | Lightweight scannable-device list for the multi-select UI. |
| GET | `/api/v1/threat-intel/findings` | Cross-report findings query (filters: `severity`, `category`, `correlated_only`, `new_only`, `search`; paginated). |
| GET | `/api/v1/threat-intel/findings/{finding_id}` | Single finding with IOCs + correlation detail. |
| GET | `/api/v1/threat-intel/dashboard/stats` | Dashboard overview stats (7-day window: total scans, last scan, critical/high counts, new findings, top categories, correlated count). |
| GET | `/api/v1/threat-intel/rules/{rule_id}/findings` | Findings correlated to a specific firewall rule (via `matched_rule_ids`). |

#### 6.3.6 Notes & gaps

- The internal `docs/API_CONTRACT.md` is the **target** contract (e.g. `/policies`, `/risks`, `/cti/indicators`, `/normalization/run/{device_id}`, `/jobs/{job_id}/replay-parser`, `/auth/*`, `/settings/*`, `/api/graph/policy-relationships`). The **implemented** paths differ from the target in several names: rules are served under `/api/v1/rules` (not `/policies`); risk under `/api/v1/risk` (singular, not `/risks`); CTI exposes `/api/v1/cti` + `/api/v1/cti/run` rather than `/cti/indicators` + `/cti/observations`. The normalization-run, parser-replay, auth, settings, and graph endpoints described in the contract are **not present** in `backend/api/routes/` and are not mounted in `main.py` — treat them as specified-but-unimplemented at this snapshot.
- Authentication/RBAC is described in the contract and `SECURITY_MODEL.md` but the route handlers themselves carry **no auth dependency** (`get_db_session` is the only `Depends`); RBAC enforcement is not visible in the route layer reviewed here. State this plainly to readers: the read-only-vs-firewall guarantee holds in code, but per-endpoint authz is not implemented in these routers.
- Several routers expose **both** `/api/v1/<resource>` and `/api/v1/<resource>/` (anomalies, jobs) to tolerate trailing-slash variance.

---

## 7. Backend — Threat-Intelligence (LTI/Robin) Subsystem & Core Infrastructure

This section documents two distinct concerns that share the `backend/` tree. **§7.1–§7.6** describe the **LTI/Robin dark-web threat-intelligence subsystem** — a large, mostly self-contained module that is **future/optional, disabled by default, and explicitly NOT part of the strict v1 read-only anomaly scope**. **§7.7–§7.12** describe the **core runtime infrastructure** (config, logging, security/credential encryption, Celery, the production task pipeline, and the test suite) that the v1 platform actually depends on.

> **Status and scope (read first).** Per `docs/ARCHITECTURE_DECISIONS.md` ADR **LFPM-IMPL-005** ("Realign 'Lumina Threat Intel' (LTI) to API-based CTI; demote dark-web/Robin"), the dark-web/Tor/Robin code is the *old* identity of this module. Volumes 9/14 make **API-based CTI primary** (documented in the Volume-9 CTI section — `backend/services/cti/`, exercised by `backend/tests/test_cti.py`) and make **dark-web threat intel a "future/optional" research extension**. The decision was to "quarantine Tor/dark-web/Robin behind an explicit, **disabled-by-default**, legally-gated feature flag," salvaging only the clearnet NVD/KEV connectors and correlation logic. The feature flag is `ENABLE_DARKWEB_INTEL` (`backend/core/config.py`), **default `false`**. The LTI subsystem described below (`backend/services/lumina_threat_intel/` + `backend/services/robin/`) is therefore documented as an implemented-but-optional capability, separate from the v1 deterministic anomaly engine and the v1 Volume-9 API-based CTI.

### 7.1 LTI subsystem — purpose and high-level pipeline

`backend/services/lumina_threat_intel/` ("LTI") scans for threats relevant to the customer's *actual* firewall inventory and correlates them against firewall rules/devices. It is built on top of **Robin** (`backend/services/robin/`), a third-party Tor dark-web search/scrape/LLM engine (Streamlit app + library; `README.md`, MIT `LICENSE`), which LTI imports without modifying (each LTI module inserts `services/robin` onto `sys.path` and imports `llm`, `search`, `scrape`).

The full pipeline is implemented in `orchestrator.py::run_scan(db, trigger_type, admin_id, requested_categories, device_ids, report)`. Its documented 12-stage sequence:

| Step | Stage | Implementation | LLM/Tor cost |
|------|-------|----------------|--------------|
| 1 | Extract keywords from Lumina DB | `keyword_extractor.extract_keywords` | none |
| 2 | Generate dark-web queries (single batched call) | `_generate_queries_batched` → `call_llm_structured(..., tier="fast")` | 1 LLM call |
| 3 | Search dark web over Tor | `scraper/engine.search_dark_web` → Robin `fetch_search_results` | Tor |
| 4 | Filter/rank results **in code** (no LLM) | `_filter_results_in_code` | none |
| 5 | Scrape `.onion` pages | `scraper/engine.scrape_results` → Robin `scrape_multiple` | Tor |
| 5b | Relevance filter (no LLM) | `_filter_scraped_by_relevance` / `_relevance_terms` | none |
| 6+7 | **One** consolidated Findings extraction + assessment | `build_findings_prompt` + `call_llm_structured(AssessedFindingsOutput, tier="strong")` | 1 LLM call |
| 8 | Validate IOCs against source; dedupe IOCs | `_validate_iocs_in_source`, `_dedupe_iocs` | none |
| 9 | Correlate against firewall inventory | `correlator.correlate_findings` | none |
| 10 | Diff vs prior scans | `diff_tracker.mark_new_findings` | none |
| 11 | Persist findings + IOCs | inline ORM writes | none |
| 12 | Finalize report, emit `done` SSE | inline | none |

A design note in the code states this replaces the original 30–50 per-keyword `refine_query` calls + 6 narrative/refiner calls with **~2 LLM calls per scan** (1 fast query-gen + 1 strong findings); `LTI_DEMO_BRIEF.md` confirms "~2 LLM calls per scan."

Deterministic **clearnet** and **dark-web-aggregator** connectors (§7.3) run *before* the Findings LLM call (so the narrative can speak for the whole report) and are merged into `all_findings`; they are reliable even when Tor/LLM are down.

### 7.2 LTI components

| File | Responsibility |
|------|----------------|
| `orchestrator.py` (38.5 KB) | The pipeline above; corpus building, IOC validation, stats, `clean`/`coverage_note` synthesis |
| `keyword_extractor.py` | `extract_keywords(db, device_ids)` → bundle `{firmwares, vendors_models, cves, org_domains, org_ips}` from `FirewallDevice`/`Vendor`/`NetworkObject`/`RuleAnomaly`; `_CVE_RE`, `_IP_RE`, splits public vs RFC1918 IPs (`_PRIVATE_PREFIXES`); caps (`[:50]`, CVEs `[:25]`); `keywords_are_empty()` |
| `prompts/` | `shared.py` (`CORE_PREAMBLE`, `DATA_HANDLING_BLOCK`, `SHARED_PREAMBLE`, `ACTION_FORMAT_GUIDANCE`, `LLM_RETRY_INSTRUCTION`); `query_generator.py` (`QUERY_GENERATOR_PROMPT`); `findings.py` (`CONSOLIDATED_FINDINGS_PROMPT`, `build_findings_prompt`); `refiners.py` (legacy `REFINER_BASE_TEMPLATE`, `CATEGORY_GUIDANCE_MAP`, `build_refiner_prompt`) |
| `scraper/engine.py` | `search_dark_web`, `scrape_results`; `_lti_search` queries LTI's curated engines via Robin's `fetch_search_results`; `_dedup_key` canonicalizes URLs; drops noise via `sources.is_noise_result` |
| `sources.py` | Source registry: `SEARCH_ENGINES` (Group A, 8 `.onion` search engines), `CURATED_ONION_SOURCES` (Group B, 11 forums/DLS, metadata-only), `CLEARNET_FEEDS` (Group C); `RESULT_DENY_SUBSTRINGS`, `is_noise_result`, `search_query_urls` |
| `clearnet_intel.py` | Deterministic CISA KEV + NVD + PAN/Fortinet PSIRT + EPSS connectors (§7.3) |
| `darkweb_aggregators.py` | Ransomware.live leak-site connector (§7.3) |
| `correlator.py` | IOC→rule/device matching, version-range correlation, hybrid relevance upgrade (§7.4) |
| `diff_tracker.py` | `compute_finding_hash` = SHA-256(category\|title\|sorted IOC values); `mark_new_findings(lookback_days=7)` |
| `model_router.py` | Tiered, budget-aware, multi-provider model selection (§7.5) |
| `llm_client.py` | `call_llm_structured` (schema-validated, retrying), `call_llm_text`, `get_robin_model_name` |
| `schemas.py` | Pydantic enums + LLM/API schemas (§7.6) |
| `db_models.py` | 4 ORM tables (§7.6) |
| `api.py` | FastAPI router `/api/v1/threat-intel` (§7.6) |
| `stream.py` | `SSEPublisher` (Redis Pub/Sub), `format_sse_message` |
| `exceptions.py` | `LLMValidationError`, `LLMProviderError` |
| `__init__.py`, `test_ground.py`, `tests/` | package init; ad-hoc ground-truth script; unit tests (§7.12) |

**Robin** (`backend/services/robin/`) provides: `llm.py` (`get_llm`, `refine_query`, `filter_results`, `generate_summary`, LangChain-based, multi-provider via `llm_utils.resolve_model_config`); `search.py` (`fetch_search_results`/`get_search_results`, its own 16-engine `SEARCH_ENGINES` list — superseded by LTI's `sources.SEARCH_ENGINES`); `scrape.py` (Tor SOCKS5 session via `socks5h://$LTI_TOR_SOCKS_HOST:$LTI_TOR_SOCKS_PORT`, rotating `USER_AGENTS`, `MAX_DOWNLOAD_BYTES=1_000_000`, `MAX_EXTRACTED_TEXT_CHARS=50_000`, `MAX_RETURN_CHARS=2_000`); `api_bridge.py` (standalone FastAPI `POST /api/v1/hunt`, not mounted into Lumina's app); `ui.py` (Streamlit), `health.py`, `config.py`. Robin reads `ROBIN_MODEL` (default `gpt4o`).

### 7.3 Deterministic connectors (the salvaged, free, no-LLM backbone)

These are the parts ADR-005 explicitly preserves. They produce findings in the *same dict shape* as the LLM Findings call, so they flow through correlation/diff/persistence unchanged.

**Clearnet (`clearnet_intel.py`).** `fetch_clearnet_findings(db, device_ids)` merges, de-duplicating by primary CVE, in priority order:
- `fetch_kev_findings` — **CISA KEV** (`CLEARNET_FEEDS["cisa_kev"]`), filtered to customer vendors via `_VENDOR_MATCH` tokens. KEV = actively-exploited → `criticality` `high` (or `critical` if `knownRansomwareCampaignUse=="known"`), `relevance_score=60`/band `medium`, `confidence=95`. Urgency prefix `IMMEDIATE`/`24H` from ransomware flag or overdue `dueDate`.
- `fetch_paloalto_psirt_findings` — **PAN PSIRT** (`PAN_PSIRT_API = https://security.paloaltonetworks.com/json`), queried **per installed PAN-OS version**, so every advisory is vendor-confirmed → `relevance_score=90`/band `high`.
- `fetch_fortinet_psirt_findings` — **Fortinet PSIRT RSS** (`FORTINET_PSIRT_RSS = https://www.fortiguard.com/rss/ir.xml`), not version-filtered → `relevance_score=30`/band `low`.
- `fetch_nvd_findings` — **NVD 2.0 API** per product (`_NVD_VENDOR_KEY` → `fortios`/`pan_os`/`cisco_asa`), window `LTI_NVD_LOOKBACK_DAYS` (default 120, NVD max), `per_vendor_cap=15`. Severity via `_cvss_to_criticality` (≥9 critical, ≥7 high, ≥4 medium, >0 low, else info). `relevance_score=25`/band `low`. Extracts CPE affected version ranges (`_extract_affected_ranges`, `_NVD_PRODUCT_CPE`) and attaches **internal hints** `_affected_ranges`/`_nvd_product` for the correlator (stripped at persistence; not schema fields).
- `_enrich_with_epss` — **FIRST.org EPSS** (`EPSS_API_URL`), one batched request; tags `epss:<p>` and, above `LTI_EPSS_LIKELY_THRESHOLD` (default 0.5), `likely-exploited` + appends probability to `relevance_reason`. Does **not** change bands.

**Dark-web aggregator (`darkweb_aggregators.py`).** `fetch_ransomware_dls_findings(db, device_ids)` queries **Ransomware.live** (`RANSOMWARELIVE_API`, default `https://api.ransomware.live/v2`) `searchvictims/<label>` for the customer's registrable org-name labels (budget `LTI_RANSOMWARELIVE_MAX_LOOKUPS`, default 5). Full-domain hit → `confirmed` finding (`relevance_score=95`/band `high`, `criticality=critical`); name-only similarity → `possible-match` (band `medium`, tagged `possible-match`) for human verification. Returns `(findings, domains_checked)`. Honest scope note in-file: this checks whether the *customer* appears on leak sites; it does **not** provide vendor/CVE exploit chatter (the paid-only gap).

`sources.CLEARNET_FEEDS` also registers (not all wired): `cisco_psirt` (bearer auth), `exploit_db`, `github_poc`, `threatfox` (api_key), `ransomware_live`.

### 7.4 Correlation and the hybrid-relevance / assessment model

`correlator.correlate_findings(db, findings, device_ids)` mutates each finding in place. It pre-loads `NetworkObject`, `FirewallDevice`, `RuleObjectMapping`, `PolicyRule`, then for each IOC:
- matches `NetworkObject.value` → `RuleObjectMapping` → `matched_rule_ids`;
- matches device `management_ip` (for `ipv4`/`ipv6`/`domain`) → `matched_device_ids`;
- for `cve` IOCs, matches firmware version strings mentioned in title/description (`_firmware_matches_cve_context`);
- **version-aware (P14):** for NVD findings carrying `_affected_ranges`+`_nvd_product`, tests whether the device's installed `firmware_version` falls inside a CPE range via `_version_tuple`/`_version_in_range` (vendor-gated by `_NVD_PRODUCT_VENDOR`), and if so adds the device + all its rules.

**Hybrid relevance:** the LLM proposes `relevance_score`/`relevance_band`/`relevance_reason` against the fingerprint; the correlator then **verifies against real inventory** and, on any confirmed rule/device match, upgrades band to `high`, raises score to `max(score, 90)`, and escalates `[SCHEDULED]` actions to `[24H]`. **Exception:** `possible-match` findings carry the customer's own org domain as IOC — matching that is circular, so their correlation is cleared and band left as stated.

The two-axis **assessment model** (`schemas.py`): **Criticality** (`info|low|medium|high|critical`, intrinsic danger) and **Relevance** (`none|low|medium|high` + 0–100 score, fit to this inventory). The orchestrator computes `report.clean = not any(band in ("medium","high"))` *after* correlation, synthesizes a non-null `coverage_note`, and **does not persist `criticality=="info"` findings** as rows (they appear only in the narrative). The legacy `severity` column is derived from criticality (`info → low`).

### 7.5 Model router (multi-provider, tiered, budget-aware)

`model_router.py` selects a model **per request** by tier and remaining budget, with fallback chains. Tiers map task→class: `fast` (query gen), `strong` (Findings reasoning), `premium` (explicit max quality). `create_llm(model_id)` builds a LangChain chat model for prefixes `agentrouter/` (ChatAnthropic by default; `LTI_AGENTROUTER_MODE=openai` switches), `opencode/`, `openrouter/`, `deepseek/`, `gemini*` (with `BLOCK_NONE` safety via `_gemini_safety_off`), else Robin's resolver.

`_provider_default_chains()` picks defaults from whichever credentials exist: **DeepSeek direct** (`DEEPSEEK_API_KEY`) > **Gemini** (`GOOGLE_API_KEY`/`LTI_LLM_API_KEY`) > **AgentRouter** (legacy; noted to 401 on backend API calls). Per-tier override env: `LTI_CHAIN_FAST|STRONG|PREMIUM`. `MODEL_CATALOG` holds per-1M-token prices. Budget: soft cap `LTI_BUDGET_USD` (default 20), state file `LTI_BUDGET_STATE_FILE` (default `/app/.lti_budget_state.json`); once spend ≥ `LTI_BUDGET_DOWNGRADE_AT` (0.9) × cap, all tiers downgrade to the cheapest model (warn, never hard-stop). `invoke_with_fallback(prompt, tier)` tries the chain until non-empty text, records estimated spend (`_estimate_cost`, ~4 chars/token), and sets `last_model_used()` for accurate report metadata. `llm_client.call_llm_structured` strips markdown fences (`_extract_json`), `json.loads`, `model_validate`, and retries up to `LTI_LLM_MAX_RETRIES` (default 3) by appending `LLM_RETRY_INSTRUCTION` on `ValidationError`/`JSONDecodeError`.

### 7.6 LTI persistence, schemas, API

**ORM tables (`db_models.py`, Integer PKs, single-tenant, no `tenant_id`):**
- `threat_intel_reports` — one row per scan. Columns: `trigger_type` (`ti_trigger_type`), `triggered_by_admin_id` (FK `administrator`), `status` (`ti_scan_status`: running/completed/failed/partial), timestamps + `scan_duration_seconds`, `input_keywords` (JSONB), `queries_generated_count`, `onion_pages_scraped_count`, `scanned_device_ids` (JSONB), `narrative_summary`, `clean` (Bool), `coverage_note`, `stats` (JSONB), `llm_model_name`/`llm_input_tokens`/`llm_output_tokens`, `error_log` (JSONB), `archived`. Cascade relations to findings + raw_scrapes.
- `threat_intel_findings` — `category` (`ti_category`), `severity` (`ti_severity`), `criticality` (`ti_criticality`), `relevance_score`/`relevance_band` (`ti_relevance_band`)/`relevance_reason`, `confidence`, `title`/`description`, `recommended_actions`/`tags` (JSONB), source provenance columns, `matched_rule_ids`/`matched_device_ids` (JSONB), `correlation_match_reason`, `is_new_since_last_scan`/`first_seen_in_scan_id`, `finding_hash` (indexed), `parse_error`.
- `threat_intel_iocs` — `finding_id` FK, `ioc_type` (`ti_ioc_type`, 12 values), `ioc_value` (≤2048).
- `threat_intel_raw_scrapes` — raw scraped content (`raw_text`, doc'd 7-day retention; orchestrator truncates to 10 000 chars).

These models are imported in `main.py` so they register with `Base.metadata`.

**Schemas (`schemas.py`):** enums `IOCType`, `Severity`, `ThreatCategory` (`exploit|credential|c2|ransomware|iab`), `TriggerType`, `ScanStatus`, `Criticality`, `RelevanceBand`. LLM-output models `IOC`, `FindingSource`, `Finding`, `GeneratedQuery`/`QueryGenerationOutput`, `AssessedFinding`/`AssessedFindingsOutput` (the one used by the consolidated call: `clean`, `coverage_note`, `narrative_summary`, `findings`). API models `ScanRequest`/`ScanCreatedResponse`, `FindingResponse`/`IOCResponse`, report summary/detail, `DashboardStatsResponse`, `PaginatedResponse`.

**API router (`api.py`, prefix `/api/v1/threat-intel`, mounted in `main.py`):**

| Verb + path | Function | Notes |
|-------------|----------|-------|
| `POST /scans` | `trigger_scan` | rate-limited; 409 if a scan is `running`; validates `device_ids`; creates report; dispatches Celery `run_scan_task.delay` |
| `GET /scans` | `list_reports` | paginated, `archived`/`status` filters |
| `GET /scans/{id}` | `get_report_detail` | full report + findings + IOCs + `error_log` |
| `DELETE /scans/{id}` | `archive_report` | soft archive |
| `GET /scans/{id}/stream` | `stream_scan_progress` | SSE via Redis Pub/Sub channel `sse_events:{id}` |
| `GET /devices` | `list_scannable_devices` | for multi-select UI |
| `GET /findings`, `GET /findings/{id}` | cross-report queries | severity/category/correlated/new/search filters |
| `GET /dashboard/stats` | `get_dashboard_stats` | 7-day aggregates |
| `GET /rules/{rule_id}/findings` | findings correlated to a rule | |

Rate limiting is **Redis-backed sliding window** keyed `rate_limit:user:{admin_id|anon}` (`RATE_LIMIT_PER_USER_HOUR=10`; `RATE_LIMIT_PER_TENANT_DAY=50` declared but unused; `admin_id` is always passed as `None`, an implementation gap). **Note:** a separate, unrelated CRUD router `backend/api/routes/threat_feeds.py` (prefix `/api/v1/threat-feeds`) manages a `ThreatFeed` table and is independent of LTI.

**Celery task (`tasks/threat_intel.py`):** `run_scan_task` (name `tasks.run_scan_pipeline`, `max_retries=0`, `acks_late=True`, `time_limit=1800`/`soft_time_limit=1500`) opens its own DB session, publishes progress to Redis channel `sse_events:{report_id}`, and delegates to `orchestrator.run_scan`. The SSE `stream.SSEPublisher.emit` and the task's `_set_progress` both publish JSON events to the same channel; `api.stream_scan_progress` subscribes and terminates on `done`/`failed`.

**Notable LTI env vars:** `ENABLE_DARKWEB_INTEL` (default false — gates the whole subsystem), `LTI_TOR_SOCKS_HOST`/`_PORT` (default 127.0.0.1/9050), `LTI_MAX_QUERIES`(8), `LTI_MAX_FILTERED_RESULTS`(20), `LTI_MAX_SEARCH_RESULTS`(100), `LTI_MAX_WORKERS`(5), `LTI_MAX_PAGES`(25)/`LTI_MAX_CHARS`(60000)/`LTI_MAX_DIGEST_ITEMS`(25), `LTI_CORPUS_MODE` (`digest` default = moderation-safe defanged metadata vs `excerpts` = real text), `ROBIN_MODEL`, `LTI_LLM_MODEL`/`LTI_LLM_API_KEY`, plus router/budget/connector vars above.

---

### 7.7 Core configuration — the `Settings` object (`backend/core/config.py`)

The single source of runtime config. It prefers **pydantic-settings** (typed/validated `Settings(BaseSettings)`, `env_file=".env"`, `extra="ignore"`) and **gracefully falls back to a plain `os.getenv` class** if `pydantic-settings` is not installed (so a partially-built image never hard-fails). Both variants expose the same fields and properties. Exposed as the module-level `settings = get_settings()` (`@lru_cache`).

Key fields (env var → default):

| Field / env | Default | Purpose |
|-------------|---------|---------|
| `environment` / `ENVIRONMENT` | `development` | development\|lab\|staging\|production; `is_production` property |
| `log_level` / `LOG_LEVEL` | `INFO` | |
| `database_url` / `DATABASE_URL` | `postgresql://lumina:lumina@db:5432/lumina_fpm` | |
| `redis_url` / `REDIS_URL` | `redis://redis:6379/0` | broker |
| `secret_key` / `SECRET_KEY` | `change-me-in-production` | |
| `encryption_key` / `ENCRYPTION_KEY` | `""` | **Fernet** key for credential encryption (§7.9) |
| `cors_allowed_origins_raw` / `CORS_ALLOWED_ORIGINS` | `http://localhost:5173` | CSV → `cors_allowed_origins` property |
| `access_token_expire_minutes` | 30 | |
| `firewall_tls_verify` / `FIREWALL_TLS_VERIFY` | `True` | lab may disable for self-signed certs |
| `acquisition_raw_dir` / `ACQUISITION_RAW_DIR` | `/app/raw_acquisition` | |
| `acquisition_timeout_seconds` / `_max_retries` | 60 / 3 | |
| **`firewall_insecure_http_hosts_raw` / `FIREWALL_INSECURE_HTTP_HOSTS`** | `""` | CSV of mgmt IPs reached over plain **HTTP** (§7.8) |
| `llm_provider`/`llm_model`/`llm_api_key` | `gemini`/`gemini-2.5-flash`/`""` | v1 CTI LLM (Gemini default, offline fallback) |
| `ollama_base_url` | `http://ollama:11434` | |
| `cti_provider_keys_raw` / `CTI_PROVIDER_KEYS` | `""` | CSV → CTI provider API keys |
| `cti_allow_internal_indicators` | `False` | data-minimization: never send RFC1918 indicators out by default |
| **`enable_darkweb_intel` / `ENABLE_DARKWEB_INTEL`** | `False` | feature flag gating the entire LTI/dark-web subsystem (ADR LFPM-IMPL-005) |

The file cites Volume 13 §6 (canonical env vars) and Volume 12 (secrets from env / secret manager, never source).

### 7.8 `FIREWALL_INSECURE_HTTP_HOSTS` (lab-only HTTP escape hatch)

A CSV env var (`firewall_insecure_http_hosts` property splits it) listing management IPs whose HTTPS admin service is unavailable, so acquisition reaches them over plain HTTP. In `tasks/acquisition.py::poll_device`: `scheme = "http" if device.management_ip in settings.firewall_insecure_http_hosts else "https"`, passed into `ConnectorConfig.scheme`. The config docstring warns: **NEVER set in production** — API tokens would traverse unencrypted. This exists for the VMware lab (per memory: a FortiGate whose `httpsd` won't bind 443).

### 7.9 Credential encryption (`core/security.py` + `services/credentials.py`)

Per Volume 12 §6 / Volume 3 §6.2 (ADR LFPM-IMPL-008), per-device firewall secrets are **encrypted at rest with Fernet** (AES-128-CBC + HMAC) and decrypted only in backend/worker memory.

`core/security.py`:
- `_derive_fernet_key()` — uses `ENCRYPTION_KEY` directly if it is already a valid 32-byte url-safe-b64 Fernet key; otherwise **derives** a key by `urlsafe_b64encode(sha256(passphrase))` (so the lab need not pre-generate a Fernet key). Raises `CredentialEncryptionError` if `ENCRYPTION_KEY` is empty ("refusing to handle credentials") with a generation hint.
- `encrypt_secret(plaintext) → str` (b64 ciphertext), `decrypt_secret(ciphertext) → str` (never includes the secret/ciphertext in error text), `mask_secret()` → `"<N chars, ***>"`.

`services/credentials.py`:
- `VALID_AUTH_TYPES = {"fortigate_api_token", "panos_api_key", "panos_userpass"}`.
- `set_credential(db, device_id, auth_type, secret)` — create/rotate `DeviceCredential.secret_encrypted`, sets `rotated_at`; logs only device_id + auth_type.
- `get_decrypted_secret(db, device_id) → (auth_type, plaintext)` (memory-only; updates `last_used_at`), `has_credential(...)`. Plaintext is never returned to the frontend or logged.

### 7.10 Structured, secret-safe logging (`core/logging.py`)

`configure_logging(level)` configures the root logger **once, idempotently** (`root._lumina_configured` flag), a single stdout `StreamHandler`, format `"%(asctime)s %(levelname)-7s [%(name)s] %(message)s"` (ISO-8601 with tz), and tames `urllib3`/`asyncio` to WARNING. A `SecretRedactingFilter` (Volume 12 §8/§9) masks credential-looking substrings via four regexes — `api_key`/`api-key`, `token`, `password` (key=value/JSON forms), and `Authorization: Bearer <…>` — replacing the value with `***REDACTED***`. `get_logger(name)` is the standard accessor.

### 7.11 Celery app and the production task pipeline

**`backend/celery_app.py`** — `Celery("lumina_fpm")`, broker = `REDIS_URL`, **result backend = PostgreSQL** via SQLAlchemy (`db+<DATABASE_URL>`; falls back to Redis if `DATABASE_URL` is misconfigured). Reliability config: `task_acks_late=True`, `worker_prefetch_multiplier=1`, `task_track_started=True`, JSON-only serialization, UTC, `result_expires=86400`. **Per-job-type queue routing** (V2 §14.3 / V3 Table 28 / V13 Table 5):

```
acquisition.*  → acquisition     normalization.* → normalization
analysis.*     → analysis        cti.*           → cti        reporting.* → reporting
```

Registered task modules (`celery.conf.include`): `tasks.acquisition`, `tasks.normalization`, `tasks.threat_intel`, `tasks.anomaly`.

**The real v1 task chain** (acquisition → normalization → anomaly → risk), all read-only and never writing to firewalls:
- `tasks/acquisition.py::poll_device(job_id)` (name `acquisition.poll_device`, queue `acquisition`) — loads job+device, decrypts credential, resolves vendor, builds `ConnectorConfig` (with HTTP/HTTPS scheme per §7.8, `verify_tls`, timeout), runs `connector.collect()`, persists raw artifacts + manifest (SHA-256 via `storage.store_bundle`), updates device freshness/firmware, maps connector error codes → job status via `_ERROR_TO_STATUS`, and on success/partial chains `normalize_device.delay(job_id)`.
- `tasks/normalization.py::normalize_device(job_id)` (name `normalization.normalize_device`, queue `normalization`) — replays stored raw artifacts (never touches the firewall, never stores secrets): `parse_artifacts` → `normalize_payloads` → `persist_result` (canonical Schema v4, idempotent), then chains `run_anomaly_analysis_task.delay(device_id=…)`.
- `tasks/anomaly.py::run_anomaly_analysis_task(device_id=None)` (name `analysis.run_anomaly_analysis`, queue `analysis`, `time_limit=300`, `ENGINE_VERSION="anomaly-engine/1.0.0"`) — creates an `AnomalyExecutionLog`, reconstructs `NormalizationResult` via `load_normalized_result`, runs the **deterministic** `services.anomaly.analyze` (no randomness, no LLM, no network), maps each `Finding` (device_id+rule_uuid) → `PolicyRule.rule_id` and writes `RuleAnomaly` rows, finalizes the log, then best-effort triggers `services.risk.runner.run_risk` (V6 §11; a risk failure never fails analysis). `device_id=None` analyzes all devices (needed for cross-device detectors).
- `tasks/threat_intel.py::run_scan_task` — the **optional** LTI scan (§7.6), on no dedicated queue routing (uses default).

### 7.12 Test suite (`backend/tests/`)

All tests are designed to run **without a live firewall, network, or DB** (pure / fixture- or monkeypatch-based); each is runnable as `python backend/tests/test_*.py` or via pytest.

| File | Subsystem covered |
|------|-------------------|
| `test_parsing.py` | Vendor parsers vs **real captured lab artifacts** (FortiOS v7.0.5, PAN-OS) → uniform `ParsedDevicePayload`; the cross-device benchmark pair (LAN_NET→WEB_SERVER HTTPS allow, no inspection) |
| `test_normalization.py` | Cross-vendor normalization — FortiGate + Palo Alto correlate into one canonical model (the project keystone) |
| `test_acquisition.py` | Acquisition connectors + storage: monkeypatched FortiOS JSON / PAN-OS XML, firmware extraction, partial-success on optional 404, raw-artifact manifest + SHA-256 |
| `test_anomaly.py` | Deterministic anomaly engine (V5): ground-truth on real fixtures + crafted unit tests (shadowing/duplicate/conflict/any_to_sensitive/overly_permissive) |
| `test_risk.py` | Risk scorer bands/factors (V8): `tier_of`, `score_rule`, `score_device`, cap at 100 |
| `test_benchmark.py` | Benchmark scorer (V7) `ExpectedCase`/`score` |
| `test_cti.py` | **v1 API-based CTI** (V9): `is_public_ip`/`classify`/`extract_indicators` (RFC1918 minimization), `LabOfflineProvider`, `build_providers`, `threat_exposure` → CTI risk factor (28) |
| `test_llm.py` | **v1 LLM SOC reporting** (V10): `SYSTEM_PROMPT` guardrails ("use only evidence", "do not invent", "deterministic engine … not you"), `OfflineProvider` determinism, provider fallback, evidence-id embedding |

LTI-specific unit tests live separately under `backend/services/lumina_threat_intel/tests/`: `test_diff_tracker.py` (`compute_finding_hash`, new/seen classification), `test_llm_client.py` (`_extract_json`, retry, schema validation), `test_prompts.py` (prompt construction + `_validate_iocs_in_source` anti-hallucination). **Observation:** there is **no test for `orchestrator.run_scan`, `correlator.py`, `clearnet_intel.py`, or `darkweb_aggregators.py`** end-to-end — consistent with LTI's optional/quarantined status. Note `test_cti.py` and `test_llm.py` cover the **v1 API-based CTI/LLM** path (`services/cti`, `services/llm`), which is *separate* from the LTI subsystem documented in §7.1–§7.6.

---

## 8. Frontend Architecture & Components

### 8.1 Overview & Stack

The LuminaFPM frontend is a single-page React application that consumes the FastAPI backend's REST endpoints. It is a **read-only console**: every mutating call it makes triggers LuminaFPM's own analysis jobs (sync, analyze, enrich, generate, benchmark) — none of them writes to a firewall. The app lives entirely under `frontend/src/`.

**Tooling (`frontend/package.json`):**

| Concern | Choice | Notes |
|---|---|---|
| Build / dev server | **Vite `^8.0.4`** | `dev`, `build`, `preview`, `lint` (`eslint .`), `typecheck` (`tsc --noEmit`) scripts |
| UI framework | **React `^19.2.4`** + `react-dom` | `React.StrictMode` enabled (`main.jsx`) |
| Vite React plugin | `@vitejs/plugin-react ^6.0.1` | esbuild transpile; Babel fast-refresh |
| TypeScript | `typescript ^5.7.2` | incremental migration (see §8.4) |
| Styling | `tailwindcss ^4.2.2` + `@tailwindcss/vite` listed as devDeps | **but** the app's real styling is hand-rolled CSS variables in `src/style.css` (imported in `main.jsx`); no Tailwind utility classes appear in any component. Fonts (Inter, JetBrains Mono) are loaded from Google Fonts in `index.html` |
| Lint | `eslint ^9.39.4` flat config (`eslint.config.js`), `eslint-plugin-react-hooks`, `eslint-plugin-react-refresh`; rule `no-unused-vars` with `varsIgnorePattern: '^[A-Z_]'`; ignores `dist`; `files: ['**/*.{js,jsx}']` only (TS files are **not** linted by ESLint) |

**Declared-but-unused dependencies** (verified by grep over `src/` — zero imports): `cytoscape ^3.33.2`, `cytoscape-dagre ^2.5.0`, `react-cytoscapejs ^2.0.0`, `recharts ^3.8.1`, `react-router-dom ^7.14.1`, `lucide-react ^1.8.0`. The topology is a hand-rolled SVG (not Cytoscape), routing is hash-based (not react-router), charts are hand-drawn SVG (not Recharts), and icons are hand-crafted SVG paths in `src/icons.jsx` (not lucide). These packages are installed dead weight. (See §8.10.)

**Entry chain:** `index.html` → `<div id="root">` + `<script type="module" src="/src/main.jsx">` → `main.jsx` renders `<React.StrictMode><LFPMProvider><App/></LFPMProvider></React.StrictMode>`.

### 8.2 Build & Serve Topology

**Dev (`vite.config.js`):** a single dev-server proxy maps `'/api/v1'` → `apiTarget`, where
```js
const apiTarget = process.env.VITE_API_PROXY || 'http://localhost:8000'
```
- In Docker Compose, the frontend service sets `VITE_API_PROXY=http://api:8000` (reach the backend by service name).
- On the host (`npm run dev`), the var is unset → defaults to `http://localhost:8000` (the published backend port).
All client code calls relative paths (`/api/v1/...`), so the proxy/origin is environment-agnostic.

**Dev container (`frontend/Dockerfile`):** `node:22-slim`, `npm install`, `EXPOSE 5173`, `CMD ["npm","run","dev","--","--host"]` — i.e. the shipped Docker image runs the **Vite dev server**, not a production build.

**Production (`nginx.conf`):** an Nginx config exists for serving a built SPA: `root /usr/share/nginx/html`, SPA fallback `try_files $uri $uri/ /index.html`, and a 1-year immutable cache for static asset extensions. Note: the provided `Dockerfile` does not build/copy into Nginx; `nginx.conf` is the intended prod-serve config but is not wired into the included Dockerfile.

### 8.3 App Structure, Routing & Global State

**Hash-based router (`src/app.jsx`).** There is no router library. The default export `App` parses `window.location.hash`:
- `VALID_PAGES = {'dashboard','audit','risk','topology','threats','reports','benchmark','settings'}`.
- `parseHash()` strips a leading `#/`, splits `path?qs`, validates the page, and parses the query string into an `intent` object. `makeHash(page, intent)` rebuilds `#page?key=val`.
- Navigation is centralised in `goTo(nextPage, params)`: it clears the inspector + palette, sets `page`, and sets `intent`. A `useEffect` mirrors `(page,intent)` into the URL via `history.replaceState`; another listens to `hashchange`/`popstate` so back/forward and pasted deep-links work.
- Deep-link examples used across screens: `#audit?rule=POL-026`, `#audit?filter=critical&vendor=palo-alto`, `#topology?device=fw-004`, `#threats?cve=CVE-…&tab=advisories`.

**Page mounting:** `App` conditionally renders one screen by `page`:
`Dashboard`, `PolicyAudit`, `RiskPosture`, `Topology`, `ThreatIntelligence`, `Reports`, `BenchmarkCenter`, `Settings`. It also mounts the persistent `Rail`, `Topbar`, `StatusBar`, `Inspector`, `CommandPalette`, and `ToastHost`.

**App-level state & persistence:**
- `user` — demo session, persisted in `sessionStorage` (`lumina_demo_user` + `lumina_session_ver`); a `LFPM_SESSION_VERSION = 2` constant invalidates old sessions.
- `page` — persisted to `sessionStorage` (`lumina_page`).
- `theme` — `'dark' | 'light'`, persisted to `localStorage` (`lumina_theme`), applied to `document.documentElement[data-theme]` *before* React mounts to avoid a flash; toggled via `toggleTheme`.
- `timeRange` / `timeRangeLabel` — dashboard window (`'1h' … '90d'` plus `'custom'`).
- `paletteOpen`, `inspector`.
- Keyboard: `⌘K`/`Ctrl-K` and `/` (when not in an input) open the command palette.
- `criticalCount = data.policies.filter(p => p.status !== 'clean').length` feeds the Audit nav badge.

**Global data provider (`src/context/LFPMContext.jsx`).** `LFPMProvider` holds `{ data, loading, error, refreshData }` in context (consumed via the `useLFPM()` hook, which throws if used outside the provider). Initial `data` is seeded from the mock skeleton in `src/data.js` (mostly empty arrays + the static `users` list + the `fmt` helpers), `loading` starts `true`. On mount it calls `refreshData()` → `fetchLFPMData()`; on success it replaces `data`, on failure it sets `error` and keeps the (mostly empty) fallback. `refreshData` is also passed down to screens so actions (sync, run audit, scan) can re-pull the whole model.

### 8.4 Two API Layers & the Incremental TS Migration

There are **two distinct client layers**, by design:

**(A) Legacy aggregate loader — `src/api.js` (JS).** `fetchLFPMData()` is the single big loader feeding `LFPMContext`. It fans out parallel `fetch` calls to the inventory + analysis endpoints and **maps backend DB rows into the UI's flat view-model**. Key transforms:
- Inventory pulled in parallel: `GET /api/v1/vendors/`, `/devices/`, `/rules/`, `/network-objects/`, plus deterministic risk `GET /api/v1/risk?scope_type=rule&limit=200` and `?scope_type=device&limit=200`.
- **Current findings are run-scoped.** It calls `GET /api/v1/anomalies/runs?limit=20`, picks the latest `scope_type==='all' && status==='completed'` run (`latestRunId`), then `GET /api/v1/anomalies?analysis_run_id={id}&page_size=200` and groups anomalies by `rule_id`. This avoids double-counting findings across historical runs and ensures cross-device detectors (only present in all-scope) appear.
- Per-rule object resolution: `GET /api/v1/rules/{id}/objects` resolves `source`/`destination` network-object names into `srcIp`/`dstIp` strings (`'any'` when empty).
- **Status is severity-based** (`SEV_RANK = {critical:4,high:3,medium:2,low:1,info:0}`): a rule's `status` is the worst *open* anomaly's `severity_level`, or `'clean'` if none open. `status` doubles as a CSS severity class; `'clean'`→`'safe'` at render.
- **Real V8 risk** is keyed by `scope_id`; `riskScore`, `riskTier`, `riskFactors (factor_breakdown)` come straight from `/risk` (fallback baseline only if a rule has no assessment row: `action==='deny'?5:20`). Device risk uses the backend's `0.6*max + 0.4*avg(top5) + modifier` blend, not a mean.
- `vendorMeta(name)` canonicalises vendor identity to stable ids `'palo-alto' | 'fortinet' | 'cisco'` with abbr/accent/OS-prefix (`PAN-OS`/`FortiOS`/`ASA`), fixing earlier slug bugs.
- Derived collections: `conflicts` (relational anomaly types paired via `related_rule_id`, incl. cross-device), `zones` (derived from rule `src/dst_zone_interface` + matched `*_NET` CIDR objects; `subnet` null when not derivable), `assets` (monitored = private `/32`/`/128` host objects, deduped by IP, zoned by subnet containment; `os: null` — config carries no OS), `externalNodes` (Volume-9 CTI malicious indicators correlated to devices via `threat_exposure` evidence), and a synthetic `activityFeed` (`buildActivityFeed`) built from real findings/anomalies/last-scan.
- Threat data: `GET /api/v1/threat-intel/findings?page_size=100`, `/threat-intel/dashboard/stats`, `/cti`. `meta` carries live scan KPIs; `usingMockThreats` is `true` when no scan findings exist (UI shows a "run a scan" notice; it does **not** fall back to fabricated threats).
- Also exported from `api.js` (imperative triggers used by `.jsx` screens): `triggerRulesSync(deviceId)` → `POST /devices/{id}/sync`; `triggerDeviceAnalysis(deviceId)` → `POST /rules/device/{id}/analyze`; `updateAnomalyStatus(id,status,reason)` → `PATCH /anomalies/{id}`; `fetchThreatReports`, `fetchThreatReportDetail`, `triggerThreatScan` (threat-intel scans); and `subscribeThreatScanProgress(reportId,onEvent)` which opens an **`EventSource`** SSE stream `GET /threat-intel/scans/{id}/stream` and auto-closes on `SUCCESS`/`FAILED`/`done`.

**(B) Typed client — `src/lib/api.ts` (TS).** The "new single source of truth" for all new screens. Structure:
- A generic `request<T>(path, init)` over `BASE='/api/v1'`, with `get`/`post`/`patch` helpers, a `qs()` query builder, an `ApiError` class (carries `status` + `body`), and 204/empty-body → `null` handling.
- Shared union types: `Severity`, `RiskTier`, `DetectionMode` (`config_only | conditional | simulated | cti | future_enhanced`), `AnomalyStatus` (`open | resolved | suppressed | accepted_risk | false_positive`).
- Typed interfaces mirroring backend rows: `Vendor`, `Device`, `Rule`, `NetworkObject`, `RuleObjectMapping`, `Anomaly`, `Paged<T>`, `AnomalyRun`, `RiskItem`/`RiskList`/`RiskFactorBreakdown`, `BenchmarkCase`/`BenchmarkReport`/`BenchmarkMetrics`/`BenchmarkRunResult`, `CtiIndicator`/`CtiObservation`/`CtiRunResult`, `ReportSummary`/`ReportDetail`.
- Grouped endpoint objects: `anomalies` (`list/get/runs/run/updateStatus`), `risk` (`list/run`), `benchmark` (`report/run`), `cti` (`list/run`), `reports` (`list/get/generate`), and `inventory` (`vendors/devices/rules/networkObjects/ruleObjects/ruleAnomalies/syncDevice/analyzeDevice`). Default export aggregates them as `api`.

**Migration mechanics (`tsconfig.json`):** `target ES2022`, `module ESNext`, `moduleResolution bundler`, `jsx react-jsx`, `strict: true`, `noEmit: true`. Critically `allowJs: true` / `checkJs: false`, with a comment stating legacy `.js/.jsx` keep working un-type-checked while new code is authored in `.ts/.tsx`; Vite/esbuild transpiles TS regardless. So legacy `.jsx` and new `.tsx` coexist in one tree, `tsc --noEmit` only type-checks the typed surface, and `vite-env.d.ts` is just `/// <reference types="vite/client" />`. New screens authored in `.tsx`: **risk, reports, cti, benchmark** (all import from `lib/api.ts`). All other screens remain `.jsx` and consume `LFPMContext`/`api.js`.

### 8.5 Shell, Navigation Chrome & Global Widgets

- **`src/shell.jsx`** — `Rail` (icon nav for the 8 pages + a Help item; Audit shows `criticalCount` badge), `Topbar` (tenant switcher "NovaTech Industries", breadcrumb, ⌘K search button, time-range button, notifications, **Sync** button, theme toggle, user menu; the Sync button fans `triggerRulesSync` across `data.firewalls` via `Promise.allSettled` then `refreshData`), and `StatusBar` (terminal-style footer: connection, region/env, live "last sync" from `meta.lastScanAt`, UTC clock, hard-coded `build v2.4.1+8a91c2`). Also exports a small hand-drawn `Sparkline`.
- **`src/menus.jsx`** — a module-level toast event bus exposing the global `window.toast(titleOrOpts, opts)`, the `<ToastHost/>` renderer, and popovers `UserMenu / NotifMenu / TenantMenu / TimeRangeMenu`. These popovers are registered on `window` (`Object.assign(window, {...})`) because `Topbar` renders them as `window.TenantMenu` etc.; without registration the dropdowns silently render nothing (an explicit fix noted in code). `NotifMenu` is real-data-driven (top of `activityFeed`); Tenant/TimeRange are cosmetic/UI-only. A `useOutsideClick` hook handles outside-click + Escape.
- **`src/icons.jsx`** — `Icons`, a hand-authored SVG icon set (`<Icon>` wrapper, 24×24 viewBox, stroke-based), also assigned to `window.Icons` for "backward compat"; nearly every component reads `const I = window.Icons`.
- **`src/palette.jsx`** — `CommandPalette` (⌘K) global search/jump. Empty query shows "jump to" + recent searches; a typed term filters `policies` (rules), `firewalls`, `threats` (CVEs), `assets` (hosts) from context, grouped, with arrow-key navigation; Enter on a result either navigates (`jump`) or opens the inspector (`rule/firewall/cve/host`).

### 8.6 Screens — Responsibility & Data Source

| Screen | File | Source | Real vs mock |
|---|---|---|---|
| Dashboard / Overview | `dashboard.jsx` | `LFPMContext` (api.js) | **Real**: V8 fleet/vendor/device risk, anomaly-type distribution from current findings, live `meta` scan KPIs, conflicts, activity feed. "run audit" fans `triggerDeviceAnalysis` across the fleet. Trend line uses `hits24h` (mock-seeded) shaped by `TIME_RANGES`. |
| Policy Audit | `audit.jsx` | `LFPMContext` | **Real**: run-scoped per-rule anomalies, severity-based status, V8 risk; faceted filters (saved views, severity, vendor, firewall, action, min-risk slider), sort, CSV export, deep-link `intent` application, "run audit". Row click → inspector. |
| Inspector (slide-over) | `inspector.jsx` | `LFPMContext` + `updateAnomalyStatus` | **Real** for rule/firewall/cve/zone/host/external/path detail. `AnomalyCard` exposes the **analyst lifecycle**: `resolve / false_positive / accept_risk` → `PATCH /anomalies/{id}` (reason prompted for the latter two). `HostDetail`'s "recent activity" list is hardcoded mock; FirewallDetail "last sync 14:32:08 UTC" is hardcoded. |
| Risk Posture | `risk.tsx` | `lib/api.ts` (`risk`, `inventory`) | **Real**: device-risk cards + top-risky-rules table, deterministic V8 with `factor_breakdown` chips, tier legend (90–100/70–89/40–69/1–39). Row → `goTo('audit',{rule})`. |
| SOC Reports | `reports.tsx` | `lib/api.ts` (`reports`, `inventory`) | **Real**: `reports.list/get/generate` (`executive` or per-`rule`); LLM explains deterministic findings, never detects; renders `evidence_refs`, `confidence_note`, status, and a dependency-free markdown renderer (`renderMarkdown`/`inlineBold`). Handles `failed` status (provider unavailable, V10 §11). |
| CTI / Threat Center | `cti.tsx` (`CtiCenter`) | `lib/api.ts` (`cti`, `anomalies`) | **Real**: indicator table (provider verdict, threat type, confidence) + affected ALLOW rules joined from `threat_exposure` anomalies; "run enrichment" → `cti.run()`. Rendered as the **indicators tab inside `threats.jsx`**, not a standalone page. |
| Benchmark Center | `benchmark.tsx` | `lib/api.ts` (`benchmark`) | **Real** acceptance gate: `benchmark.run()` then `benchmark.report()` (sequential — `run` rewrites rows, so `report` must wait, with a StrictMode double-invoke guard `started.current`). Shows precision/recall/F1/severity-match, tp/fp/fn, per-type coverage, per-case TP/FN matrix. |
| Topology | `topology.jsx` | `LFPMContext` | **Real** data (firewalls, zones, assets, CTI threat vectors/edges), **hand-rolled static SVG** layout (see §8.10). Focus mode, severity edge filter, layer toggles, SVG export, deep-link `?device=`. |
| Threat Intelligence | `threats.jsx` | `api.js` threat fns + `LFPMContext` + `CtiCenter` | **Real**: three tabs — *latest scan* (report picker, SSE progress, clean/action hero, narrative, findings table; "run threat scan" → `triggerThreatScan` + SSE), *advisories* (filterable CVE feed: severity/exploit/vendor/KEV/relevance, source lanes clearnet vs Tor dark-web), *indicators* (`CtiCenter`). This is the LTI / CVE-scan feature. |
| Settings | `settings.jsx` | `LFPMContext` + `triggerRulesSync` | **Mixed** (see §8.8). |
| Login | `login.jsx` | `LFPMContext` (`users` from data.js) | **Cosmetic mock gate** (see §8.9). |

### 8.7 Dashboard internals (de-mocked KPIs)

`dashboard.jsx` is the most data-dense `.jsx` screen and is explicitly de-mocked:
- Five clickable hero KPIs deep-link into filtered views: **avg fleet risk** (mean of real per-device V8 risk, not rule-mean), **open issues** (`status!=='clean'`), **critical CVEs**, **fleet online** (`x/total`), **threat findings** (`meta.totalFindings`/new/correlated).
- `charts` memo builds: a risk-trend line (hand-drawn `TrendChart` SVG with hover crosshair), a real anomaly-type distribution colored by worst severity (`HBars`), and vendor-risk tiles built **from vendors actually present** in the fleet (no longer hardcoded PA/FT; Cisco appears if present), guarding the average against divide-by-zero (no NaN).
- Tables: firewall fleet (sorted by real device risk), top risky rules, active advisories, cross-vendor conflicts — every row is a context-aware `goTo` navigation. A collapsible `ActivityColumn` groups priority alerts first. Risk colouring comes from `LFPM.fmt.riskColor/riskLabel` (thresholds 80/60/40/20) in `data.js`.

### 8.8 Settings — real vs mock breakdown

`settings.jsx` is labelled a **"read-only demo"** admin console (a `read-only demo` chip in the header). Tabs and their reality:

| Tab | Status |
|---|---|
| **Connectors → firewall fleet** | **REAL**: rows from `data.firewalls`; per-device **Sync** and **Sync all** buttons call `triggerRulesSync` + `refreshData`. (Endpoint URLs `https://{ip}/api/v1` and "api-key · rotated 3d ago" labels are cosmetic.) |
| Connectors → threat-intel feeds | **Mock**: hardcoded NVD/CISA-KEV/PA-PSIRT/Fortinet-PSIRT/MITRE rows. |
| Analyzer schedule | **Mock**: hardcoded cron rows (e.g. `*/15 * * * *`). |
| Notifications | **UI-only**: 8 routing rules toggled and persisted in `localStorage` (`lumina_notif_rules`); no backend. |
| Access & roles | **Mock** (members from `data.js users`, session policy text). |
| API & secrets | **Mock** tokens; "create token" downloads a client-side JSON; "open api docs" opens `/docs` (FastAPI Swagger). |
| Audit log | **Mock** rows. |
| About | **Mock** build/version strings. |

### 8.9 Login — cosmetic mock gate

`login.jsx` is a **purely cosmetic gate; the backend has no auth route.** It simulates credential → MFA → success (or a WebAuthn alt path) with `setTimeout` delays and a fake terminal "auth-gateway" log. Accepted demo creds: any email in `LFPM.users` (`data.js`), password `'demo'`, MFA `'123456'`. On success it calls `onLogin(user)` which just sets `App`'s `user` state (persisted to `sessionStorage`). The "POST /v1/auth/password", "jwt minted", IP-allowlist, SSO/Okta strings are decorative. No token is sent on any API request; the dev proxy reaches an unauthenticated backend.

### 8.10 Known Off-Spec / Divergences (state plainly)

1. **Topology is a hand-rolled static SVG, not Cytoscape.** `topology.jsx` lays out a single `<svg viewBox="0 0 1280 600">` on a fixed `TOPO` geometry grid (lane positions, zone/asset stacking computed in JS). `cytoscape`, `cytoscape-dagre`, and `react-cytoscapejs` are installed but **never imported**. Consequence: **nodes are not draggable**; interaction is limited to hover tooltips, click-to-focus (dim others), a severity edge filter, layer toggles, and SVG export. Layout does not auto-route or re-flow.
2. **Login is a cosmetic mock** with no backend auth (§8.9).
3. **Benchmark Center is an internal QA/acceptance tool shown in the customer UI.** `benchmark.tsx` scores the engine against the ground-truth matrix (precision/recall/F1) — a regression guard, surfaced as a first-class nav item alongside customer features.
4. **Cisco / CVE remnants persist though v1 = FortiGate + Palo Alto only.** `vendorMeta` still maps `cisco`→`ASA`; device-model inference includes `'Cisco ASA 5500-X'`; the topology/dashboard/threats vendor filters include a `cisco` lane/chip; `deriveVendors`/`isKev` parse Cisco/ASA keywords. These are dormant code paths for an out-of-scope vendor.
5. **"Monitored assets" derive from `/32` (and `/128`) host objects.** In `api.js`, `assets` = private single-host CIDR network-objects, deduped by IP, zoned by subnet containment; `os` is always `null` (firewall config carries no OS). Hosts behind un-derivable interfaces (e.g. FortiGate `PORTx`) are left unzoned.
6. **Other installed-but-unused deps:** `recharts` (charts are hand-drawn SVG in `dashboard.jsx`), `react-router-dom` (routing is the hand-rolled hash router in `app.jsx`), `lucide-react` (icons are hand-authored in `icons.jsx`).
7. **Reliance on `window` globals.** `Icons`, `toast`, the four topbar menus, and `useOutsideClick` are attached to `window` and consumed via `window.*`. This is load-bearing (the topbar dropdowns broke until the menus were explicitly registered) and atypical for a React app.
8. **Cosmetic/hardcoded chrome:** build string `v2.4.1+8a91c2` (StatusBar/login/About), the "NovaTech Industries · prod · eu-west-1" tenant, `HostDetail` recent-activity, and several "last sync" timestamps are static and not backed by the API.

---

## 9. Build, Setup & Deployment

This section is grounded in the repository's `docker-compose.yml`, `.env.example`, `backend/Dockerfile`, `backend/entrypoint.sh`, `frontend/Dockerfile`, `frontend/nginx.conf`, `frontend/vite.config.js`, `backend/core/config.py`, the Alembic configuration (`backend/alembic.ini`, `backend/alembic/env.py`), the lab provisioner (`lab/*`), `docs/SESSION_HANDOFF.md`, and the deployment spec `Volumes/_extracted/LuminaFPM_Volume_13_Deployment_and_Operations_Architecture.txt` (hereafter "V13"). Where the implementation diverges from the spec, this is flagged explicitly.

### 9.1 Deployment model overview

LuminaFPM v1 is deployed as a **Docker Compose** stack (V13 §2, Table 1; Kubernetes is explicitly future work). The whole stack is brought up with a single command from the repository root:

```bash
docker compose up -d
```

This starts the runtime services (`db`, `redis`, `api`, `celery_worker`, `frontend`) plus an optional `tor-proxy`. The canonical application is then reachable at **http://localhost:5173** (the dockerized Vite dev server, which proxies `/api/v1` → `api:8000`), and the backend API directly at **http://localhost:8000** (`docs/SESSION_HANDOFF.md`, "How to resume the running environment").

The platform is **strictly read-only against firewalls**: the running services never write to FortiGate/Palo Alto. Writing benchmark policy into the lab is a separate operator action performed by the `lab/` provisioner using *separate write-capable credentials* (see §9.7).

**Spec-vs-implementation divergences worth noting:**
- V13 (Table 2, Table 3) envisions **separate Celery worker containers per job type** (`lumina-worker-acquisition`, `-normalization`, `-analysis`, `-cti`, `-reporting`). The actual `docker-compose.yml` ships a **single `celery_worker` container** that consumes all routed queues (`-Q acquisition,normalization,analysis,cti,reporting,celery`). The queue separation exists at the routing level, not the container level.
- V13 (Table 2) calls for the React build to be "served by Nginx." The compose stack runs the frontend as a **Vite dev server** (`npm run dev -- --host`). An `frontend/nginx.conf` and an Nginx-based production serving path exist as artifacts but are **not wired into `docker-compose.yml`** (the `frontend/Dockerfile` is a Node dev image, not a multi-stage Nginx build) — see §9.5.
- V13 §6 shows `DATABASE_URL=postgresql+psycopg://...`; the implementation uses the plain `postgresql://...` driver prefix in both `.env.example` and `core/config.py` defaults.

### 9.2 Service-by-service description (from `docker-compose.yml`)

| Service | Image / build | Host ports | Internal expose | Volumes | depends_on | Healthcheck | env_file / env |
|---|---|---|---|---|---|---|---|
| `db` | `postgres:16-alpine` | none (host port commented out) | `5432` | `postgres_data:/var/lib/postgresql/data` | — | `pg_isready -U $POSTGRES_USER -d $POSTGRES_DB`, interval 5s/timeout 5s/retries 10 | `env_file: .env` |
| `tor-proxy` | build `./tor-proxy/Dockerfile` | `9050:9050` | — | — | — | none | — |
| `redis` | `redis:7-alpine` | none (commented out) | `6379` | `redis_data:/data` | — | `redis-cli ping`, interval 5s/timeout 3s/retries 10 | — |
| `api` | build `./backend/Dockerfile` | `8000:8000` | — | `./backend:/app` (live-reload bind mount) | `db` (service_healthy), `redis` (service_healthy) | none | `env_file: .env`; env `LTI_TOR_SOCKS_HOST=tor-proxy`, `LTI_TOR_SOCKS_PORT=9050`; `dns: 8.8.8.8, 1.1.1.1` |
| `celery_worker` | build `./backend/Dockerfile` | none | — | `./backend:/app` | `db` (service_healthy), `redis` (service_healthy) | none | `env_file: .env`; same `LTI_TOR_*` env + DNS |
| `frontend` | build `./frontend/Dockerfile` | `5173:5173` | — | `./frontend:/app`, `frontend_node_modules:/app/node_modules` | `api` | none | env `CHOKIDAR_USEPOLLING=true`, `VITE_API_PROXY=http://api:8000` |

Named volumes declared at the bottom of the file: `postgres_data`, `redis_data`, `frontend_node_modules`.

**Per-service notes:**

- **`db` (PostgreSQL 16):** Not exposed to the host by default (the `ports: 5432:5432` mapping is commented out per V13 §12 / Table 4 — Postgres is internal-only); other services reach it via the Docker network name `db:5432`. The host port can be uncommented for local debugging. Data persists in the `postgres_data` named volume — this means **a fresh device starts with an empty DB** (`docs/SESSION_HANDOFF.md`, "Environment caveats").

- **`redis` (Redis 7):** Also internal-only (host port commented out, V13 Table 4). Serves as the Celery broker and result/queue backend; persists to `redis_data`.

- **`tor-proxy`:** Built from `./tor-proxy/`, publishes SOCKS port `9050`. This supports **future/optional dark-web CTI** only (ADR LFPM-IMPL-005). It is not required for normal operation; the API/worker reach it via `LTI_TOR_SOCKS_HOST=tor-proxy` injected in their `environment`.

- **`api` (FastAPI):** Built from `backend/Dockerfile` (Python 3.11-slim base; installs `tor`, `build-essential`, `curl`, `libssl-dev`, `libffi-dev`, then `pip install -r requirements.txt`). The compose file overrides the image CMD with an inline entrypoint: `["/bin/sh","-c","chmod +x ./entrypoint.sh && exec ./entrypoint.sh"]`. The whole `./backend` tree is bind-mounted to `/app` for live code mirroring. `depends_on` uses `condition: service_healthy` so the API starts only after Postgres and Redis pass health checks. Custom DNS (`8.8.8.8`, `1.1.1.1`) is set so outbound calls to CTI/LLM providers resolve.

  The actual startup sequence is in `backend/entrypoint.sh`:
  1. *(optional)* If `ENABLE_DARKWEB_INTEL=true` and `tor` is present, start Tor best-effort (failure is non-fatal; it `WARNING`s and continues). Default deployments skip this.
  2. **`alembic upgrade head`** — runs DB migrations; **fatal on failure** ("the app must not start against an unmigrated schema").
  3. `exec uvicorn main:app --host 0.0.0.0 --port 8000`.

  Note: uvicorn here runs **without `--reload`**, despite the compose comment claiming live-reload; the bind mount mirrors code but the API process must be restarted to pick up changes (an inline `command:` with `--reload` is present but commented out).

- **`celery_worker`:** Same image as `api`. Overrides `command:` to wrap Celery in `watchmedo auto-restart` (from the `watchdog` package) so the worker reloads on `*.py` changes — the worker has no native `--reload`, and stale in-memory code was the documented cause of null `clean`/`coverage_note` in early scans. It runs `celery -A celery_app.celery worker --loglevel=info -Q acquisition,normalization,analysis,cti,reporting,celery`. The explicit `-Q` list is required: `task_routes` send work to per-job-type queues, and without listing them a single worker would only drain the default `celery` queue (so acquisition/normalization/analysis tasks would never execute).

- **`frontend` (React/Vite):** Built from `frontend/Dockerfile` (`node:22-slim`, `npm install`, `EXPOSE 5173`, default CMD `npm run dev -- --host`). Compose runs the same `npm run dev -- --host`. Two volumes: the `./frontend` bind mount for live editing, and the **`frontend_node_modules` named volume** mounted at `/app/node_modules` — the "trap killer" that prevents a host (Windows) `node_modules` from shadowing the Linux container's installed modules. `CHOKIDAR_USEPOLLING=true` forces file-change detection on Windows hosts. `VITE_API_PROXY=http://api:8000` directs the Vite dev-server proxy at the backend by service name.

The two `robin_*` (dark-web OSINT) services are present but **fully commented out** in `docker-compose.yml`.

### 9.3 Vite dev-server proxy

`frontend/vite.config.js` configures a single proxy rule: `'/api/v1'` → `process.env.VITE_API_PROXY || 'http://localhost:8000'`, with `changeOrigin: true`. In Compose, `VITE_API_PROXY=http://api:8000`; on a bare host (`npm run dev`) the variable is unset and it falls back to the published backend port `http://localhost:8000`.

### 9.4 Environment-variable reference

The single source of truth at runtime is `backend/core/config.py` (a pydantic-settings `Settings` class with an `os.getenv` fallback if `pydantic-settings` is not installed). Template values are in `.env.example`. **`.env` is gitignored and must never be committed; all secrets come from the environment only** (Volume 12 §6; `.env.example` header).

`Settings` loads `env_file=".env"` with `extra="ignore"`, so variables present in `.env`/compose but not declared in `Settings` (e.g. the `LTI_*`, `OPENAI_*`, `AGENTROUTER_*` keys) are accepted but **not consumed by `core/config.py`** — they are read, if at all, by their own subsystem modules (LTI/Robin), which are future/optional.

#### Core variables consumed by `core/config.py`

| Variable | Purpose | Default / example | Required? |
|---|---|---|---|
| `ENVIRONMENT` | `development` \| `lab` \| `staging` \| `production`; drives `is_production` | `development` | optional |
| `LOG_LEVEL` | Log verbosity | `INFO` | optional |
| `DATABASE_URL` | PostgreSQL DSN | `postgresql://lumina:lumina@db:5432/lumina_fpm` | **required** (has default) |
| `POSTGRES_USER` | Postgres role (used by `db` image + healthcheck) | `lumina` | **required** for `db` |
| `POSTGRES_PASSWORD` | Postgres password — **secret** | `change-me` (never ship the default) | **required**; secret |
| `POSTGRES_DB` | Database name | `lumina_fpm` | **required** for `db` |
| `REDIS_URL` | Celery broker / cache URL | `redis://redis:6379/0` | **required** (has default) |
| `SECRET_KEY` | Session/JWT signing — **secret** | `change-me-generate-a-long-random-string` | **required**; secret |
| `ENCRYPTION_KEY` | **Fernet** key encrypting stored device credentials (`device_credential` table) | empty; generate via `python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"` | **required to use stored creds**; secret. Must match the key that encrypted existing credentials or they will not decrypt |
| `CORS_ALLOWED_ORIGINS` | Comma-separated allowlist (aliased to `cors_allowed_origins_raw`; parsed by `cors_allowed_origins` property) | `http://localhost:5173`; never `*` with credentials | optional |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Token TTL | `30` | optional |
| `FIREWALL_TLS_VERIFY` | Verify firewall TLS certs (set `false` in lab for self-signed certs) | `true` | optional |
| `FIREWALL_INSECURE_HTTP_HOSTS` | **LAB-ONLY** comma-separated mgmt IPs polled over plain HTTP because their HTTPS admin service is down (e.g. lab FortiGate `.10`). Sends API token unencrypted — **leave empty in production** | empty | optional (lab only) |
| `ACQUISITION_RAW_DIR` | Where raw firewall output is stored | `/app/raw_acquisition` | optional |
| `ACQUISITION_TIMEOUT_SECONDS` | Per-poll timeout | `60` | optional |
| `ACQUISITION_MAX_RETRIES` | Poll retry count | `3` | optional |
| `LLM_PROVIDER` | LLM provider abstraction: `gemini` \| `openai` \| `ollama` | `gemini` | optional |
| `LLM_MODEL` | Model id | `gemini-2.5-flash` | optional |
| `LLM_API_KEY` | LLM provider key — **secret** | empty / `your_provider_api_key_here` | required for live LLM; secret |
| `OLLAMA_BASE_URL` | Ollama endpoint when `LLM_PROVIDER=ollama` | `http://ollama:11434` | optional |
| `CTI_PROVIDER_KEYS` | Provider-parsed CTI keys, e.g. `abuseipdb=...,virustotal=...,otx=...` — **secret** | empty | optional (offline lab provider used if empty); secret |
| `CTI_ALLOW_INTERNAL_INDICATORS` | If `false`, never send RFC1918/internal indicators to external CTI providers (data minimization, V9 §4 / V12 §10) | `false` | optional |
| `ENABLE_DARKWEB_INTEL` | Feature flag for future/optional dark-web/Tor/Robin intel (ADR LFPM-IMPL-005) | `false` | optional (future) |

#### Variables present in `.env.example`/compose but NOT consumed by `core/config.py`

These belong to the LTI/Robin (Lumina Threat Intel) and alternate-LLM subsystems, which are **future/optional**. They are accepted by `Settings` (`extra="ignore`") and read, where used, by their own modules. Treat keys/tokens as **secrets** that must never be committed.

| Variable | Subsystem / purpose | Default / example | Status |
|---|---|---|---|
| `OPENAI_API_KEY` | OpenAI key (alt LLM) — secret | `your_openai_api_key` | optional/future |
| `ANTHROPIC_API_KEY` | Anthropic key — secret | `your_anthropic_api_key` | optional/future |
| `GOOGLE_API_KEY` | Google/Gemini key — secret | `your_google_api_key` | optional/future |
| `OPENROUTER_BASE_URL` / `OPENROUTER_API_KEY` | OpenRouter LLM gateway — key is secret | placeholders | optional/future |
| `LLAMA_CPP_BASE_URL` | llama.cpp endpoint | placeholder | optional/future |
| `LTI_LLM_PROVIDER` / `LTI_LLM_MODEL` / `LTI_LLM_API_KEY` | LTI engine LLM config — key is secret | `gemini` / `gemini-2.5-flash` / placeholder | optional/future |
| `ROBIN_MODEL` | Robin OSINT engine model | `gemini-2.5-flash` | optional/future |
| `LTI_LLM_TIMEOUT_SECONDS` / `LTI_LLM_MAX_RETRIES` | LTI LLM resilience | `120` / `3` | optional/future |
| `LTI_TOR_SOCKS_HOST` / `LTI_TOR_SOCKS_PORT` | Tor SOCKS endpoint (compose sets host=`tor-proxy`, port `9050`; `.env.example` defaults host=`tor`) | `tor` / `9050` | optional/future |
| `LTI_SCRAPE_PAGE_TIMEOUT_SECONDS` / `LTI_SCAN_TOTAL_TIMEOUT_SECONDS` | Dark-web scrape timeouts | `60` / `900` | optional/future |
| `LTI_RATE_LIMIT_PER_USER_HOUR` / `LTI_RATE_LIMIT_PER_TENANT_DAY` | LTI rate limits | `10` / `50` | optional/future |
| `AGENTROUTER_BASE_URL` / `AGENTROUTER_TOKEN` | Agent Router gateway — token is secret | `https://agentrouter.org/` / placeholder | optional/future |

**Secrets that must never be committed:** `POSTGRES_PASSWORD`, `SECRET_KEY`, `ENCRYPTION_KEY`, `LLM_API_KEY`, `CTI_PROVIDER_KEYS`, all `*_API_KEY`/`*_TOKEN` values. Device API credentials are **not** stored in env at all — they live encrypted (Fernet) in the `device_credential` table (V3 §6.2).

A minimal working lab `.env` (per `docs/SESSION_HANDOFF.md`) sets: `DATABASE_URL`, `POSTGRES_*`, `SECRET_KEY`, `ENCRYPTION_KEY`, `LLM_API_KEY` (working Gemini key), `LLM_PROVIDER=gemini`, `LLM_MODEL=gemini-2.5-flash`, `FIREWALL_TLS_VERIFY=false`, `FIREWALL_INSECURE_HTTP_HOSTS=192.168.55.10`, optionally `CTI_PROVIDER_KEYS=abuseipdb=...`.

### 9.5 Frontend production serving (Nginx) — present but not wired

`frontend/nginx.conf` defines an SPA-serving server block: `listen 80`, `root /usr/share/nginx/html`, SPA fallback `try_files $uri $uri/ /index.html`, and a 1-year immutable cache header for static assets (`js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot`). This matches V13's "React build served by Nginx" intent (Table 2). **However**, the shipped `frontend/Dockerfile` is a Node 22 dev image running the Vite dev server, and `docker-compose.yml` runs that dev server — there is **no multi-stage build that produces a static bundle and copies it into an Nginx image**, and no Nginx service in compose. The Nginx config is therefore a prepared-but-unused artifact for a future production path. This should be flagged plainly: **as built, the frontend runs as a development server, not a production Nginx build.**

### 9.6 Database migrations (Alembic)

Schema is migration-managed (V5 §14, V13 §7); destructive auto-sync is forbidden. Configuration:

- **`backend/alembic.ini`:** `script_location = alembic`, `prepend_sys_path = .`, `path_separator = os`. Crucially, `sqlalchemy.url` is **left blank** so no secret lives in the file; it is injected programmatically at runtime.
- **`backend/alembic/env.py`:** Inserts the backend dir on `sys.path`, imports `models.models.Base` (registering all Schema v4 tables), and best-effort imports the still-wired LTI tables (`services.lumina_threat_intel.db_models`, guarded so a missing optional dep cannot break migrations — these tables are slated for demotion per ADR LFPM-IMPL-005). It then resolves the DB URL from `core.config.settings.database_url`, falling back to `os.getenv("DATABASE_URL", "postgresql://lumina:lumina@db:5432/lumina_fpm")` if the config import fails, and sets it via `config.set_main_option("sqlalchemy.url", _DB_URL)`. `target_metadata = Base.metadata` enables autogenerate; both offline and online modes set `compare_type=True`; online uses `pool.NullPool`.

Migrations run automatically on API startup via `entrypoint.sh` (`alembic upgrade head`, fatal on failure). To run them manually inside the container: `docker compose exec api alembic upgrade head`. V13 §7 additionally calls for seeding the initial vendors (Fortinet, Palo Alto Networks) and version-controlling migration history.

### 9.7 Host dev-preview path (Vite on 5175)

Independent of Compose, the frontend can be previewed directly on the host for Claude's preview tooling. `.claude/launch.json` defines a `frontend` configuration that runs `npx vite frontend --port 5175` (fixed port, `autoPort: false`). Setup: `cd frontend && npm install`, then launch via `.claude/launch.json`. Because `VITE_API_PROXY` is unset on the host, the Vite proxy (`vite.config.js`) defaults its `/api/v1` target to `http://localhost:8000` — i.e. the host-published backend port. (Compose, by contrast, sets `VITE_API_PROXY=http://api:8000` and serves on 5173.) Typecheck on the host: `cd frontend && npx tsc --noEmit` (only `.ts/.tsx` are checked; `.jsx` remains under `allowJs`).

### 9.8 Lab benchmark provisioner (write tooling — NOT part of the platform)

The `lab/` directory is **operator tooling that writes** the phase-1 benchmark policy set to the controlled VMware lab firewalls so the deterministic anomaly engine has data to detect (Volume 7 §13). It is **not part of the read-only LuminaFPM platform** and must be run with a **separate write-capable credential**, never the read-only token Lumina stores (`lab/README.md`).

**Components:**

- **`lab/benchmark_dataset.py`** — the logical rule specs plus design ground truth:
  - `FORTIGATE_RULES`: 13 rule dicts (list order = rule evaluation order, which matters for shadowing/redundancy/conflict). Each carries `name`, logical zones (`LAN`/`DMZ`/`DB`/`ANY`), `src`/`dst`/`service`, `action`, `logging`, `inspection`, `schedule`, `description`, `enabled`, an `expected` list of intended anomaly types, and `severity`.
  - `PALOALTO_RULES`: 8 rule dicts with the analogous shape.
  - `CROSS_DEVICE_PAIRS`: cross-device ground-truth pairs by rule name (e.g. `FGT_DB_ACCESS_XDEV`/`PA_DB_ACCESS_XDEV` → `cross_device_inconsistency`; `FGT_REDUNDANT_WEB`/`PA_ALLOW_WEB` and `/PA_DUP_WEB` → `cross_device_security_posture_inconsistency`).
  - All referenced address/service objects (`LAN_NET`, `DMZ_NET`, `DB_NET`, `WEB_SERVER(_2)`, `DB_SERVER(_2)`, `ADMIN_PC`, `MALICIOUS_IP`, services `HTTP/HTTPS/SSH/MYSQL/RDP/ALL/ALL_TCP/DNS`) are assumed to already exist in the lab baseline.

- **`lab/provision_benchmark.py`** — translates the specs to vendor payloads and (optionally) pushes them:
  - Logical-zone → vendor maps: `FGT_INTF = {LAN:port1, DMZ:port2, DB:port3, ANY:any}`, `PAN_ZONE = {LAN:trust, DMZ:dmz, DB:db, ANY:any}` (confirmed against the lab: PAN zones `trust`=eth1/1, `dmz`=eth1/2, `db`=eth1/3).
  - `build_fgt_payload(r)` builds a FortiGate REST body (POST `/api/v2/cmdb/firewall/policy`); inspection-ON rules add `utm-status=enable`, `av-profile=default`, `ssl-ssh-profile=certificate-inspection`.
  - `build_pan_element(r)` builds the PAN-OS XML `set` element. Because the lab PAN-OS has **no security profile group**, the provisioner first creates one (`PAN_PROFILE_GROUP = "lumina-inspect"`) referencing PAN-OS predefined `default` AV/anti-spyware/vulnerability/URL/wildfire profiles + `basic file blocking`, and inspection-ON PAN rules reference it.
  - `apply_fortigate(...)`: GET existing policies, POST each rule (with `--replace` to delete-then-recreate by name). `apply_paloalto(...)`: create profile group, `set` each rule via `type=config&action=set`, then a final `type=commit` `<commit></commit>`.
  - `export_ground_truth(path)`: flattens `expected` per (vendor, rule, order, anomaly type, severity) with `detection_mode="config_only"`, plus `cross_device_pairs`, into `lab/benchmark_ground_truth.json`.
  - **Safety model:** default mode is `--dry-run` (prints payloads, writes ground truth, contacts **no** firewall). Live writes require **both** `--apply` **and** `--confirm`; FortiGate writes require `--fgt-token`/`FGT_WRITE_TOKEN`, PAN writes require `--pan-key`/`PAN_API_KEY`. TLS verification is **off** unless `--verify-tls` (lab certs are self-signed). A `--fgt-scheme http` lab escape hatch exists for the FortiGate whose HTTPS admin service is broken. Host defaults: FGT `192.168.55.10`, PAN `192.168.55.20`.

**Typical lab workflow:**

```bash
# 1. Preview + write ground truth (no network):
python lab/provision_benchmark.py --dry-run --out lab/benchmark_ground_truth.json

# 2. Push benchmark policy to the lab firewalls (WRITE — separate keys, not Lumina):
python lab/provision_benchmark.py --apply --confirm \
  --fgt-host 192.168.55.10 --fgt-token <FGT_WRITE_TOKEN> \
  --pan-host 192.168.55.20 --pan-key <PAN_API_KEY>
```

After provisioning, **LuminaFPM read-syncs**: poll each device in the platform, then `POST /api/v1/anomalies/run` (all-scope) and review findings. The Phase-6 benchmark runner scores the deterministic engine's findings against `benchmark_ground_truth.json` (precision/recall/F1) — the handoff records a live lab run of 2 devices, 20 rules, 54 findings, and benchmark precision/recall/F1 = 100% (47/47).

### 9.9 Device-local caveats (what does NOT transfer across machines)

Per `docs/SESSION_HANDOFF.md`, only the **code** is the durable handoff (pushed to `origin/analyze-project-todo-report`). The following are device-local:

- **`.env`** is gitignored — a new device must create its own from `.env.example` (§9.4). `ENCRYPTION_KEY` in particular must match the key that originally encrypted any stored device credentials, or they will fail to decrypt.
- **The database** lives in the `postgres_data` Docker volume — a fresh machine starts **empty** and must re-sync from the firewalls or re-provision the lab (§9.8) to repopulate.
- **The VMware lab firewalls** are on this host's network only (management `192.168.55.0/24`: FortiGate `.10`, Palo Alto `.20`, host adapter `.1`). Another device must join the same network to poll them live.
- Any read-only poll keys and write provisioner keys exposed in chat should be **rotated** (handoff guidance).

---

## 10. Change Log — Volume-Driven vs Manual Changes

This section separates the changes **Claude (Opus 4.8 / Fable 5) implemented to satisfy the LuminaFPM specification volumes** from the changes the **human team authored by hand** (with or without an AI pair-programmer assist). The discriminator is the `Co-Authored-By` git trailer:

- A commit with `Co-Authored-By: Claude …` (or `Claude Fable 5`) is a **volume-driven / Claude-implemented** change. These are chronicled independently in `docs/EXECUTION_LOG.md` (entries **E-001 … E-029**).
- A commit with **no Claude trailer** — authored by `kandeel679`/`Kandeel679`, `dewa3355`/`dewa35`, `Youssef Hazem`, or `Youssef Kandeel`, and in many cases co-authored by `Cursor <cursoragent@cursor.com>` — is a **manual / hand-made** change. These are documented by the team in the root files `LTI_DEMO_BRIEF.md`, `LTI_OPTIMIZATION_PLAN.md`, `LTI_PROGRESS_AND_FIXES.md`, and `THREAT_INTEL_DEV_REPORT.md`.

> **Method note / caveat on `%an` (author) vs authorship.** The git **author** name is an unreliable signal here, because the Claude-driven backend/frontend phase commits were committed under the human account `Youssef Hazem` while still carrying a `Co-Authored-By: Claude Opus 4.8` trailer (e.g. `9ec2e39`, `ec3928c`). Conversely, several `dewa3355`-authored commits in the LTI work carry a Claude/`Cursor` trailer because they were AI-assisted by hand. Therefore the **trailer**, not the author, is the authoritative discriminator below. Across the **88-commit** branch: **43 commits carry a Claude co-author trailer**, **16 carry a Cursor co-author trailer** (some carry both), and the remainder are purely hand-typed. Author tallies for reference: `dewa3355` 33, `kandeel679`/`Kandeel679` 26, `Youssef Hazem` 23, `Youssef Kandeel` 5, `dewa35` 1.

> **Important ambiguity — "AI-assisted manual" is a grey zone.** A large block of the LTI/threat-intel commits (the `dewa3355` "Phase 1/2/3" series) carry a `Co-Authored-By: Claude …` and/or `Cursor` trailer, yet they are **not** part of the LuminaFPM spec-volume execution (E-001…E-029) — they predate it and belong to the team's separate dark-web threat-intel track, driven interactively by a human (Yassine/`dewa3355`) using Cursor + Claude as a coding assistant. I classify these as **manual/hand-made** for the purpose of this log (subsection 10.2), because they were not produced by the volume-driven LuminaFPM execution and are not recorded in `EXECUTION_LOG.md`. The trailer here reflects an editor/agent assist, not the spec-traceable pipeline build. This is called out plainly rather than silently bucketed.

### Summary table

| Bucket | Author(s) (committer / co-author) | Approx. commit count | What changed |
|---|---|---|---|
| **10.1-A** Backend P0–P9 (spec pipeline) | committed by `Youssef Hazem`, co-author **Claude Opus 4.8** | ~19 | Foundation, Schema v4, acquisition, parsing, normalization, deterministic anomaly engine, benchmark, risk, CTI, LLM reporting + lab/normalization fixes |
| **10.1-B** Frontend P10.0–P10.7 + final pass + fixes | committed by `Youssef Hazem`, co-author **Claude Opus 4.8** | ~12 | TS foundation + typed client, dashboard/audit/anomalies de-mock, Risk/Reports/CTI/Benchmark TSX screens, topology de-mock, `related_rule_id` 500 fix, dropdown/label fixes |
| **10.2-A** LTI / Robin dark-web threat-intel subsystem | `dewa3355` (+ `Cursor`, + `Claude` assist) | ~30 | Dark-web + clearnet threat-intel engine, model router, connectors (CISA KEV, NVD, PSIRT/EPSS), relevance correlation, Robin service |
| **10.2-B** Core platform / architecture (hand-made) | `kandeel679`/`Kandeel679`, `Youssef Kandeel` | ~26 | Initial infra/docker, base DB models + CRUD, "real DB models" refactor, mock-data removal, docker-frontend fixes, `.env.example` template, Tor fix |
| **10.2-C** Demo-readiness frontend (hand-made, AI-assisted) | `dewa3355` (+ `Cursor`/`Claude` assist) | ~6 | Live controls/exports/theme wiring, global spinner, security-key login, Threat-Intel UI tabs, Cisco/vendor-mapping fix |

(Counts are approximate; some commits span buckets, and several `dewa3355` commits carry an AI co-author trailer while remaining hand-driven LTI work — see the ambiguity note above.)

---

### 10.1 Volume-driven changes (Claude-implemented, spec-traceable)

All entries below are recorded in `docs/EXECUTION_LOG.md` and carry a `Co-Authored-By: Claude Opus 4.8` trailer. They implement the LuminaFPM specification volumes (the 14 `Volumes/_extracted/*.txt`) following the V14 phase order. The single landmark backend commit `9ec2e39` ("feat: align codebase to LuminaFPM spec volumes — Schema v4 + read-only acquisition→normalization→anomaly pipeline (Phases 0–5)") folds Phases 0–5 together; later phases land as discrete commits.

#### Backend — Phases P0–P9

| Phase | EXECUTION_LOG entries | Representative commit(s) | What was implemented |
|---|---|---|---|
| **P0 Foundation** | E-001…E-004, E-006 | `9ec2e39` | Spec intake (14 volumes → `Volumes/_extracted/`); `backend/core/{config,logging,security}.py`; Alembic introduced and `Base.metadata.create_all` retired (`alembic/versions/0001_schema_v4_baseline.py`); CORS hardened off wildcard; Postgres/Redis unpublished from host; `.env.example` rewritten to canonical V13 §6 vars |
| **P1 Schema v4** | E-005 | `9ec2e39` | `backend/models/models.py` extended: `network_object`, `policy_rule` (canonical posture fields + `normalized_content_hash`), full `rule_anomaly` V6 contract; **17 new tables** (`normalized_object`, `service_object`, `normalized_service`, `*_normalization_mapping`, `normalization_warning`, `rule_snapshot`, `anomaly_execution_log`, `risk_assessment`, `cti_indicator`, `cti_observation`, `llm_report`, `benchmark_case`, `benchmark_result`, `acquisition_job`, `raw_artifact`, `device_credential`). `configure_mappers()` → 30 tables clean |
| **P2 Acquisition** | E-007, E-011, E-013, E-014 | `9ec2e39`, `34bf706`, `bee447e` | Read-only connectors `services/acquisition/{fortigate,paloalto}.py` (FortiOS REST Bearer GET-only; PAN-OS XML keygen/op/config-show GET-only), `registry.py`, `storage.py` (raw artifacts + SHA-256, replayable); Celery `acquisition.poll_device`; removed the synchronous mock `/sync`; `vendor_type` column + migration `0003`; lab-gated `FIREWALL_INSECURE_HTTP_HOSTS` HTTP escape hatch; worker `-Q` queue fix |
| **P3 Parsing** | E-008 | `9ec2e39` | `services/parsing/{fortigate,paloalto}.py` (defusedxml); real-lab fixtures `fortigate_policy.json` / `paloalto_rulebase.xml`; PAN unqualified-xpath connector fix |
| **P4 Normalization (keystone)** | E-009, E-010 | `9ec2e39`, `7d315a5` | `services/normalization/{canonical,engine,model,persist,loader}.py` — deterministic cross-vendor object/service correlation with confidence (V4 Table 11), canonical action/logging/inspection mapping, predefined-service map, derived `vendor_uuid`, idempotent upsert; migration `0002_rule_service_mapping`; FortiGate `ALL`→canonical ANY fix (`7d315a5`, closes the E-014 shadowing/redundancy gap) |
| **P5 Anomaly engine** | E-010, E-015 | `9ec2e39` | `services/anomaly/{detectors,engine}.py` — deterministic config-only detectors (unprotected_allow, missing_logging, any_to_sensitive, overly_permissive, wide_port_range, missing_description, disabled_rule_review, object_sprawl, duplicate, redundancy, shadowing, conflict, cross_device_inconsistency, cross_device_security_posture_inconsistency). **Deleted the random mock** `services/anomaly_engine.py` and orphaned `mock_connector.py`. Anomaly API `api/routes/anomalies.py` + analyst lifecycle PATCH |
| **P6 Benchmark** | E-016 | `acb307d`, `60f2cdb` | `services/benchmark/{scorer,ground_truth,runner}.py` + `api/routes/benchmark.py`; precision/recall/F1/severity-match at (rule, anomaly_type) granularity; `cross_device_inconsistency` severity high→critical. **Live result: precision/recall/F1 = 1.0, FP 0, FN 0** |
| **P7 Risk** | E-017 | `cb7f5e3` | `services/risk/{scorer,runner}.py` + `api/routes/risk.py`; deterministic 0–100 `risk = min(100, anomaly+exposure+asset_sensitivity+security_posture+logging+cross_vendor+cti+lifecycle)`; tiers 90/70/40/1; device blend `0.6*max + 0.4*avg(top5) + modifier`; `RISK_VERSION 1.0.0` |
| **P8 CTI** | E-018 | `60e3f0b`, `60f2cdb` | `services/cti/{providers,extract,runner}.py` + `api/routes/cti.py`; `AbuseIPDBProvider` + `LabOfflineProvider`; **data minimization** (RFC1918/loopback/link-local/ANY never sent externally); malicious-indicator→ALLOW-rule `threat_exposure` (`detection_mode=cti`) feeding the `cti_score` risk factor |
| **P9 LLM/AI SOC reporting** | E-019 | `0a10f3f`, `9d5685c` | `services/llm/{providers,prompts,reporter}.py` + `api/routes/reports.py`; `GeminiProvider` (default) + `OfflineProvider` fallback; guardrail `SYSTEM_PROMPT` ("explains, never detects"); evidence-grounded `llm_report` with `evidence_refs` DB IDs; cross-vendor CTI correlation fix; `GeminiProvider` hardening (retry 429/503, `thinkingBudget=0`, join parts) |

Supporting lab/migration fixes (still Claude-authored, lab-side only, never writing to firewalls in the platform path): `0e9a5db`, `7e8d558` (PAN security-profile group for benchmark inspection rules), `bee447e` (idempotent migrations 0002/0003 vs the create_all baseline).

#### Frontend — Phase P10 (P10.0–P10.7 + final pass + fixes)

| Sub-phase | EXECUTION_LOG entry | Commit | What was implemented |
|---|---|---|---|
| **P10.0** TS foundation + `related_rule_id` 500 fix | E-020 | `ec3928c` | `frontend/tsconfig.json` incremental TS migration (`allowJs`), typed client `src/lib/api.ts`, env-overridable Vite proxy. **Backend bug fixed:** `RuleAnomalyBase.related_rule_id` typed `Optional[str]` vs int FK → 500; changed to `Optional[int]` in `schemas/pydantic_schemas.py` |
| **P10.1** Dashboard de-mock | E-021 | `142147c` | Removed fabricated heuristic risk; wired real `/api/v1/risk` device/rule V8 scores. Fleet headline 18 "safe" → 98 "critical" |
| **P10.2** Audit + Anomalies | E-022 | `215b936` | Run-scoped rich findings from `/api/v1/anomalies?analysis_run_id=`; severity-based status; analyst lifecycle (resolve/false-positive/accept-risk PATCH); removed the read-only-violating "enable/disable rule" button |
| **P10.3** Risk Posture screen | E-023 | `6d7e5b6` | First fully-TSX screen `src/risk.tsx` against the typed client; device-risk cards + top-risky-rules with V8 factor breakdown |
| **P10.4** Topology de-mock | E-024 | `231914b` | Replaced hardcoded "3 threat vectors"/dead `targetMap` with real `/api/v1/cti` indicators and engine `threat_exposure` targets |
| **P10.5** SOC Reports screen | E-025 | `8858825` | `src/reports.tsx`; generate/list/view evidence-grounded LLM reports with `evidence_refs` DB-ID chips |
| **P10.6** CTI / Threat Center | E-026 | `4277cc5` | `src/cti.tsx` "indicators" tab; enriched indicators + affected rules + data-minimization notice |
| **P10.7** Benchmark Center | E-027 | `3ce9422` | `src/benchmark.tsx` acceptance-gate dashboard; StrictMode race fix (sequential run→report, `useRef` guard) |
| **Final pass** topology assets/zones | E-028 | `99ec9ca` | Real `/32` internal objects → "5 monitored assets" by subnet containment; dropped fabricated OS/zone subnet |
| **Bug fixes** (UX review) | E-029 | `1cb66cb` | `menus.jsx` dropdowns registered on `window.*` (tenant/profile/notifications/time-range); removed overlapping topology band legend |
| **Handoff doc** | (n/a) | `bdaab52` | `docs: add SESSION_HANDOFF for cross-device continuation` |

---

### 10.2 Manual / hand-made changes (human team)

These commits carry **no Claude trailer** (or carry only a `Cursor`/AI-assist trailer on a human-driven LTI track) and are documented by the team in the root `LTI_*` / `THREAT_INTEL_*` markdown files. They were authored **by hand**, both **before** the Claude volume-driven execution began (the entire LTI subsystem and the original platform scaffold predate E-001 on 2026-06-22) and **after** it (e.g. `b63fd69` ".env.example template" on 2026-06-22, interleaved with the backend phase work).

#### 10.2-A — LTI / Robin dark-web threat-intel subsystem

The dark-web + clearnet **Lumina Threat Intel (LTI)** engine and the separate **Robin** AI service are entirely hand-built by the team's AI developer (`dewa3355` / "Yassine", branch `robin/ai_dewa` → `feature/lti-agentic-optimization`), often pair-programmed with **Cursor** and Claude as an editor assist. This subsystem is **out of the LuminaFPM spec-volume scope** (it is the off-direction dark-web/Tor stack flagged as a conflict in `docs/CODEBASE_GAP_ANALYSIS.md` per E-003) and is documented in `THREAT_INTEL_DEV_REPORT.md`, `LTI_OPTIMIZATION_PLAN.md`, `LTI_PROGRESS_AND_FIXES.md`, and `LTI_DEMO_BRIEF.md`.

Representative hand-made commits (author `dewa3355`; trailer where present noted):

| Commit | Message | Trailer |
|---|---|---|
| `2133120`, `1d0551d` | "adding Robin code" / "finished setting the robin containers" | none (`kandeel679`) |
| `1034477` | "Phase 1+2: stack bring-up + LTI agentic workflow optimization" | Claude (assist) |
| `6a63d9b`, `ce7b9a6`, `b56b4ff`, `df7fa5e` | LTI Model Router; AgentRouter / OpenRouter / DeepSeek providers | Claude (assist) |
| `2ee31b2`, `beb5a7b`, `ee5ceea` | clearnet CISA KEV connector, NVD connector, source registry | Claude (assist) |
| `e85e375`, `5f19442`, `9c56225` | version-aware correlation, dark-web source curation (P15), finding relevance band/score | Claude + **Cursor** |
| `e8a4c9c`, `1ccdf36`, `3f3343a` | PSIRT/EPSS/leak-site connectors (P17), full-cycle test assets, P17 hardening | **Claude Fable 5** |
| `90ec064`, `735b8af`, `f910646`, `c948278`, `5d5e5ce`, `0aee8ed` | dark-web scrape-noise dropping, NVD threshold tuning, coverage_note handling | **Cursor** |
| `05e8ee7`, `69ce2ab`, `c20f63f`, `67b8d49`, `4861a3e` | LTI/Robin base code, wiring into main API routes, removing old threat-intel API, Tor fix | none (`kandeel679`) |

This subsystem brings the budget-aware model router (`LTI_BUDGET_USD` $20 soft cap), the two-axis criticality/relevance model, and the Tor `.onion` scraper described in `THREAT_INTEL_DEV_REPORT.md` §4 (10-step pipeline). It remains separate from — and is **not** the spec's API-based CTI (P8, §10.1) which Claude built deterministically.

#### 10.2-B — Core platform / architecture (hand-made foundation)

Authored by hand by `kandeel679`/`Kandeel679` and `Youssef Kandeel` (no AI trailer). This is the original platform skeleton that predated the spec-volume realignment, plus later hand fixes:

| Commit | Author | Message |
|---|---|---|
| `7896f3d`, `2885a00`, `447a6ab` | kandeel679 | "initial infrastructure setup with docker and pr template"; yaml files; docker in README |
| `d983bed`, `bbb6a9d` | kandeel679 | "base database and the crud without testing"; seed_data + schemas folder |
| `31daaed`, `dd0d643` | kandeel679 | "Refactor: Replace mock data logic and migrate components to JSX" |
| `728cec5` | kandeel679 | "added the new frontend with basic functionality" |
| `62850ed` | Kandeel679 | "removing the mock data from" — manual mock-data removal |
| `275a8e4` | Kandeel679 | **"feat(backend, frontend): fix architecture flaws and integrate real DB models"** — a by-hand architecture/DB-model integration pass |
| `66c08bb` | kandeel679 | **"fixing docker frontend problems"** |
| `b63fd69` | Kandeel679 | **"finishing the .env.example template"** — hand-made, dated 2026-06-22, *interleaved with* the Claude backend phases |
| `852da8e`, `eedc3f8`, `c3d9b31`, `d6bddad`, `3ea7388` | kandeel679 | "testing" / "fix working problem" / test sh file / test files NOTE not working yet |
| `d3da1e6`, `bfc0d45`, `bbfbbfb`, `951f474` | Youssef Kandeel | PR merges (#1/#2/#3, robin/ai_dewa merge) |

Note `b63fd69` (`.env.example` template) is a hand-made edit landed **after** Claude had already rewritten `.env.example` to the V13 §6 canonical variables in E-006 (`9ec2e39`), confirming both manual and volume-driven hands touched that file.

#### 10.2-C — Demo-readiness frontend (hand-made, AI-assisted)

Front-end "demo readiness" wiring authored by `dewa3355`, several co-authored by **Cursor** (and some by Claude as an assist on a human-driven branch). Documented under the LTI demo brief:

| Commit | Message | Trailer |
|---|---|---|
| `4dae114` | **"frontend: wire live controls, exports, and theme tokens for demo readiness"** | none (hand-typed) |
| `eef9548` | "frontend: fix inspector toggle re-render, audit spinner, theme tokens" | Claude (assist) |
| `a0fad0f` | "frontend: fix setState-in-render warning from global toast bus" | Claude (assist) |
| `5c54eaf` | "frontend: add global li-spinner for scan and login loading states" | **Cursor** |
| `92ba650` | "frontend: make security key the primary login path" | **Cursor** |
| `eaff944`, `5733a12` | demo-ready Threat Intelligence scan + advisories tabs; LTI scan API helpers | **Cursor** |
| `f43a776` | **"frontend: fix vendor/Cisco mapping + wire dashboard panels to live data"** | Claude + **Cursor** |
| `69a1b58`, `547ec75` | LTI stakeholder demo brief; document LTI progress / handoff notes | **Cursor** |

The `f43a776` "Cisco mapping" fix is hand-made and pre-dates the spec realignment; the **Cisco/ASA removal** itself was driven by the spec (v1 vendors are FortiGate + Palo Alto ONLY) and is reflected in the Claude gap analysis (E-003 flagged "Cisco/ASA seeds" as an obsolete conflict), though the team's NovaTech demo tenant in `LTI_DEMO_BRIEF.md` still seeds a `Cisco ASA 9.18.3` for the LTI demo — an explicit divergence between the LTI demo data and the LuminaFPM v1 vendor scope.

---

**Net distinction.** The deterministic, spec-traceable LuminaFPM core — Schema v4, read-only acquisition, cross-vendor normalization, the deterministic anomaly/benchmark/risk engines, API-based CTI, evidence-grounded LLM reporting, and the TypeScript de-mocked frontend (E-001…E-029) — is **Claude-implemented (volume-driven)**. The dark-web/Tor LTI + Robin subsystem, the original platform scaffold/DB models, docker/frontend fixes, the `.env.example` template, and the demo-readiness UI wiring are **hand-made by the human team**, some with Cursor/Claude acting as an interactive coding assistant on human-driven branches rather than as the spec-execution agent.

Relevant source files for this section (absolute paths):
- `D:\لا تراجع ولا استسلام (القبضة الدامية)\LUMINA\lumina-fpm\docs\EXECUTION_LOG.md`
- `D:\لا تراجع ولا استسلام (القبضة الدامية)\LUMINA\lumina-fpm\THREAT_INTEL_DEV_REPORT.md`
- `D:\لا تراجع ولا استسلام (القبضة الدامية)\LUMINA\lumina-fpm\LTI_DEMO_BRIEF.md`
- `D:\لا تراجع ولا استسلام (القبضة الدامية)\LUMINA\lumina-fpm\LTI_OPTIMIZATION_PLAN.md`
- `D:\لا تراجع ولا استسلام (القبضة الدامية)\LUMINA\lumina-fpm\LTI_PROGRESS_AND_FIXES.md`

---

## 11. Gap Analysis — Implemented vs Diverged vs Outstanding (against the 14 Volumes)

This section compares each of the fourteen specification volumes (`Volumes/_extracted/LuminaFPM_Volume_*.txt`) against the **current** codebase, verified directly against source files (not merely against the prior `docs/CODEBASE_GAP_ANALYSIS.md` / `docs/IMPLEMENTATION_ROADMAP.md`, which predate later manual edits). Status legend: **IMPLEMENTED** = present and faithful to spec; **DIVERGED** = present but built differently than the spec mandates; **PARTIAL** = partially present; **MISSING** = absent; **FUTURE** = intentionally deferred per spec.

Method note: the 14 detector functions are in `backend/services/anomaly/detectors.py` (`ALL_DETECTORS` tuple, lines 546–561); the anomaly runner is `backend/services/anomaly/engine.py`. Connectors are under `backend/services/acquisition/` (not `services/connectors/`, which is an empty 1-line stub). ORM schema v4 is `backend/models/models.py`. Cross-cutting realities that recur below: **(a)** the 46-type taxonomy is only ~14 detectors live; **(b)** topology is hand-rolled SVG, not Cytoscape; **(c)** there is no real backend auth; **(d)** Cisco is still seeded despite ADR-004.

### V1 — Executive & Strategic Specification

| Requirement / capability | Status | Evidence (file or absence) | Notes |
|---|---|---|---|
| Read-only, multi-vendor (FGT + PA) policy intelligence platform | IMPLEMENTED | `backend/services/acquisition/fortigate.py`, `paloalto.py` — only GET / `type=keygen`/`config&action=show`/`op` | No write/commit/set verbs in either connector |
| Cross-vendor normalization as primary innovation | IMPLEMENTED | `backend/services/normalization/{engine,canonical,model,persist}.py` | Canonical correlation keys drive detectors |
| Deterministic anomaly engine, normalized input only | IMPLEMENTED | `services/anomaly/engine.py` docstring "Reads the NORMALIZED model ONLY (ADR-010); no DB, no network, no LLM" | |
| 46-category framework with full/conditional/simulated/future classification | PARTIAL | 14 detectors live in `detectors.py`; no 46-row taxonomy registry/enum in code | See V6 for the live-vs-not breakdown |
| Approved stack: FastAPI, PostgreSQL, Celery, Redis, React+TS, **Cytoscape.js**, Docker Compose | DIVERGED | Stack present except Cytoscape: `frontend/package.json` lists `cytoscape`/`react-cytoscapejs` but `grep` finds zero imports in `frontend/src/`; topology is `frontend/src/topology.jsx` raw `<svg>` (1032 lines) | Cytoscape is a dependency-on-paper only |
| ADR-004: remove Cisco from v1 implementation | DIVERGED | `backend/seed_data.py` L49 seeds vendor "Cisco"; L119 seeds device `ASA-BRANCH-ALEX-01`; `frontend/src/api.js` L39/247–248 render "Cisco ASA 5500-X" | No Cisco *connector* exists (`registry.py` only fortinet/paloalto) — violation is demo seed + UI styling, not acquisition |
| ADR-021: no MongoDB | IMPLEMENTED | Only PostgreSQL in `docker-compose.yml` (`db: postgres:16-alpine`) | |
| RBAC roles (Admin/Engineer/SOC/Auditor/Viewer) | MISSING | No auth/RBAC dependency on any route (`backend/main.py` only adds CORS) | Roles exist only as frontend demo `LFPM.users[]` |

### V2 — System Architecture Specification

| Requirement / capability | Status | Evidence | Notes |
|---|---|---|---|
| 8-layer pipeline (acquire→parse→normalize→repo→analyze→risk/CTI→AI→present) | IMPLEMENTED | `backend/services/{acquisition,parsing,normalization,anomaly,risk,cti,llm}/` all present | |
| Async acquisition via Celery+Redis (never in request cycle) | IMPLEMENTED | `backend/tasks/` + `celery_worker` service in compose; `jobs.py` route creates jobs | |
| Recommended backend module layout (`api/`, `core/`, `db/`, `services/`, `workers/`) | DIVERGED | Layout is `backend/api/routes/`, `core/`, `models/`, `services/`, `tasks/` — equivalent but renamed (`db/`→`models/`, `workers/`→`tasks/`) | Functional, not literal |
| Workers split by job type (acquisition/normalization/analysis/cti/reporting) | DIVERGED | One `celery_worker` container consuming all queues: `-Q acquisition,normalization,analysis,cti,reporting,celery` (compose L122) | Task *routing* exists; physical worker separation does not |
| Risk tiers 90–100 crit / 70–89 high / 40–69 med / 1–39 low / 0 info | IMPLEMENTED | `services/risk/scorer.py` `tier_of()` matches exactly | |
| Graph library = Cytoscape.js (logical graph) | DIVERGED | Hand-rolled SVG (see V1/V11) | |
| New v4 tables (normalized_object, mappings, risk, cti, benchmark, llm_report, etc.) | IMPLEMENTED | `models.py` defines all (see V5) | |

### V3 — Firewall Acquisition Specification

| Requirement / capability | Status | Evidence | Notes |
|---|---|---|---|
| FortiGate REST connector, Bearer token, spec endpoints | IMPLEMENTED | `acquisition/fortigate.py`: `/api/v2/cmdb/firewall/policy`, `/address`, `/addrgrp`, `firewall.service/custom`, `/group`, `/api/v2/monitor/system/status`; `Authorization: Bearer` (L62–63) | Schedules endpoint marked optional |
| Palo Alto XML connector, key auth, XPath show only | IMPLEMENTED | `acquisition/paloalto.py`: `type=keygen`, `type=config&action=show`, `type=op`; `rulebase/security` etc. | Docstring: "There is NO set/edit/delete/commit" |
| Connector interface + registry by vendor_type | IMPLEMENTED | `acquisition/base.py`, `registry.py` | |
| TLS verify configurable (lab insecure allowed) | IMPLEMENTED | `config.verify_tls` used in both connectors' `requests` calls | Matches V3 Table 25 (lab FGT HTTPS-broken reality) |
| Raw artifact storage + manifest + SHA-256 | IMPLEMENTED | `acquisition/storage.py`; `backend/raw_acquisition/{fortinet,paloalto}/…` populated per job | |
| Job lifecycle states / `acquisition_job` table | IMPLEMENTED | `models.py` `AcquisitionJob`, `RawArtifact`; `jobs.py` route | |
| Encrypted device credentials, never to frontend | IMPLEMENTED | `models.py` `DeviceCredential.secret_encrypted`; `services/credentials.py`; `core/security.py` Fernet | |
| Parser replay endpoint `POST /jobs/{id}/replay-parser` | PARTIAL | Raw artifacts persisted (replay-capable); explicit replay endpoint not confirmed in `jobs.py` | Data substrate exists; named endpoint unverified |
| FortiManager / Panorama connectors | FUTURE | Absent by design (V3 §19) | Correctly deferred |

### V4 — Normalization Engine Specification

| Requirement / capability | Status | Evidence | Notes |
|---|---|---|---|
| Canonical normalized rule model (action/logging/inspection/zones) | IMPLEMENTED | `normalization/model.py` `NormalizedRule`, `NormalizedObjectRec`; `canonical.py` | |
| Object correlation model (vendor-owned + canonical + mapping) | IMPLEMENTED | `models.py` `NetworkObject` (+device_id/vendor_id L103–107), `NormalizedObject`, `ObjectNormalizationMapping` | Matches V4 §7 correlation decision |
| Service normalization + mapping | IMPLEMENTED | `ServiceObject`, `NormalizedService`, `ServiceNormalizationMapping` | |
| Canonical ANY object/service sentinels | IMPLEMENTED | `detectors.py` L31–32 `ANY_OBJECT_KEY`/`ANY_SERVICE_KEY` via `canonical` | |
| Group expansion with cycle detection | PARTIAL | Expansion present (canonical keys); explicit recursive cycle-detection + `group_cycle` warning not separately verified | `NormalizationWarning` table exists |
| Logging/inspection abstraction → true/false/unknown | IMPLEMENTED | Detectors test `security_inspection_enabled == "false"`, `logging_enabled == "false"` (tri-state) | |
| `normalization_warning`, `rule_snapshot`, normalized content hash | IMPLEMENTED | `models.py` `NormalizationWarning`, `RuleSnapshot` | |
| Re-sync key (device_id, vdom_vsys, vendor_uuid) idempotent upsert | IMPLEMENTED | `normalization/persist.py`; V5 unique index | |

### V5 — Database & Data Model (Schema v4)

| Requirement / capability | Status | Evidence | Notes |
|---|---|---|---|
| Full schema v4 table set | IMPLEMENTED | `models.py` defines all spec tables: `vendor`, `firewall_device`, `policy_rule`, `network_object`, `rule_object_mapping`, `rule_service_mapping`, `rule_anomaly`, `normalized_object`, `object_normalization_mapping`, `normalized_service`, `service_normalization_mapping`, `normalization_warning`, `rule_snapshot`, `anomaly_execution_log`, `risk_assessment`, `cti_indicator`, `cti_observation`, `llm_report`, `benchmark_case`, `benchmark_result`, `acquisition_job`, `raw_artifact`, `device_credential` (+`external_node`, `threat_feed`, `api_token`, `audit_log`, `saved_search`) | Superset of spec |
| network_object ownership fields | IMPLEMENTED | L103–114 device_id/vendor_id/vendor_object_id/vendor_uuid/raw_value | |
| Indexes/constraints (V5 Table 12) | IMPLEMENTED | `idx_netobj_device_type_value`, etc.; sync unique index | |
| Alembic migrations | IMPLEMENTED | `backend/alembic/versions/` | |
| rule_anomaly evidence/severity/confidence/run_id/status | IMPLEMENTED | `models.py` `RuleAnomaly` (L223+) | |

### V6 — Anomaly Detection Engine (the 46-taxonomy)

Only **14 detectors are live** (`ALL_DETECTORS`). Mapping the live detectors onto the 46-row framework (V6 Table 5):

| Taxonomy area | Status | Evidence | Notes |
|---|---|---|---|
| **Live config-only detectors (14)** | IMPLEMENTED | `detectors.py` | shadowing (#1), redundancy (#2), conflict (#3), overly_permissive (#4), unprotected_allow (#5), missing_logging (#6/#32), any_to_sensitive (#7), wide_port_range (#8), duplicate_rules (#10), missing_description (#18), disabled_rule_review (#20/#42-ish), object_sprawl (#34), cross_device_inconsistency (#44), cross_device_security_posture_inconsistency (#44 posture) |
| Threat exposure (#36, CTI-mode) | IMPLEMENTED (separate engine) | `services/cti/runner.py` raises `threat_exposure` on ALLOW rules referencing malicious indicators | Not in `ALL_DETERMINISTIC` set — runs in CTI pipeline, labeled cti-mode |
| Ordering/overlapping/inconsistent-actions (#9, #11, #12) | PARTIAL | Subsumed by shadowing/conflict/redundancy logic but no dedicated #9/#11/#12 detectors | |
| Lifecycle/governance with history (unused #13, drift #14, age #16, explosion #17, change-freq #41) | MISSING / FUTURE | No hit-count/history ingestion; `RuleSnapshot` table exists but unused for these | Spec marks these conditional/history |
| Firewall-specific (zone mismatch #27, negate misuse #28, schedule misconfig #29, NAT risk #30, cross-VDOM #31, weak profile #33, direction #35) | MISSING | No detectors in `detectors.py` | `security_profile_strength` modeled but no #33 detector |
| Poor naming #19, hardcoded IP #22, unusual port #23, complexity score #24, temporary rule #15 | MISSING | Not implemented | |
| Runtime/advanced (hit distribution #37, time-of-day #38, geo #39, sim-gap #40, dependency #43, compliance #45, asymmetric #46) | FUTURE / MISSING | Require telemetry; not present | Spec-deferred |
| Auto-recommendation #26 | PARTIAL | Each Finding carries a `recommendation` string | Not a standalone recommender |
| Engine determinism, evidence payloads, execution log | IMPLEMENTED | `engine.py`; `Finding` dataclass `evidence`; `AnomalyExecutionLog` | |
| Detection-mode label (config_only/conditional/simulated/future) | PARTIAL | `Finding.detection_mode` defaults `"config_only"`; only config_only + cti-mode emitted | |

**Net V6 reality:** the deterministic engine is correct and well-built for the ~14 config-only types it covers (the core shadowing/redundancy/conflict/permissive/posture set), but the remaining ~32 of 46 (firewall-specific, lifecycle/history, runtime/advanced) are MISSING or FUTURE. The lab's thin policy set (≤10 deployed FGT rules per `ground_truth.py` comments) also limits how many live types actually fire.

### V7 — Benchmark & Evaluation Framework

| Requirement / capability | Status | Evidence | Notes |
|---|---|---|---|
| Ground-truth matrix (atomic + compound, cross-device pairs) | IMPLEMENTED | `services/benchmark/ground_truth.py` (`INTRA`, `CROSS_DEVICE`, `EXPECTED_SEVERITY`) | ~13 anomaly types covered |
| TP/FP/FN, precision, recall, F1, severity-match | IMPLEMENTED | `benchmark/scorer.py` L82–88 computes all | |
| `benchmark_case` / `benchmark_result` tables | IMPLEMENTED | `models.py` | |
| Benchmark runner filters expectations vs live policy_rule | IMPLEMENTED | `benchmark/runner.py` | |
| Benchmark **gates** the engine (CI/acceptance gate) | MISSING | No pass/fail gate wired into build/CI; runner computes metrics only | Identified next-step (see Outstanding) |
| Export benchmark report (DOCX/PDF) | FUTURE | Spec says "future releases"; not implemented | Correctly deferred |

### V8 — Risk Scoring Engine

| Requirement / capability | Status | Evidence | Notes |
|---|---|---|---|
| 0–100 additive formula + tiers | IMPLEMENTED | `risk/scorer.py` L3 formula; `min(100, sum(factors))` L72 | |
| Factor breakdown stored (JSONB) | IMPLEMENTED | `RiskAssessment.factor_breakdown`; scorer returns `factors` | |
| Per-anomaly factor contributions | IMPLEMENTED | `_FACTOR_CONTRIB` map (exposure/posture/etc.) | |
| Device risk = weighted top-N + critical-count modifier | IMPLEMENTED | `score_device()` top-5 blend + crit modifier (L81–99) | |
| CTI contribution to risk | IMPLEMENTED | `threat_exposure` finding feeds `cti_score`; `cti/runner.py` recalcs risk (L147) | |
| Recalculation triggers (sync/anomaly/CTI) | IMPLEMENTED | `risk/runner.py`; invoked post-anomaly and post-CTI | |
| Versioned weights (`calculation_version`) | PARTIAL | Column exists; explicit version constant not prominently set | |

### V9 — Threat Intelligence Engine (API-based CTI)

| Requirement / capability | Status | Evidence | Notes |
|---|---|---|---|
| Provider abstraction + ≥1 real provider | IMPLEMENTED | `cti/providers.py`: `CtiProvider` ABC, `AbuseIPDBProvider` (real REST), `LabOfflineProvider` (deterministic) | `build_providers()` always includes offline; abuseipdb when keyed |
| Indicator extraction, public-only (RFC1918 excluded) | IMPLEMENTED | `cti/extract.py` `is_public_ip()`; private/loopback/link-local excluded | FQDNs treated as public |
| Threat→rule correlation + `threat_exposure` | IMPLEMENTED | `cti/runner.py` raises labeled `threat_exposure` on ALLOW rules referencing bad indicators | |
| `cti_indicator` / `cti_observation` tables, provider+confidence | IMPLEMENTED | `models.py` | |
| Firmware/CVE/vendor-version threat matching | PARTIAL | Firmware fields modeled; IP correlation live; no CVE/NVD provider wired | `NVDProvider`/`OTXProvider`/`VirusTotalProvider` are interface stubs only |
| **LLM-assisted CTI query generation** (V9 §5) | MISSING | `services/llm/prompts.py` only has SOC-report prompt (`PROMPT_VERSION="soc-report/1.0"`); no `generate_cti_queries` | CTI runs provider lookups directly, no LLM query step |
| Dark-web / Robin / Tor LTI | FUTURE (present, off) | `backend/services/{robin,lumina_threat_intel}/`, `tor-proxy` compose service; `.env ENABLE_DARKWEB_INTEL=false` (L60) | Optional, gated off per ADR LFPM-IMPL-005 |

### V10 — AI / LLM Architecture

| Requirement / capability | Status | Evidence | Notes |
|---|---|---|---|
| Provider abstraction (Gemini + offline fallback) | IMPLEMENTED | `llm/providers.py`: `LLMProvider` ABC, `GeminiProvider` (real), `OfflineProvider`; `build_provider()` falls back when unkeyed | OpenAI/Ollama are documented plug-points, not coded |
| Evidence-grounded SOC report, DB IDs, prompt version, provider metadata | IMPLEMENTED | `llm/reporter.py` assembles findings+risk+CTI with IDs, stores `llm_report`; `prompts.py` system instruction forbids inventing CVEs/claims | |
| Failure isolation (LLM down → deterministic output) | IMPLEMENTED | `OfflineProvider` renders evidence verbatim; Gemini retries then `status="failed"` | |
| Executive-summary workflow | MISSING | No executive-summary prompt/path; only rule-level SOC report | V10 Table 3 lists it |
| CTI-query-generation workflow | MISSING | (same as V9 §5) | |
| Reports exposed via API + frontend | PARTIAL | `reports.py` (generate/list/get) + `frontend/src/reports.tsx`; no export endpoint | |

### V11 — Visualization & Dashboard

| Requirement / capability | Status | Evidence | Notes |
|---|---|---|---|
| React+TS dashboard shell, all modules | IMPLEMENTED | `frontend/src/`: `dashboard.jsx`, `inspector.jsx` (policy explorer), `risk.tsx`, `threats.tsx`/`cti.tsx`, `benchmark.tsx`, `reports.tsx`, `audit.jsx`, `settings.jsx`, `shell.jsx` | |
| Benchmark Center, Risk Center, CTI Threat Center | IMPLEMENTED | `benchmark.tsx`, `risk.tsx`, `cti.tsx`/`threats.tsx` | |
| **Logical graph built with Cytoscape.js** | DIVERGED | `topology.jsx` is hand-rolled `<svg>` (manual coordinates, `XMLSerializer` SVG export L488); `cytoscape`+`react-cytoscapejs` in `package.json` but **never imported** | Functionally a topology view, but not the mandated engine |
| Backend graph endpoint `GET /api/graph/policy-relationships` | MISSING | No graph router in `backend/main.py`; no `api/routes/graph.py` | Topology renders from frontend `useLFPM` context/assets, not a backend graph contract |
| Logical-not-runtime framing | IMPLEMENTED | Topology is config/asset-derived (CTI threat_exposure correlation noted in code), not packet flow | |

### V12 — Security Architecture

| Requirement / capability | Status | Evidence | Notes |
|---|---|---|---|
| Read-only firewall enforcement | IMPLEMENTED | Connectors issue only read verbs (V3) | Strongest-honored security control |
| Encrypted credentials at rest (Fernet), never to frontend | IMPLEMENTED | `core/security.py` `encrypt_secret`/`decrypt_secret`/`mask_secret`; `ENCRYPTION_KEY` derived | |
| **Real authentication (JWT/session) + login** | DIVERGED (cosmetic) | `frontend/src/login.jsx` checks against in-app `LFPM.users[]` with hardcoded `DEMO_PASSWORD="demo"`, MFA `123456`; the `POST /v1/auth/password` is only an animated log line; **no backend auth endpoint exists** | `core/security.py` docstring admits auth "added in the security phase" |
| RBAC middleware | MISSING | No route is protected; only CORS middleware in `main.py` | |
| Read-only API keys (`api_token` table) | PARTIAL | `models.py` `APIToken` + `api_tokens.py` CRUD, but tokens are not enforced as gatekeepers on other routes | Storage/management without enforcement |
| Audit logging | PARTIAL | `audit_log` table + `audit_logs.py` route + `audit.jsx`; not uniformly written on every action | |
| Data-minimization for external CTI/LLM | IMPLEMENTED | `CTI_ALLOW_INTERNAL_INDICATORS=false`; public-only extraction (V9) | |
| No public PostgreSQL/Redis exposure | IMPLEMENTED | `docker-compose.yml` internal services | |

### V13 — Deployment & Operations

| Requirement / capability | Status | Evidence | Notes |
|---|---|---|---|
| Docker Compose for all v1 services | IMPLEMENTED | `docker-compose.yml`: db, redis, api, celery_worker, frontend (+tor-proxy) | |
| Healthchecks + service dependencies | IMPLEMENTED | `depends_on … condition: service_healthy` on db/redis | |
| Env-var config (DATABASE_URL/REDIS_URL/ENCRYPTION_KEY/LLM_PROVIDER/CTI keys) | IMPLEMENTED | `.env`, `.env.example`, `core/config.py` | |
| Alembic migration entrypoint + Fortinet/PA vendor seed | IMPLEMENTED | `alembic/`; `seed_data.py` (but seeds Cisco too — see V1) | |
| Separate worker containers per queue | DIVERGED | Single worker, all queues (see V2) | |
| Backup/restore scripts, image tagging, K8s path | FUTURE / PARTIAL | Not present; K8s correctly deferred | |

### V14 — Development Roadmap & Handoff

| Phase | Status | Evidence | Notes |
|---|---|---|---|
| P0 prep / P1 acquisition / P2 normalization / P3 db v4 | IMPLEMENTED | As above | Foundation (never-sacrifice) layers solid |
| P4 anomaly engine (full 46) | PARTIAL | ~14 of 46 live (V6) | Core config-only types done; firewall-specific/lifecycle/runtime not |
| P5 benchmark validation | IMPLEMENTED (un-gated) | V7 | Metrics computed, not gating |
| P6 risk + CTI | IMPLEMENTED | V8/V9 | |
| P7 AI reporting | PARTIAL | V10 — SOC report yes; CTI-query-gen + exec summary no | |
| P8 visualization | DIVERGED | All modules present; graph not Cytoscape, no graph API (V11) | |
| P9 security + deployment | PARTIAL/DIVERGED | Compose + Fernet + read-only yes; **real auth/RBAC no** (V12) | |
| Future roadmap (Panorama/FortiManager/Cisco-proper/telemetry/K8s/Robin) | FUTURE | Correctly deferred; note Cisco currently leaks as demo seed, contrary to "future" | |

---

### Outstanding / Recommended Next (prioritized)

1. **Cytoscape topology rebuild (DIVERGED → spec).** Replace the 1032-line hand-rolled `frontend/src/topology.jsx` SVG with the mandated `react-cytoscapejs`/Cytoscape.js (already in `package.json`), and add the missing backend `GET /api/graph/policy-relationships` endpoint (V11 §12 node/edge contract) so the graph is data-driven rather than frontend-context-driven. *Highest user-visible architectural gap.*
2. **Benchmark gating.** Wire `services/benchmark/runner.py`/`scorer.py` into an acceptance gate (CI or a release check) that fails on precision/recall regressions and on false negatives, per V7 "fix false negatives before UI polish."
3. **Cisco removal (ADR-004).** Delete the Cisco vendor + `ASA-BRANCH-ALEX-01` device from `backend/seed_data.py` (L49, L119) and the Cisco/ASA styling branches in `frontend/src/api.js` (L39, L247–248) and `dashboard.jsx`. No connector to remove (none exists), but the demo seed and UI currently contradict v1 scope.
4. **Real authentication + RBAC (DIVERGED cosmetic → real).** Implement a backend auth endpoint (JWT/session per V12 Table 3) and an RBAC dependency on routes; replace the client-only `login.jsx` (`DEMO_PASSWORD="demo"`, MFA `123456`) and actually enforce the `api_token` read-only keys that today are stored but ungated.
5. **Report export.** Add DOCX/PDF export to `reports.py` (and a benchmark-report export), satisfying V7/V10 "exportable" requirements; today reports are stored `llm_report` text only.
6. **Settings honesty.** Make `settings.jsx` reflect real backend capabilities (which LLM/CTI providers are actually keyed and active, real provider/queue status) rather than demo affordances, so the UI does not imply unimplemented controls.
7. **VM policy enrichment to exercise the full taxonomy.** The lab currently deploys a thin rule set (≤10 FGT rules per `ground_truth.py`); enrich FortiGate/Palo Alto policies (schedules, NAT, zone-mismatch, temporary/named rules, weak profiles, hardcoded IPs) so the additional firewall-specific/lifecycle detectors (#15, #19, #22, #27–#33) can be implemented and benchmarked against live data rather than remaining MISSING/FUTURE.
8. **LLM CTI-query-generation + executive-summary workflows (MISSING).** Add the `generate_cti_queries(context)` and `generate_executive_summary(context)` paths to `services/llm/` (V9 §5, V10 Table 3); only the rule-level SOC report exists today.
