# LuminaFPM — Session Handoff

> Purpose: let work resume on another device / a fresh Claude session. The **code** is the durable
> handoff (all pushed to `origin/analyze-project-todo-report`). The data, `.env`, and the VMware lab are
> **device-local** and do not travel — see "Environment caveats" below.

_Last updated at commit `1cb66cb` (branch `analyze-project-todo-report`, no PR per mandate)._

---

## Where we are

**The whole platform is built and live-verified.** Backend Phases 0–9 (acquire → normalize → detect →
benchmark → risk → CTI → AI report) + frontend Phase 10 (the dashboard/screens). Full chronological detail
is in [`docs/EXECUTION_LOG.md`](EXECUTION_LOG.md) (entries E-001 … E-029).

**Frontend (Phase 10) — done, all 8 sub-phases + a final pass:**
- `frontend/src/lib/api.ts` — typed API client (the single source of truth for backend calls).
- New TSX screens: `risk.tsx`, `reports.tsx`, `cti.tsx`, `benchmark.tsx`. `tsc --noEmit` is green.
- Legacy `.jsx` screens de-mocked against the live backend (real V8 risk, real run-scoped findings +
  analyst lifecycle, real CTI threat vectors, real topology assets). Cosmetic lab login retained.
- Incremental TS migration: `tsconfig.json` has `allowJs` so `.jsx` keeps working; migrate screen-by-screen.

**Verified live data (lab, run #18):** 2 devices (FGT-LAB 192.168.55.10, PA-LAB 192.168.55.20), 20 rules,
54 current findings, device risk 96/100, benchmark precision/recall/F1 = 100% (47/47).

---

## OPEN — decisions/work queued (this is where to resume)

### A. Two quick fixes the user approved direction on (do first, ~15 min)
1. **Gate the Benchmark Center out of the customer UI.** It's our internal acceptance-gate/QA tool, not a
   product feature. Hide the rail item + route behind a dev flag (e.g. `VITE_ENABLE_BENCHMARK`, default
   off). Files: `frontend/src/shell.jsx` (rail items), `frontend/src/app.jsx` (VALID_PAGES/render).
2. **Strip Cisco from all v1 surfaces.** v1 is **Fortinet + Palo Alto only**, but `vendorMeta` (api.js),
   topology band colors/labels, and threat filters still carry Cisco/ASA branches. Remove them.

### B. THE NEXT MAJOR TASK the user will give — VM policy enrichment
The user will ask to **enrich the firewall VMs with policies that trigger all (config-detectable) anomaly
types**, then have Lumina detect them:
- **FortiGate:** make its **10 policies** (unlicensed-VM cap = 10) maximally **dense** — each rule
  deliberately tripping several anomaly types.
- **Palo Alto:** an **efficient set** that triggers all anomalies **plus genuine clean/normal rules** to
  mimic a real production environment.

Two alignment points already established with the user:
- **"All anomalies" = all config-detectable types.** The config-only taxonomy (`unprotected_allow`,
  `shadowing`, `redundancy`, `duplicate_rules`, `conflict`, `any_to_sensitive`, `wide_port_range`,
  `missing_description`, `missing_logging`, `overly_permissive`, the cross-device pair, CTI
  `threat_exposure`, …) is rule-triggerable. **Bucket-C** types (hit-count/age/drift/time-of-day/geo/
  change-frequency) need logs/telemetry/history config can't carry — they stay `simulated`/`benchmark`.
- **Lumina is READ-ONLY to firewalls.** So enrichment = extend the **lab provisioner**
  (`lab/benchmark_dataset.py` + `lab/provision_benchmark.py`, which use the *write* keys, NOT Lumina) and
  the **ground-truth matrix**, push to both firewalls, then Lumina syncs read-only and the benchmark
  re-scores. Before provisioning, produce the **policy matrix** (which rule → which anomaly, expected
  severities, cross-device pairs).

### C. Bigger items explained to the user, awaiting priority
1. **Topology is hand-rolled SVG, NOT Cytoscape.js (off-spec).** That's why nodes don't drag/zoom. The
   cytoscape deps are installed but unused. Proper fix = rebuild the topology view on Cytoscape.js
   (interactive, draggable, fcose/dagre). Biggest remaining frontend item — best done AFTER enrichment.
2. **Threat Intelligence CVE-scan feature is future/optional (LTI/Robin).** Empty until a scan runs; carries
   off-spec Cisco + CVE/NVD/CISA-KEV/clearnet/dark-web. Decide: label "future" or remove; keep only the
   real Volume-9 CTI "indicators" tab.
3. **SOC reports: add export + improve.** No export today; add Markdown/PDF download + richer report
   structure (findings table, prioritized remediation, per-rule evidence). Ask user what "satisfying" means.
4. **Settings is mostly a "read-only demo."** Real: Connectors→firewall fleet + sync buttons. Mock:
   threat-intel feeds, analyzer schedule, notifications, access/api/audit-log/about. (A real
   `/api/v1/audit-logs` exists but Settings doesn't call it.) Decide: trim to real / wire the real bits /
   keep labeled demo.

### D. Optional cleanup
- `llm_report` table has test artifacts (failed Gemini attempts + a couple generated during verification).
  No DELETE route; purge with a one-off DB statement only if a pristine DB is wanted. (Failed attempts are
  arguably intentional V10 §11 history.)

---

## How to resume the running environment

```bash
docker compose up -d            # db, redis, api (:8000), celery_worker, frontend (:5173)
```
- **Canonical app:** http://localhost:5173 (dockerized Vite dev server, proxies /api/v1 → api:8000).
- **Host dev preview (optional, for Claude's preview tools):** `cd frontend && npm install` then run via
  `.claude/launch.json` ("frontend", port **5175**, proxies → localhost:8000). `VITE_API_PROXY` controls
  the target (Compose sets it to `http://api:8000`; host defaults to `http://localhost:8000`).
- **Login is a cosmetic lab gate.** Bypass it by injecting a session:
  `sessionStorage.setItem('lumina_demo_user', JSON.stringify({id:'u-1',name:'Hamza Al-Mansoori',email:'hamza@lumina-fpm.local',role:'admin',avatar:'H'})); sessionStorage.setItem('lumina_session_ver','2');`
  then reload. (Or just use the on-screen demo-account buttons.)
- **Typecheck:** `cd frontend && npx tsc --noEmit` (only `.ts/.tsx` are checked; `.jsx` stays under `allowJs`).

## Environment caveats (what does NOT transfer across devices)
- **`.env` is gitignored** (secrets). A new device needs its own `.env` — start from `.env.example` and set:
  `DATABASE_URL` (lumina:lumina@db:5432/lumina_fpm), `POSTGRES_*`, `SECRET_KEY`, **`ENCRYPTION_KEY`** (must
  match the one that encrypted any stored device credentials, else they won't decrypt), `LLM_API_KEY`
  (working Gemini key), `LLM_PROVIDER=gemini`, `LLM_MODEL=gemini-2.5-flash`,
  `FIREWALL_TLS_VERIFY=false`, `FIREWALL_INSECURE_HTTP_HOSTS=192.168.55.10` (lab FortiGate HTTPS is broken;
  REST works over HTTP). Optional: `CTI_PROVIDER_KEYS=abuseipdb=...` for live CTI (else offline lab provider).
- **The DB is a local Docker volume** — a fresh device starts empty; re-sync from the firewalls or
  re-provision the lab to repopulate.
- **The VMware lab firewalls are on this host's network** (mgmt `192.168.55.0/24`: FortiGate .10, Palo Alto
  .20, host adapter .1). Another device must be on the same network to poll them live. Read-only poll keys
  and write provisioner keys are documented in the lab notes — **all keys exposed in chat should be rotated.**

## Key files
- Specs (source of truth): `docs/*` (esp. ANOMALY_ENGINE_SPEC, DATABASE_SCHEMA_V4, BENCHMARK_FRAMEWORK,
  ARCHITECTURE_DECISIONS, API_CONTRACT). Full history: `docs/EXECUTION_LOG.md`.
- Frontend: `frontend/src/lib/api.ts` (typed client), `frontend/src/{risk,reports,cti,benchmark}.tsx`,
  `frontend/src/{api.js,app.jsx,shell.jsx,audit.jsx,inspector.jsx,dashboard.jsx,topology.jsx,threats.jsx,menus.jsx,settings.jsx}`.
- Lab provisioner (for the enrichment task): `lab/benchmark_dataset.py`, `lab/provision_benchmark.py`.
- Backend routes: `backend/api/routes/*` ; anomaly/risk/cti/llm/benchmark services under `backend/services/*`.
