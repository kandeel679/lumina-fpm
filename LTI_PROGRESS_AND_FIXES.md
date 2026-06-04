# Lumina Threat Intel (LTI) — Progress, Problems & Fixes

**Scope:** the dark-web + clearnet threat-intelligence module at
`backend/services/lumina_threat_intel/`, fine-tuned to Lumina FPM's firewall scope.
**Branch:** `feature/lti-agentic-optimization`
**Last updated:** 2026-06-04

> Companion doc: **`CLAUDE.md`** (the engineering handoff / "how to work on this
> repo efficiently from scratch"). This file is the *journey* — what we built,
> what broke, and how/why we fixed it.

---

## 1. What LTI is

LTI scans the dark web (via Tor) **and** authoritative clearnet feeds (CISA KEV,
NVD) for threats, then assesses each finding against the customer's *actual*
firewall inventory (vendors, models, firmware) and produces a report that is
**dedicated to their system** — not generic OSINT. It reuses Robin (a proven
dark-web OSINT tool) as a **library only** for Tor search/scrape and the
LangChain LLM layer; all LTI logic lives in `lumina_threat_intel/`.

---

## 2. What we accomplished (the brag list)

### 2.1 Killed the token/call explosion (≈50 LLM calls → ~2 per scan)
- **Before:** keyword→query generation looped one LLM call *per keyword* (~30–50
  calls), then Robin's generic narrative + 5 per-category "refiner" calls. This
  bloated tokens, lost focus, and instantly exhausted Gemini's free quota.
- **After:** **1** batched, structured query-generation call (`fast` tier) +
  **1** consolidated, firewall-scoped Findings call (`strong` tier). Result
  filtering moved to deterministic code (0 LLM calls).

### 2.2 A firewall-scoped Findings prompt (the centerpiece)
- `prompts/findings.py :: build_findings_prompt(...)` injects the customer's
  firewall fingerprint (vendors/models/firmware) and asks the model to reason
  **relevance natively** and emit a single strict-JSON object
  (`AssessedFindingsOutput`). Verified to produce scoped narratives that name the
  customer's exact firmware versions.

### 2.3 Two-axis assessment model
- **Criticality:** `info | low | medium | high | critical`.
- **Relevance (hybrid):** the LLM proposes a 0–100 score + band
  (`none | low | medium | high`); then `correlator.py` **verifies** against the
  real DB inventory and upgrades to `high` on a confirmed rule/device match.
- **Clean** = no finding reached `medium`+ relevance ("this FW is clean").
- **`info` findings** appear in the report narrative but are **not persisted** as
  rows (assessment-model decision).
- Schema + DB columns: `criticality`, `relevance_score`, `relevance_band`,
  `relevance_reason` on findings; `clean`, `coverage_note` on reports.

### 2.4 A reliable clearnet intelligence backbone (free, deterministic)
- `clearnet_intel.py`: **CISA KEV** (actively-exploited) + **NVD** (recent CVEs,
  CVSS-scored) connectors, scoped to the customer's firewall *products*.
- **No LLM, no Tor, no cost, no content-blocking** — works even when Tor or the
  LLM gateway is flaky. Verified: **62 real, scoped CVE findings** with correct
  criticality, tags (`cisa-kev`, `actively-exploited`, `ransomware`), and
  dedup/diff metadata.

### 2.5 Live dark-web source registry
- `sources.py`: 8 live `.onion` search engines, 11 curated sources, 9 clearnet
  feeds. `scraper/engine.py` rewired to use LTI's curated live engines (Robin's
  default engine list was dead) **without modifying Robin**.

### 2.6 Tiered, budget-aware, **credential-aware** model router
- `model_router.py`: tiers `fast | strong | premium`; soft budget cap ($20)
  that downgrades to the cheapest model + warns; multi-provider
  (`gemini*`, `deepseek/*`, `openrouter/*`, `opencode/*`, `agentrouter/*`).
- **Credential-aware defaults:** picks the provider whose key is present
  (`DEEPSEEK_API_KEY` → DeepSeek; else `GOOGLE_API_KEY` → Gemini; AgentRouter only
  as explicit last resort). A fresh checkout "just works" with the keys in `.env`.

### 2.7 Dev-ops hardening
- CRLF→LF entrypoint fix + `.gitattributes`; Docker DNS workaround; **celery
  worker auto-reload** via `watchmedo`; in-pipeline diagnostics + a build marker
  so stale-code runs are instantly visible.

### 2.8 Verified end-to-end
- Full pipeline runs on Gemini: scoped narrative, 1-call query gen, Tor scrape,
  consolidated findings, clearnet merge, correlation, diff, persistence.

---

## 3. Problems & Fixes (root cause → fix → why → outcome)

### P1 — `entrypoint.sh: not found` (containers exit 127)
- **Symptom:** `api`/`robin` containers failed with `exec ./entrypoint.sh: not found`.
- **Root cause:** the file had Windows CRLF line endings; the Linux loader read
  `#!/bin/sh\r` and couldn't find the interpreter.
- **Fix:** `sed -i 's/\r$//' backend/entrypoint.sh` + a `.gitattributes` rule
  (`*.sh text eol=lf`) so Windows checkouts never reintroduce CRLF.
- **Why:** `.gitattributes` fixes the class of bug at the source, not just the
  instance.
- **Outcome:** containers start reliably on Windows and Linux.

### P2 — Gemini free-tier rate limits (429) blocked scans
- **Symptom:** scans failed after a few calls (`5/min`, then `20/day` exhausted).
- **Root cause:** the old pipeline made ~50 calls/scan.
- **Fix:** collapsed to ~2 calls/scan (see §2.1).
- **Why:** the cheapest, most robust rate-limit fix is *fewer calls*, not paid tiers.
- **Outcome:** a full scan fits comfortably inside the free quota.

### P3 — Docker Desktop DNS drops (name resolution `Errno -2/-3`)
- **Symptom:** intermittent DNS failures inside containers; `resolv.conf` lost its
  nameserver. `down && up` didn't help.
- **Root cause:** Docker Desktop's embedded DNS forwarder dropping on Windows.
- **Fix:** pinned `dns: [8.8.8.8, 1.1.1.1]` on `api` and `celery_worker` in
  `docker-compose.yml`.
- **Outcome:** stable outbound resolution (NVD/KEV/Tor bootstrap).

### P4 — Findings call returned empty / unparseable JSON (the red herring)
- **Symptom:** `Expecting value: line 1 column 1 (char 0)` — empty LLM response
  on real dark-web content.
- **Wrong theory #1:** "Gemini is safety-blocking the content." Built
  `safety_settings = BLOCK_NONE`. A probe showed a small harmful prompt returned
  fine → safety wasn't the blocker.
- **Actual root cause(s):** (a) a **heavy, self-contradicting prompt** — the
  shared preamble forbade "generating exploit/credential content" while the task
  *required extracting* it; (b) feeding **raw scraped text** through restrictive
  gateways. The user's key insight: **Robin processed dark-web content with the
  same Gemini key**, so the model was never the problem — our prompt + input were.
- **Fix:** a **moderation-safe "clean digest"** corpus mode (defanged
  IOCs/metadata) as the default, with an `excerpts` mode (real truncated text) for
  permissive backends, toggled by `LTI_CORPUS_MODE`.
- **Outcome:** Gemini reliably returns a scoped narrative + structured findings.

### P5 — AgentRouter unusable as a backend (`401 unauthorized_client`)
- **Symptom:** every API call to AgentRouter returned `401 unauthorized_client` —
  even with a fresh key, the Anthropic-style endpoint, a Claude model, and a benign
  prompt.
- **Root cause:** AgentRouter authorizes only the **Claude-Code / Codex CLIs**, not
  arbitrary backend API clients.
- **Fix:** stopped treating AgentRouter as a usable default; kept it reachable via
  explicit `agentrouter/` ids only. We **do not spoof** the Claude Code client.
- **Outcome:** routing no longer depends on a dead gateway (see P9).

### P6 — NVD connector pulled ancient (2012) CVEs
- **Symptom:** "recent CVEs" feed returned decade-old entries.
- **Root cause:** queried `lastModStartDate`, which catches NVD *re-enrichment* of
  old CVEs.
- **Fix:** switched to `pubStartDate`/`pubEndDate` over the last 120 days.
- **Outcome:** genuinely recent, relevant CVEs.

### P7 — CISA KEV over-matched (FortiClient EMS, Catalyst SD-WAN, etc.)
- **Symptom:** 133 "matches" including products the customer doesn't run.
- **Root cause:** matching on bare vendor names ("cisco", "fortinet").
- **Fix:** `_VENDOR_MATCH` uses firewall-**product** tokens (`fortios`/`fortigate`,
  `pan-os`/`globalprotect`, `adaptive security appliance`/`secure firewall`).
- **Outcome:** 40 relevant KEV findings (62 total with NVD), no vendor noise.

### P8 — `clean` / `coverage_note` persisted as `null` (stale worker)
- **Symptom:** a successful scan saved a rich, scoped narrative but `clean: null`
  and `coverage_note: null` — impossible given current code (the narrative and
  `coverage_note` are set together; `clean` is computed unconditionally).
- **Root cause:** the scan runs in **Celery**, and `celery_worker` had **no
  `--reload`**. The bind-mounted code on disk was current, but the worker kept
  **stale code in memory** from its last start. (`api` reloads; the worker didn't.)
- **Fix:** ran the worker under **`watchmedo auto-restart`** (added `watchdog`),
  so any `.py` change restarts the worker. Also added a **build marker**
  (`build=assessment-v2`) and an **`Assessment:` diagnostic** line so a stale run
  is obvious in logs, plus a guaranteed non-null `coverage_note`.
- **Why:** fixes the *class* of bug (silent stale worker) instead of the instance,
  and makes future regressions self-diagnosing.
- **Outcome:** `clean`/`coverage_note` always populate; the worker can't go stale.

### P9 — Default model chain pointed at the dead gateway → total LLM failure
- **Symptom:** a fresh checkout with only the Gemini key failed **every** LLM call
  (`fast` chain → `agentrouter/deepseek-v4-flash` → 401), so query-gen produced 0
  queries and only clearnet findings survived.
- **Root cause:** `_DEFAULT_CHAINS` hard-coded AgentRouter (chosen when we believed
  its $150 credits worked; it doesn't for APIs — see P5).
- **Fix:** **credential-aware defaults** (`_provider_default_chains()`):
  `DEEPSEEK_API_KEY` → DeepSeek; else `GOOGLE_API_KEY` → Gemini; AgentRouter only
  if it's the sole credential. Per-tier `LTI_CHAIN_*` env overrides still win.
- **Outcome:** the pipeline works out of the box with whatever key is in `.env`;
  no manual `LTI_CHAIN_*` override needed.

### P10 — "Gemini key is broken" → actually a key-format/rotation issue
- **Symptom:** Gemini returned `401 UNAUTHENTICATED … ACCESS_TOKEN_TYPE_UNSUPPORTED`.
- **Investigation:** the key was `AQ.A…` / 53 chars. We initially flagged this as
  "not an `AIza…` API key." **Empirically, a fresh `AQ.Ab8…` token works** — so
  the format is valid (a newer Google credential), but the *specific* old token had
  **expired/been revoked** (these OAuth-style tokens rotate). A new `AQ.Ab8…` token
  returned `OK`.
- **Fix:** swapped the working token into `.env` (`GOOGLE_API_KEY` +
  `LTI_LLM_API_KEY`).
- **Lesson:** if Gemini suddenly 401s with `ACCESS_TOKEN_TYPE_UNSUPPORTED`, the
  token likely **expired** — refresh it, or use a permanent `AIza…` key for stability.
- **Outcome:** Gemini calls succeed; verified end-to-end.

### P11 — `correlated_rules: 0` (clearnet CVEs never upgrade to `high`)
- **Symptom:** all 62 clearnet findings stayed at `medium`; none correlated to a
  rule/device.
- **Root cause:** correlation does a **literal substring** match of the device's
  exact firmware (e.g. `7.4.3`) against the CVE text, but NVD/KEV describe affected
  **ranges** ("FortiOS 7.4.0 through 7.4.2") — so the exact patch string rarely
  appears.
- **Status / fix:** **RESOLVED in P14** — version-aware relevance using CPE
  `versionStartIncluding`/`versionEndExcluding` from NVD (range containment), so a
  CVE that covers the customer's installed version now upgrades to `high`.
- **Interim outcome (pre-P14):** correctly conservative — vendor-present CVEs sat at
  `medium`/`low` until a real version match was proven.

### P12 — API returned `clean: null` / `coverage_note: null` on a correct scan
- **Symptom:** a colleague's run (Report 8) finished cleanly — logs showed
  `build=assessment-v2`, `Assessment: … clean=False bands={'medium': 40, 'low': 22}`,
  the `coverage_note` UPDATE committed, and `test_ground` printed `CLEAN: False` +
  the full coverage note — yet the **API JSON** for that report showed
  `clean: null` and `coverage_note: null` (every other field was current).
- **Root cause:** a **read-side serialization bug**, not a scan/worker bug. In
  `api.py`, `list_reports` (`ReportSummaryResponse`) and `get_report_detail`
  (`ReportDetailResponse`) built the response objects **without** passing
  `clean=`/`coverage_note=`. The schema declares both as `Optional[... ] = None`,
  so Pydantic filled the defaults → the API always emitted `null` regardless of the
  DB. Direct ORM reads (`test_ground`) were correct because they bypass the API.
- **Confirmation:** `SELECT id, clean, coverage_note FROM threat_intel_reports`
  showed real values (Report 1 `t`, Reports 2–5 `f`, all with coverage notes) while
  the endpoint returned `None` for all.
- **Fix:** pass `clean=r.clean, coverage_note=r.coverage_note` in **both** endpoints.
  After an `api` reload/restart the endpoint returns the true values
  (Report 5 `clean=False` + note; Report 1 `clean=True`).
- **Footgun noted:** the `api` container did **not** hot-reload this edit until
  `docker compose restart api`; a stale `api` process can mask a correct fix.
- **Lesson:** when the DB has a value but the API shows `null`, suspect the
  endpoint's response mapping (forgotten field) before suspecting the pipeline.

### P13 — 16 onion pages scraped, 0 dark-web findings (noise, not a bug)
- **Symptom:** a scan scraped 16 onion pages but produced 0 dark-web findings;
  looked like the assessment was "missing" threats.
- **Investigation (Report 8 raw scrapes):** all 16 pages were **search-engine
  landing pages** (Ahmia, OnionLand, I2P Search), a **hosting ad**, and
  **conference / podcast archives** (InfoCon/RSAC `.mp4` listings, DEF CON speaker
  pages, CyberWire/Security Weekly). Zero CVEs/IPs/domains/creds, nothing about the
  customer's firewalls. The Findings LLM correctly returned 0 — **garbage in**.
- **Three root causes:** (a) the curated `.onion` search engines mostly return
  generic/self-referential results, not market/forum threat content; (b) **Step 4
  did nothing useful** (`16 -> 16`) — it ranks but never drops zero-relevance pages;
  (c) **weak dedup** — the same RSAC directory under different sort params
  (`?C=S&O=A`, `?C=N&O=D`, …) counted as 4 "unique" pages.
- **Fixes shipped:**
  - **URL-normalized dedup** (`scraper/engine.py::_dedup_key`): strip
    scheme/query/fragment/trailing-slash so sort-param duplicates collapse to one.
    Verified: 3 RSAC variants → 1.
  - **Step 5b relevance filter** (`orchestrator.py::_filter_scraped_by_relevance`
    + `_relevance_terms`): after scraping (raw scrapes still persisted for audit),
    drop any page that mentions **none** of the customer's firewall identifiers
    (firmware versions, CVE ids, org domains, vendor PRODUCT synonyms like
    `pan-os`/`fortios`/`asa`). Pure code, 0 LLM cost.
- **Verified (Report 6):** `Dark web search: 4 unique results from 32 total`;
  `Step 5b: relevance filter 4 -> 0 pages (dropped non-firewall noise)`;
  `Assessment: darkweb=0 clearnet=62 total=62 clean=False`. The LLM is no longer fed
  noise; clearnet backbone unaffected.
- **Net:** dark-web=0 is now an **honest, clean** result instead of "fed 16 junk
  pages." A genuinely relevant page would pass the filter and reach the LLM.
- **Open (unchanged):** the deeper issue is **source quality** — the `.onion`
  engines need curating toward real firewall-relevant markets/forums so the filter
  has something to keep.

### P14 — Version-aware correlation (resolves P11): CVEs covering installed firmware → `high`
- **Goal:** make relevance reflect the customer's **exact installed firmware**, not
  just "a CVE exists for this vendor." Previously NVD findings sat at `low` and KEV at
  `medium` because correlation was literal-substring on the patch string (P11).
- **Fix — capture ranges (`clearnet_intel.py`):** `_extract_affected_ranges()` parses
  each NVD CVE's `configurations → nodes → cpeMatch`, keeping only `vulnerable: true`
  entries whose CPE `criteria` names the **customer's product**
  (`_NVD_PRODUCT_CPE`: `:fortinet:fortios:`, `:paloaltonetworks:pan-os:`,
  `:cisco:adaptive_security_appliance:`/`:cisco:asa:`). It records
  `versionStart/EndIncluding/Excluding` (or an exact CPE version) onto the finding as
  internal hints `_affected_ranges` + `_nvd_product` (stripped at persistence; not
  schema fields, ignored by the hash which is `category|title|iocs`).
- **Fix — range containment (`correlator.py`):** `_version_tuple()` normalizes a
  version to a fixed-length int tuple (`7.4.3 → (7,4,3,0)`, build suffixes dropped);
  `_version_in_range()` tests inclusive/exclusive bounds (or exact). A new block maps
  `_nvd_product → vendor token` (`fortios→fortinet`, etc.) so a FortiOS CVE only tests
  Fortinet devices, then, if the device's installed firmware is inside any affected
  range, adds the device + its rules to the match and the existing hybrid block
  upgrades the finding to `high` (score ≥ 90) with reason "installed firmware X on
  device N is within an affected version range for this CVE."
- **Verified (live NVD, 120-day window):** unit checks `7.4.3 ∈ (<7.4.9)` → True,
  `7.4.3 ∈ [7.4.0,7.4.2]` → False. Real fetch: 24 NVD findings, 9 carry ranges, **8
  upgraded to `high`** because FortiOS `7.4.3` (devices 1,2) and PAN-OS `11.1.2`
  (device 3) fall inside recent CVE ranges (e.g. CVE-2025-55018/64157/68686,
  CVE-2026-0300/0257). PAN-OS `11.0.4` and Cisco ASA `9.18.3` had no matching recent
  CVE → stay low/clean, correctly.
- **Net:** relevance is now **version-confirmed**, not vendor-guessed. `clean` flips to
  `False` only when a device is actually inside an affected range (or KEV/IOC match),
  which is exactly the dedicated-to-their-system signal the product promises.
- **Caveat:** comparison is numeric-tuple, padded to 4 components; non-numeric build
  tags (`_mr10`, `_beta`) are dropped — fine for modern firewall firmware, approximate
  for ancient FortiOS strings.

---

## 4. Before / after

| Dimension | Before | After |
|---|---|---|
| LLM calls / scan | ~30–50 | ~2 |
| Findings relevance | generic OSINT | scoped to the customer's FW inventory |
| Assessment | severity only | criticality + hybrid relevance + `clean` |
| Reliability when Tor/LLM flaky | scan fails | 62 free clearnet CVEs still land |
| Model backend | single, hard-coded, dead (AgentRouter) | credential-aware multi-provider + budget cap |
| Worker code freshness | silently stale | auto-reload (`watchmedo`) + build marker |
| Cost spent (of $20 cap) | — | **$0** |

---

## 5. Current status (2026-06-04)

- ✅ Pipeline runs end-to-end on Gemini (working `AQ.Ab8…` token in `.env`).
  **Verified run — Report 4 (2026-06-04, 210s, $0.00):** routing picked Gemini
  (`fast`=gemini-2.5-flash-lite for query gen → 8 queries in **1** call;
  `strong`=gemini-2.5-flash for Findings); `Model ACTUALLY used: gemini-2.5-flash`;
  4 onion pages scraped; 62 clearnet findings; `clean=False`; **LLM-authored
  `coverage_note`** ("…No specific CVEs, IPs, domains, or credential leaks relevant
  to the customer's firewall inventory were found."); scoped narrative naming the
  exact firmware versions. darkweb findings=0 (source-quality limit, not a bug).
- ✅ Assessment model persists correctly (criticality/relevance/tags/hash/diff).
- ✅ Clearnet backbone: 62 scoped CVEs, $0.
- ✅ Worker auto-reload + diagnostics live.
- ✅ NVD baseline lowered to `low` (KEV stays `medium`) so `clean` is achievable;
  verified bands `{'medium': 40, 'low': 22}`.
- ✅ API now surfaces `clean` / `coverage_note` on `GET /scans` and
  `GET /scans/{id}` (P12); verified after `api` reload.
- ⏳ **Open:** (a) version-aware correlation (P11); (b) dark-web **source
  quality** — the `.onion` engines return generic pages, so dark-web findings are
  often 0 even on a good run; (c) PSIRT connectors (Palo Alto JSON, Fortinet RSS).
- 💡 Backups wired but unused: DeepSeek direct (set `DEEPSEEK_API_KEY` → auto-preferred).
