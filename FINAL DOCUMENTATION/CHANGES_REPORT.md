# LuminaFPM Documentation — Changes Report

**Deliverable:** `LuminaFPM_Documentation.tex` (+ generated `LuminaFPM_Documentation.pdf`, **106 pages**).
**Build:** TeX Live (Docker) `pdflatex`, 3 passes; rasterized + audited with PyMuPDF.
**Final log health:** 0 errors · 0 LaTeX warnings · 0 undefined references · 0 multiply-defined labels ·
0 Overfull \vbox · 0 Underfull · **4 Overfull \hbox remaining** (all ≤7.4pt ≈ 2.6 mm — see §6).
Down from the baseline **119 Overfull \hbox**.

---

## 1. Build & toolchain (Phase 0)
- No TeX engine existed on the machine; stood up a reproducible **TeX Live Docker** compile + **PyMuPDF**
  rasterizer (ASCII build dir to avoid the Arabic repo path in Docker mounts). Scripts under the session
  scratchpad (`build.sh`, `raster.py`, `minelog.py`, `ofmap.py`).
- Preamble hardening: added `microtype` (protrusion/expansion), `xurl` (breakable URLs/paths),
  `adjustbox` (cap figures to page width AND height), `rotating` (landscape ER figure),
  `xltabular` (auto-fitting `X`-column multi-page tables); set `\widowpenalty/\clubpenalty/\brokenpenalty=10000`,
  `\tolerance=4000`, `\emergencystretch=3em`, lowered `\hfuzz/\vfuzz` 30pt → 2pt to surface real overflow;
  made the underscore a break point (`\renewcommand{\_}{\textunderscore\allowbreak}`) so long monospace
  identifiers wrap instead of overflowing.

## 2. Code ⇄ documentation synchronization (Phase 1)
Reconciled against the current code (doc was frozen at commit `21bc0b1`; ground truth captured from the
running code/tests). Authoritative numbers re-derived by running `tests/test_benchmark_matrix.py` in the
api container and reading `docs/EXECUTION_LOG.md`.

**Corrected facts**
- Benchmark run **#18 → #25**; **47 → 43** expected cases; **20 → 26** rules (10 FortiGate + 16 Palo Alto);
  rebuilt the anomaly-type distribution table to the authoritative 13-type breakdown (sum 43);
  device risk now FGT 96 (+40 firmware) → 100 and PA 100 (+30 firmware) — both critical.
- `PROMPT_VERSION` `soc-report/1.0 → 2.1` (two places), + prose-only / names-not-IDs disciplines.
- Unit-test suite **8 → 11 files** (added `test_benchmark_matrix`, `test_vuln`, `test_scheduling` rows).
- Compose stack **five → six services** (+`celery_beat`).
- CTI test case: removed the non-existent `FGT_ALLOW_MALICIOUS`; threat_exposure now on `FGT_ANY_DB` +
  `PA_ALLOW_MALICIOUS`; AI-report example moved to `FGT_ANY_DB`.
- §4.14 limitation: topology "schematic SVG" → **resolved** (Cytoscape); `disabled_rule_review` now
  exercised (PA_DISABLED_RISKY) — only `object_sprawl` remains un-exercised.
- Removed a leaked agent meta-commentary line and a stray markdown `---` separator; fixed a stale
  `PROMPT_VERSION` inside the misuse-case table.

**Newly documented features (built after the doc froze)**
- §4.8 CTI: new **firmware-CVE device-intelligence axis** (vuln_intel/vuln_runner, `cve_reference.json`
  5 CVEs, writes ZERO rule_anomaly, `VULN_PROVIDER=offline`).
- §4.7 Risk: device-scope **firmware_modifier** (crit40/high30/med18/low10), explicitly not a 9th factor.
- §4.9 AI reporting: the **deterministic `report_builder`** (Remediation / Risk-Posture / Firmware-CVE /
  Per-Finding-Evidence tables) + executive vs per-rule scopes + **Markdown/PDF export**.
- §4.10 API: added schedules, notifications, and `/reports/{id}/markdown` endpoints.
- **New §4.12 "Settings, Scheduling, and Notifications"** (device management, `schedule_config` + Celery
  Beat `scheduler.tick`, in-app notifications) + a captured Settings screenshot.
- §4.11 frontend: topology rewritten to **Cytoscape.js**; **two-axis Threat Center**; functional Settings.

**Future Work promoted (Ch. 5)**
- §5.2.1 Cytoscape topology → **delivered** (residual: Dagre auto-layout / expand-collapse).
- §5.2.6 Report export to PDF → **delivered** (Markdown + browser-print PDF).
- §5.2.4 reworded: API CTI + firmware-CVE axes delivered; dark-web/Robin remains optional/future.
- §5.1.2 added firmware-CVE, report builder, Settings to "what was achieved"; §5.1.3 numbers → run #25/26/43.

## 3. Diagrams (Phase 4)
- **Created** professional TikZ diagrams replacing placeholders: **Use-Case** (3 actors × 13 use cases),
  **Misuse-Case** (threat actor + misuse/mitigation with «threatens»/«mitigates»), **Class diagram**
  (connector/normalization/anomaly/risk/CTI/report classes, verified against code).
- **Redrew the ERD** from the real Schema-v4 (~25 entities incl. the post-freeze tables) and placed it as a
  rotated full-page **landscape** figure (`sidewaysfigure`) so it is legible (the original was a tiny,
  unreadable 10-box sketch with a non-existent table).
- **Scaled** the Data-Flow and Context diagrams to `\textwidth` (were overflowing 100–186pt).
- Sequence, architecture, pipeline, lab-topology diagrams verified legible.

## 4. Screenshots (Phase 4) — live app, light mode
Captured from the running app (port 5175) via headless Chrome, light theme, **Cisco removed** so the UI
matches the FortiGate+Palo-Alto-only scope. Embedded (framed) replacing the 6 `\uiplaceholder` boxes:
Dashboard, Policy Audit, SOC Reports, Topology, Risk Posture, Benchmark Center — plus a new **Settings**
figure. A note was added that the screenshots are from the bundled **NovaTech demonstration tenant** (the
quantitative results in §4.15 are from the live lab). The SOC-Reports and Benchmark screens show their
demo/empty state because the lab firewall VMs were down during this pass (so no live analysis run with
findings); the authoritative run-#25 scorecard lives in the §4.15 text/tables, and the figure prose was
reworded to state the run-#25 values as facts rather than "the figure shows".

## 5. Tables & overflow (Phase 4)
- Rebuilt/repaired every broken or overflowing table: §2.3.6 comparative (rotated vendor headers),
  §3.3.3 privileges, §3.5 intended-technologies, §3.6 entity-descriptions (column collision fixed),
  §3.11 misuse-cases, §4.6.5 anomaly-taxonomy, §4.10 REST endpoints, §4.13 unit-tests, §4.15.1
  representative cases, §4.15.2 type-distribution — using `xltabular`/`X` columns, `tabularx`,
  right-sized `p{}`/cm widths, rotated headers, and `\footnotesize`/`\small` where needed.
- Acronym longtable: added a repeating header (`\endhead`) and tightened to a single page.
- Long inline `\texttt{}`/`\path{}` and the risk equation (split with `aligned`) no longer overflow.

## 6. Remaining items (transparent)
- **4 Overfull \hbox**, all ≤7.4pt (≤2.6 mm), in the REST-endpoint table — two rows double-counted via the
  repeating longtable header (≈2 distinct rows). Cause: unbreakable `/` characters in URL paths. A global
  breakable-slash would corrupt `\includegraphics{figures/…}` paths, so this was left rather than risk the
  embedded screenshots; the protrusion is sub-perceptible in print.
- SOC-Reports and Benchmark screenshots show demo/empty states (lab VMs down). To show the populated
  run-#25 Benchmark scorecard and a generated SOC report, re-capture on the live lab and overwrite
  `figures/ui-benchmark.png` and `figures/ui-reports.png` (same filenames; no LaTeX edit needed).
- A few legitimate chapter-end short pages (normal for `report` class).

## 7. NEEDS-HUMAN-INPUT
None blocking. Optional: re-capture the Benchmark/SOC-Reports screenshots on the live two-vendor lab for
fully-populated figures (filenames above).
