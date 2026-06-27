# LuminaFPM Documentation — Audit Findings

Build: TeX Live (Docker) + PyMuPDF raster. Baseline compile = **104 pages**, 0 errors, 0 undefined refs,
0 multiply-defined labels, 0 LaTeX warnings, 0 underfull, **119 Overfull \hbox** (with `\hfuzz=30pt` still
set — so every reported box overflows by >30pt; these are real, visible defects).

## A. LaTeX build health
- [x] Compiles clean (pdflatex, 3 passes), refs/TOC/LoF/LoT resolve.
- [ ] 119 Overfull \hbox to eliminate (list below). 0 Overfull vbox. 0 Underfull.
- Note: preamble sets `\hfuzz=30pt \hbadness=10000` — masks sub-30pt overflow. Plan: after fixing the big
  ones, lower `\hfuzz` to ~2pt and re-mine to catch the rest; final target = no visible overflow.

## B. Overfull \hbox grouped by section (post-edit .tex line ranges; map by content, not raw line)
TABLES (cells too wide / columns too narrow):
- §2.3.6 Comparative Feature Analysis (~621–626): 5 boxes ≤16.6pt — SEED.
- §3.5 Intended Technologies (~850): 62–79pt — SEED.
- §3.14.1 Entity Descriptions table (~1255–1289): many, incl 68–149pt — big overflow.
- §4.6.5 Anomaly taxonomy longtable (~1577–1603): ~20 rows, 8–39pt each — SEED.
- §4.10 Backend API longtable (~1644–1670): incl 157pt cell — SEED.
- §4.13 Unit-test table (~1747–1753): 11–30pt — SEED.
- §4.15.1 Representative rule cases longtable (~1812–1818): 8–26pt rows — SEED.
- §4.15.2 Type-distribution table (~1854): 83pt (long anomaly-type name in narrow col).
- §3.2 Methodology (~768–775): 45–128pt — likely a wide table/list — CHECK.
- §1.4.4 Included/Excluded Scope — SEED (not in overfull list at hfuzz=30 → re-check at hfuzz=2).
- §3.3.3 Auditor/Viewer — SEED — re-check.
- §3.7.6 Portability — SEED — re-check.
- §4.3 Project Structure listing — SEED — re-check.

TIKZ DIAGRAMS overflowing (too wide → scale/resize/redraw):
- §3.9 System Architecture (~1031–1059): 40–66pt.
- §3.11 Misuse Case (~1111–1120): 36–76pt (currently placeholder per README).
- §3.12 Context Diagram (~1119–1121).
- §3.13 Data Flow Diagram (~1189–1193): 116–186pt — badly overflowing.
- §3.14 ERD (~1206): 59pt — REDRAW anyway.
- §3.16 Sequence Diagram (~1346): 49–71pt.

LONG INLINE \texttt{}/\path{} IN PROSE (unbreakable long tokens):
- §4.4 Acquisition (~1466–1474): up to 150pt (xpaths/URLs).
- §4.5 Parsing/Normalization (~1489–1494): 47–62pt.
- §4.6.2 / §4.6.4 cross-device (~1552–1566): 166pt (long function names).
- §4.7 Risk display equation (~1616): 123pt — the \[...\] risk formula too wide.
- §4.8 CTI (~1626–1629), §4.10 (~1679–1691), §4.12 (~1722), §4.14 (~1764–1780), §4.15.4 (~1881–1890): 30–72pt.
- Fix approach: make typewriter breakable at separators (preamble helper / \allowbreak), or move long
  literals to displayed listings; break the risk equation across lines (split/multline or smaller).

## C. Phase-1 code⇄doc reconciliation (ground truth in scratchpad/GROUND_TRUTH.md)
DONE:
- [x] Removed leaked agent meta-commentary line ("Above is the complete LaTeX body content…").
- [x] §4.9 PROMPT_VERSION 1.0 → 2.1 (+ prose-only / names-not-IDs disciplines).
- [x] §4.13 "eight"→"eleven" test files; added test_benchmark_matrix / test_vuln / test_scheduling rows.
- [x] §4.11 topology = Cytoscape.js (draggable/persistent); Settings = functional (Firewalls/Scheduling/
      Notifications); two-axis Threat Center; deps paragraph (Cytoscape now used).
TODO:
- [ ] §4.2 dev-env: "five active services" → six (+celery_beat); note tor-proxy present for online CTI.
- [ ] §4.7 Risk: add device-scope firmware_modifier (crit40/high30/med18/low10), NOT a 9th factor.
- [ ] §4.8 CTI: add Axis-2 firmware-CVE device intelligence (vuln_intel/vuln_runner, cve_reference.json 5
      CVEs, writes ZERO rule_anomaly, VULN_PROVIDER=offline default).
- [ ] §4.9 AI reporting: add deterministic report_builder (Remediation/Risk Posture/Firmware CVE/Per-Finding
      Evidence tables) + executive vs per-rule scopes + Markdown/PDF export. (Promotes Future-Work PDF item.)
- [ ] §4.10 API: add schedules, notifications, reports/markdown endpoints; note ~99 endpoints, no auth.
- [ ] NEW §4.12 (or sub): Settings device management + Scheduling (schedule_config + Celery Beat
      scheduler.tick 60s + interval/cron + run-now) + in-app Notifications.
- [ ] §4.14 Findings: topology limitation now RESOLVED (Cytoscape); disabled_rule_review NOW exercised
      (PA_DISABLED_RISKY) — only object_sprawl remains un-exercised.
- [ ] §4.15 Test Cases: run #18 → #25; 47 cases → 43; 20 rules → 26 (10 FGT + 16 PA); rebuild
      type-distribution table (per GROUND_TRUTH: 13 types, totals 43); device risk FGT 96+fw40→100 / PA
      100+fw30→100; firmware CVEs FGT v7.0.5→CVE-2024-21762, PA 11.1.6-h7→CVE-2025-0108; CTI threat_exposure
      on FGT_ANY_DB + PA_ALLOW_MALICIOUS (NOT FGT_ALLOW_MALICIOUS, which doesn't exist).
- [ ] §5.1 Conclusion: update numbers (run #25/43/26); add firmware-CVE axis, report builder, Settings as
      achievements. §5.1.3 "54 findings/20 rules/47 cases" → corrected.
- [ ] §5.2 Future Work: PROMOTE done items — 5.2.1 Cytoscape topology (DONE), 5.2.6 PDF export (DONE);
      reword 5.2.4 dark-web (API CTI + firmware axis delivered; Robin/dark-web still optional), 5.2.3
      taxonomy (14 detectors shipped), 5.2.7 operator topology (FG asset auto-placement done).
- [ ] ERD (§3.14) must add ~17 missing tables (schedule_config, notification, llm_report, rule_service_
      mapping, cti_*, benchmark_*, risk_assessment, normalized_*, rule_snapshot, anomaly_execution_log,
      normalization_warning, device_credential) + new cols (use_http, vendor_type, firmware_version).

## D. Required deliverables
Diagrams (TikZ, print-res, derive from code): Use Case (§3.10), Misuse (§3.11), Class (§3.15), redraw
Network Topology (§3.* virtual env) + ERD (§3.14).
Screenshots (live app, LIGHT mode) replacing \uiplaceholder: Dashboard (fig:ui-dashboard), Audit+Inspector
(fig:ui-audit), SOC Reports (fig:ui-reports), Benchmark (fig:ui-benchmark), Risk (fig:ui-risk); plus
Topology (fig:ui-topology) bonus. Also Settings/Scheduling/Notifications screenshot for the new section.

## E. Visual audit (per-page, from rasters; PDF page numbers)
BROKEN TABLES (text overlap / merged headers / column collision) — HIGH:
- p.34-35 Table 2.1 Comparative feature analysis: headers merged ("LuminaAlgoSec FireMonSkybox Panorama"). SEED 2.3.6.
- p.64-65 Table 3.6 Entity Descriptions: PK column collides with attributes ("normalized_devnetwork_object"). SEED 3.14.1.
- p.65/78/79 Table 4.x anomaly taxonomy: first col cramped, collides with Description; header "DetectionPolicy mode rule" jammed; last row dangling. SEED 4.6.5.
- p.82 REST endpoints: "reason required for the latter three." overflows right margin. SEED 4.10. (p.84 also tight.)
- p.92 Table 4.5 representative cases: header corrupted/overlapping (rule tokens over "Engine findings"). SEED 4.15.1.
- p.45-46 privileges/responsibilities table: continuation header not repeating, 2-row tail. SEED 3.3.3.
FIGURE PLACEHOLDERS (gray boxes — need real content):
- p.56 Use Case (diagram), p.57 Misuse Case (diagram) — CREATE.
- p.85 Dashboard, p.86 Policy Audit+Inspector & SOC Reports, p.87 Network Topology (UI), p.93 Benchmark, p.94 Risk — SCREENSHOTS.
DIAGRAMS LOW-QUALITY/OVERFLOW (redraw/scale):
- p.61 Data Flow Diagram cramped+overflow; p.63 ERD cardinality labels crowding (REDRAW); p.66 sequence diagram very wide; p.28 pipeline big blank band + awkward node hyphenation; p.99/102 Ch5 figures cramped.
LAYOUT:
- p.27 near-empty page (1.9.6 Environmental stranded); p.67 near-empty + stray "—" line; p.103 near-empty (Future Work tail).
- p.51 FR table 2-row orphan tail above new section; figure float placement (p.28, p.63 top gap).
- p.12 acronym longtable continuation: header not repeating + 2 stranded rows.
CONTENT to verify:
- p.31 "0.0..0/0.0..0/0" — confirm intended 0.0.0.0/0 (possible typo/ligature).
- p.89 test table cites 192.168.50.0/24 AND .55.0/24 — confirm correct lab subnet.
INLINE-CODE/EQUATION OVERFLOW (per log §B): §4.4/4.5/4.6/4.7(risk eq 123pt)/4.8/4.10/4.14/4.15.4.
REFERENCES p.104: bare URLs not breaking → use \url/xurl.
GLOBAL FIX PLAN: add microtype + widow/club penalties + xurl (breakable URLs) + breakable \texttt; rewrite broken
tables with tabularx/p-columns/booktabs; split risk equation; scale/redraw diagrams; capture screenshots; fix
near-empty pages; then lower \hfuzz to ~2pt and re-mine.

## F. RESOLUTION (final state) — see CHANGES_REPORT.md for the full account
- Build: 106 pages, **0 errors, 0 LaTeX warnings, 0 undefined refs, 0 multiply-defined labels, 0 Overfull vbox,
  0 Underfull**. Overfull \hbox **119 → 4** (all ≤7.4pt ≈2.6mm; two endpoint-table rows double-counted via the
  repeating header; cause = unbreakable URL slashes, not globally fixable without corrupting \includegraphics paths).
- Phase 1 reconciliation: DONE (run #18→#25, 20→26 rules, 47→43 cases, firmware-CVE axis, report builder,
  Settings/Scheduling/Notifications section, schedules/notifications endpoints, PROMPT_VERSION 2.1, test files 8→11,
  Future-Work promotions). Leaked meta-line + stray "---" removed; mojibake check = none (the apparent "�" was a
  terminal print artifact; source uses proper em-dashes).
- Diagrams: Use-Case, Misuse-Case, Class created; ERD redrawn as a legible landscape (sidewaysfigure); DFD/Context
  scaled to fit. All judged GOOD by re-audit.
- Screenshots: 7 captured live in light mode (Cisco removed); 6 placeholders replaced + Settings figure added.
  Benchmark/SOC-Reports show demo/empty state (lab VMs down) — captioned honestly; re-capture on live lab to
  populate (overwrite figures/ui-benchmark.png, figures/ui-reports.png; no LaTeX change needed).
- Tables: all broken/overflowing tables (2.3.6, 3.3.3, 3.5, 3.6, 3.11, 4.6.5, 4.10, 4.13, 4.15.1, 4.15.2) rebuilt;
  acronym table given a repeating header and tightened to one page.
