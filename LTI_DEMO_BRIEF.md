# Lumina Threat Intel (LTI) — Demo Brief

**Audience:** stakeholders, security leadership, product discussion  
**Branch:** `feature/lti-agentic-optimization`  
**Stack:** `docker compose up -d` → frontend `:5173`, API `:8000`

---

## What LTI is

**Lumina Threat Intel** is the dark-web + clearnet module inside Lumina FPM. It scans Tor (curated `.onion` sources) and authoritative clearnet feeds (CISA KEV, NVD), then assesses each finding against the customer's **actual firewall inventory** — vendor, model, and installed firmware — so reports are dedicated to their system, not generic OSINT.

The scan pipeline runs in the Celery worker (~2 LLM calls per scan). Clearnet connectors are free and deterministic; they produce real CVEs even when Tor or the LLM gateway is down.

---

## Two-axis assessment model

Every finding is scored on two independent axes:

| Axis | Values | Meaning |
|------|--------|---------|
| **Criticality** | info · low · medium · high · critical | How severe the vulnerability is (CVSS, KEV status, exploit activity) |
| **Relevance** | none · low · medium · high | How closely it matches *this customer's* firewalls |

**Hybrid relevance:** the LLM proposes a 0–100 score + band; `correlator.py` then verifies against the live DB inventory and upgrades to **high** when installed firmware falls inside a CVE's affected version range or a rule/device match is confirmed.

**Clean posture:** `clean = true` only when **no** finding reached medium+ relevance — "your firewalls are clean relative to what we searched."

---

## Verified outcomes (NovaTech demo tenant)

Seeded inventory: 2× FortiOS 7.4.3, 2× PAN-OS 11.1.2 / 11.0.4, 1× Cisco ASA 9.18.3.

| Report | Highlights |
|--------|------------|
| **Report 7** | Latest completed scan — use **Latest scan** tab as the default demo view |
| **6 high FortiOS CVEs** | Version-aware correlation (P14): FortiOS 7.4.3 on FG-HQ-CORE-01 / FG-HQ-EDGE-01 upgraded to **high** relevance when NVD CPE ranges cover the installed patch |
| **62 clearnet findings** | CISA KEV + NVD (120-day window), product-scoped — reliable backbone at $0 |
| **`clean = false`** | Honest signal when medium+ relevance findings exist; paired with `coverage_note` narrative |
| **Dark web = 0 (typical)** | Noise filtered at search + content relevance; clearnet still lands |

Run a fresh scan from the UI: **Threat Intelligence → Run threat scan** (SSE progress bar, ~2 LLM calls).

---

## Demo URLs

| View | URL hash |
|------|----------|
| Latest scan (default tab) | `#threats?tab=scan` |
| Advisories table | `#threats?tab=advisories` |
| High-relevance filter | `#threats?tab=advisories&relevance=high` |
| CISA KEV only | `#threats?tab=advisories&kev=1` |
| Critical severity | `#threats?tab=advisories&severity=critical` |
| Single CVE inspector | `#threats?cve=CVE-2025-55018` |

Login: security key (primary) or password `demo` + MFA `123456`.

---

## Cost note

- **Budget cap:** $20 soft limit (`LTI_BUDGET_USD`); spend tracked in `.lti_budget_state.json`
- **Default path:** Gemini free tier (~2 calls/scan, 5 req/min) or DeepSeek when `DEEPSEEK_API_KEY` is set
- **Clearnet:** $0 always (NVD + CISA KEV, no LLM)
- **Testing discipline:** prefer `docker exec lumina-fpm-api-1 python services/lumina_threat_intel/test_ground.py` for pipeline checks before burning UI scans

---

## Open roadmap

See **`LTI_PROGRESS_AND_FIXES.md`** (full problem→fix history) and **`CLAUDE.md`** (engineering handoff). Next items:

1. **PSIRT connectors** — Palo Alto JSON + Fortinet RSS (no auth); Cisco PSIRT needs customer API creds
2. **DeepSeek backup** — set `DEEPSEEK_API_KEY` for permissive, cheap LLM fallback
3. **Group-B browse-only sources** — read-only listing monitoring (carefully scoped; legal/honeypot risk)
4. **Richer dark-web yield** — better-curated `.onion` sources, not more LLM calls
