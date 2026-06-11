"""Dark-web AGGREGATOR connectors (free, deterministic, no Tor, no LLM).

These query public services that already monitor `.onion` infrastructure —
real dark-web-sourced data without authenticating to or scraping any dark-web
site ourselves. v1 = Ransomware.live (tracks ~80 ransomware leak sites / DLS).

Findings use the same dict shape as clearnet_intel.py, so they flow through
correlation / diff / persistence unchanged. The orchestrator merges them right
after the clearnet findings.

Honest scope: this checks whether the CUSTOMER (org domains) appears on
ransomware leak sites. It does not provide vendor/CVE exploit chatter — that
remains the (paid-only) gap documented in CLAUDE.md.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Optional

import requests
from sqlalchemy.orm import Session

from .keyword_extractor import extract_keywords

logger = logging.getLogger(__name__)

RANSOMWARELIVE_API = os.getenv("LTI_RANSOMWARELIVE_API", "https://api.ransomware.live/v2")
# Free API is rate-limited (~1 req/min/endpoint); keep the request budget tiny.
MAX_DOMAIN_LOOKUPS = int(os.getenv("LTI_RANSOMWARELIVE_MAX_LOOKUPS", "5"))

_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def _org_domains(db: Session, device_ids: Optional[list[int]]) -> list[str]:
    """Customer org domains from the inventory, excluding the bare IPs that
    keyword_extractor's `ip-netmask` objects can leave in org_domains."""
    bundle = extract_keywords(db, device_ids)
    out = []
    for d in bundle.get("org_domains", []):
        d = d.strip().lower().rstrip(".")
        if _DOMAIN_RE.match(d) and any(c.isalpha() for c in d):
            out.append(d)
    return out[:MAX_DOMAIN_LOOKUPS]


def _victim_to_finding(victim: dict, matched_domain: str, confirmed: bool = True) -> dict[str, Any]:
    name = (victim.get("victim") or victim.get("post_title") or matched_domain).strip()
    group = (victim.get("group") or victim.get("group_name") or "unknown group").strip()
    discovered = victim.get("discovered") or victim.get("published") or victim.get("date")
    post_url = victim.get("post_url") or victim.get("claim_url") or victim.get("url")
    desc = (victim.get("description") or "").strip()
    excerpt = (f"Ransomware.live: victim '{name}' listed by group '{group}'"
               + (f" on {discovered}" if discovered else "")
               + (f". {desc}" if desc else "."))
    return {
        "category": "ransomware",
        "criticality": "critical" if confirmed else "high",
        "severity": "critical" if confirmed else "high",
        # Confirmed org-domain match on a leak site = maximum relevance; a
        # name-only similarity is surfaced as a possible match for a human to
        # verify (often a different company with a similar name).
        "relevance_score": 95 if confirmed else 50,
        "relevance_band": "high" if confirmed else "medium",
        "relevance_reason": (
            f"Customer domain '{matched_domain}' matches a victim listed on the "
            f"{group} ransomware leak site"
            if confirmed else
            f"POSSIBLE match: victim name resembles customer domain "
            f"'{matched_domain}' on the {group} leak site — verify manually "
            f"(may be an unrelated company with a similar name)"
        ),
        "confidence": 90,  # observed DLS post via an established aggregator
        "title": f"Ransomware leak-site listing: {name} ({group})"[:512],
        "description": excerpt[:1000],
        "iocs": [{"type": "domain", "value": matched_domain}],
        "source": {
            "onion_url": post_url if post_url and (".onion/" in post_url or post_url.endswith(".onion")) else None,
            "search_engine": None,
            "scraped_at": None,
            "raw_excerpt": excerpt[:500],
            "page_title": "Ransomware.live",
            "marketplace_or_forum": f"{group} leak site (via Ransomware.live)",
        },
        "recommended_actions": (
            [
                "[IMMEDIATE] Activate incident response / ransomware playbook "
                f"(target: {matched_domain})",
                "[IMMEDIATE] Verify offline backups and isolate suspect segments "
                f"(target: {matched_domain})",
            ] if confirmed else [
                f"[24H] Verify whether leak-site victim '{name}' is your "
                f"organization (target: {matched_domain})",
            ]
        ),
        "tags": (["dark-web", "leak-site", "ransomware", group.lower().replace(" ", "-")]
                 + ([] if confirmed else ["possible-match"])),
    }


def fetch_ransomware_dls_findings(
    db: Session,
    device_ids: Optional[list[int]] = None,
    timeout: int = 15,
) -> tuple[list[dict[str, Any]], int]:
    """Check ransomware leak sites (via Ransomware.live) for the customer's
    org domains. Returns (findings, domains_checked) — the count feeds the
    report's coverage_note even when the result is the good kind of empty.
    """
    domains = _org_domains(db, device_ids)
    if not domains:
        logger.info("Ransomware.live: no org domains in inventory — skipped")
        return [], 0

    # Leak sites list victims by COMPANY NAME, not domain, and the API 404s on
    # zero-hit terms — so search by the registrable org-name label ("novatech"
    # for vpn.novatech.com) and verify matches against the full domains locally.
    # Subdomains share a label, so this also collapses N domains into few requests.
    terms: dict[str, str] = {}  # label -> registrable domain (for reporting)
    for dom in domains:
        parts = dom.split(".")
        label = parts[-2] if len(parts) >= 2 else parts[0]
        if len(label) >= 4:
            terms.setdefault(label, ".".join(parts[-2:]))
    findings: list[dict[str, Any]] = []
    checked = 0
    for label, reg_domain in list(terms.items())[:MAX_DOMAIN_LOOKUPS]:
        url = f"{RANSOMWARELIVE_API}/searchvictims/{label}"
        try:
            resp = requests.get(url, timeout=timeout)
            if resp.status_code == 404:  # no victims match this term
                checked += 1
                continue
            if resp.status_code == 429:
                logger.warning("Ransomware.live rate-limited; stopping after %d/%d terms",
                               checked, len(terms))
                break
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.warning("Ransomware.live lookup failed for %s: %s", label, str(e)[:120])
            continue
        checked += 1
        victims = data if isinstance(data, list) else data.get("victims", []) or []
        for v in victims:
            hay = " ".join(
                str(v.get(k, "")) for k in ("victim", "domain", "website", "post_title")
            ).lower()
            # A full-domain hit is a confirmed customer listing; a name-only
            # similarity (e.g. an unrelated "Novatech Engineering" vs
            # novatech.com) is a POSSIBLE match for human verification.
            matched = next((d for d in domains if d in hay), None)
            if matched:
                findings.append(_victim_to_finding(v, matched, confirmed=True))
            elif label in hay:
                findings.append(_victim_to_finding(v, reg_domain, confirmed=False))

    logger.info("Ransomware.live: %d leak-site finding(s) across %d term(s) checked",
                len(findings), checked)
    return findings, checked
