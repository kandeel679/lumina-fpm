"""Clearnet threat-intel connectors (source registry Group C).

Deterministic, NO LLM, NO Tor, NO content-blocking, NO API cost. Seeds real,
authoritative CVE findings scoped to the customer's firewall vendors from public
feeds. v1 = CISA KEV (actively-exploited vulns). Extensible to NVD / vendor
PSIRT (see sources.CLEARNET_FEEDS).

Findings are produced in the same dict shape as the LLM Findings call, so they
flow through correlation / diff / persistence unchanged.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

import requests
from sqlalchemy.orm import Session

from models.models import FirewallDevice
from .sources import CLEARNET_FEEDS

logger = logging.getLogger(__name__)

# Customer vendor name (lowercased substring) -> FIREWALL-PRODUCT match tokens.
# Deliberately product-specific (not bare vendor names) so we don't pull
# unrelated products (e.g. Cisco Catalyst SD-WAN, FortiClient EMS).
_VENDOR_MATCH = {
    "fortinet": ["fortios", "fortigate"],
    "palo alto": ["pan-os", "globalprotect"],
    "cisco": ["adaptive security appliance", "secure firewall"],
}


def _customer_vendor_tokens(db: Session, device_ids: Optional[list[int]]) -> set[str]:
    """Match tokens for the vendors actually present in the customer inventory."""
    q = db.query(FirewallDevice)
    if device_ids:
        q = q.filter(FirewallDevice.device_id.in_(device_ids))
    tokens: set[str] = set()
    for d in q.all():
        vname = ((d.vendor.name if d.vendor else "") or "").strip().lower()
        for key, toks in _VENDOR_MATCH.items():
            if key in vname:
                tokens.update(toks)
    return tokens


def fetch_kev_findings(
    db: Session,
    device_ids: Optional[list[int]] = None,
    timeout: int = 20,
) -> list[dict[str, Any]]:
    """CISA Known Exploited Vulnerabilities, filtered to the customer's vendors."""
    vendor_tokens = _customer_vendor_tokens(db, device_ids)
    if not vendor_tokens:
        return []

    url = CLEARNET_FEEDS["cisa_kev"]["urls"]["all"]
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.warning("CISA KEV fetch failed: %s", str(e)[:150])
        return []

    findings: list[dict[str, Any]] = []
    for v in data.get("vulnerabilities", []):
        hay = f"{v.get('vendorProject', '')} {v.get('product', '')}".lower()
        if not any(tok in hay for tok in vendor_tokens):
            continue

        cve = v.get("cveID", "")
        ransom = (v.get("knownRansomwareCampaignUse", "") or "").strip().lower() == "known"
        vendor_product = f"{v.get('vendorProject', '')} {v.get('product', '')}".strip()
        required = v.get("requiredAction", "Patch per vendor advisory")

        findings.append({
            "category": "exploit",
            # KEV = confirmed actively-exploited -> at least high; ransomware -> critical
            "criticality": "critical" if ransom else "high",
            "severity": "critical" if ransom else "high",
            # Vendor present in inventory -> medium baseline; correlator upgrades
            # to high if a device's firmware is implicated.
            "relevance_score": 60,
            "relevance_band": "medium",
            "relevance_reason": f"CISA KEV actively-exploited vuln in {vendor_product}; customer runs this vendor",
            "confidence": 95,  # authoritative government feed
            "title": (f"{cve}: {v.get('vulnerabilityName', '')}")[:512],
            "description": (
                (v.get("shortDescription", "") or "")
                + (f" Required action: {required}" if required else "")
            ).strip(),
            "iocs": [{"type": "cve", "value": cve}] if cve else [],
            "source": {
                "onion_url": None,
                "search_engine": None,
                "scraped_at": None,
                "raw_excerpt": (v.get("shortDescription", "") or "")[:500],
                "page_title": "CISA KEV",
                "marketplace_or_forum": "CISA Known Exploited Vulnerabilities",
            },
            "recommended_actions": (
                [required] + (["Activate ransomware IR readiness / verify backups"] if ransom else [])
            ),
            "tags": ["cisa-kev", "actively-exploited"] + (["ransomware"] if ransom else []),
        })

    logger.info("CISA KEV: %d findings match customer vendors", len(findings))
    return findings


def fetch_clearnet_findings(
    db: Session,
    device_ids: Optional[list[int]] = None,
) -> list[dict[str, Any]]:
    """All clearnet connectors, merged. v1 = CISA KEV.

    Extensible: add NVD (per-vendor CPE) and vendor PSIRT feeds here — see
    sources.CLEARNET_FEEDS for the validated endpoints.
    """
    findings: list[dict[str, Any]] = []
    try:
        findings.extend(fetch_kev_findings(db, device_ids))
    except Exception as e:
        logger.error("KEV connector failed: %s", str(e)[:150])
    return findings
