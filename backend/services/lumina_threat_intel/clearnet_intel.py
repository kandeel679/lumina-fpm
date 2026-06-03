"""Clearnet threat-intel connectors (source registry Group C).

Deterministic, NO LLM, NO Tor, NO content-blocking, NO API cost. Seeds real,
authoritative CVE findings scoped to the customer's firewall vendors from public
feeds. v1 = CISA KEV (actively-exploited vulns). Extensible to NVD / vendor
PSIRT (see sources.CLEARNET_FEEDS).

Findings are produced in the same dict shape as the LLM Findings call, so they
flow through correlation / diff / persistence unchanged.
"""
from __future__ import annotations

import datetime
import logging
import os
from typing import Any, Optional

import requests
from sqlalchemy.orm import Session

from models.models import FirewallDevice
from .sources import CLEARNET_FEEDS

logger = logging.getLogger(__name__)

NVD_LOOKBACK_DAYS = int(os.getenv("LTI_NVD_LOOKBACK_DAYS", "120"))  # NVD window max 120
# Customer vendor (lowercased substring) -> NVD url key in sources.CLEARNET_FEEDS
_NVD_VENDOR_KEY = {"fortinet": "fortios", "palo alto": "pan_os", "cisco": "cisco_asa"}

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


def _customer_nvd_keys(db: Session, device_ids: Optional[list[int]]) -> set[str]:
    q = db.query(FirewallDevice)
    if device_ids:
        q = q.filter(FirewallDevice.device_id.in_(device_ids))
    keys: set[str] = set()
    for d in q.all():
        vname = ((d.vendor.name if d.vendor else "") or "").strip().lower()
        for token, urlkey in _NVD_VENDOR_KEY.items():
            if token in vname:
                keys.add(urlkey)
    return keys


def _cvss_to_criticality(score: Optional[float], severity: Optional[str]) -> str:
    if severity and severity.lower() in ("critical", "high", "medium", "low"):
        return severity.lower()
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def fetch_nvd_findings(
    db: Session,
    device_ids: Optional[list[int]] = None,
    timeout: int = 25,
    per_vendor_cap: int = 15,
) -> list[dict[str, Any]]:
    """Recent NVD CVEs per customer firewall product (CVSS-scored), last N days."""
    keys = _customer_nvd_keys(db, device_ids)
    if not keys:
        return []
    end = datetime.datetime.utcnow()
    start = end - datetime.timedelta(days=NVD_LOOKBACK_DAYS)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    out: list[dict[str, Any]] = []
    for urlkey in keys:
        base = CLEARNET_FEEDS["nvd"]["urls"].get(urlkey)
        if not base:
            continue
        url = (f"{base}&pubStartDate={start.strftime(fmt)}"
               f"&pubEndDate={end.strftime(fmt)}&resultsPerPage={per_vendor_cap}")
        try:
            r = requests.get(url, timeout=timeout)
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            logger.warning("NVD fetch failed for %s: %s", urlkey, str(e)[:120])
            continue
        for item in data.get("vulnerabilities", [])[:per_vendor_cap]:
            cve = item.get("cve", {})
            cid = cve.get("id", "")
            desc = next((d.get("value", "") for d in cve.get("descriptions", [])
                         if d.get("lang") == "en"), "")
            score = sev = None
            metrics = cve.get("metrics", {})
            for mk in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(mk):
                    cd = metrics[mk][0].get("cvssData", {})
                    score = cd.get("baseScore")
                    sev = cd.get("baseSeverity")
                    break
            crit = _cvss_to_criticality(score, sev)
            out.append({
                "category": "exploit",
                "criticality": crit,
                "severity": "low" if crit == "info" else crit,
                "relevance_score": 50,
                "relevance_band": "medium",
                "relevance_reason": f"NVD CVE for {urlkey.replace('_', '-')} (customer product)",
                "confidence": 90,
                "title": f"{cid}: {desc[:120]}".strip()[:512],
                "description": desc[:1000],
                "iocs": [{"type": "cve", "value": cid}] if cid else [],
                "source": {
                    "onion_url": None, "search_engine": None, "scraped_at": None,
                    "raw_excerpt": desc[:500], "page_title": "NVD",
                    "marketplace_or_forum": "NVD (NIST)",
                },
                "recommended_actions": ["Review vendor advisory and patch affected versions"],
                "tags": ["nvd", "cve"],
            })
    logger.info("NVD: %d recent CVE findings for customer products", len(out))
    return out


def fetch_clearnet_findings(
    db: Session,
    device_ids: Optional[list[int]] = None,
) -> list[dict[str, Any]]:
    """All clearnet connectors, merged + de-duplicated by CVE.

    KEV (actively-exploited) takes priority; NVD adds recent CVSS-scored CVEs not
    already in KEV. Extensible to vendor PSIRT (see sources.CLEARNET_FEEDS).
    """
    findings: list[dict[str, Any]] = []
    seen_cves: set[str] = set()

    def _add(items: list[dict[str, Any]]) -> None:
        for f in items:
            cves = [i.get("value", "").upper() for i in f.get("iocs", []) if i.get("type") == "cve"]
            primary = cves[0] if cves else None
            if primary and primary in seen_cves:
                continue
            if primary:
                seen_cves.add(primary)
            findings.append(f)

    try:
        _add(fetch_kev_findings(db, device_ids))
    except Exception as e:
        logger.error("KEV connector failed: %s", str(e)[:150])
    try:
        _add(fetch_nvd_findings(db, device_ids))
    except Exception as e:
        logger.error("NVD connector failed: %s", str(e)[:150])
    return findings
