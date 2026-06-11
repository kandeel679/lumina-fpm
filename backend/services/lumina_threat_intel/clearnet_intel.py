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
import re
from typing import Any, Optional

import requests
from sqlalchemy.orm import Session

from models.models import FirewallDevice
from .sources import CLEARNET_FEEDS

logger = logging.getLogger(__name__)

NVD_LOOKBACK_DAYS = int(os.getenv("LTI_NVD_LOOKBACK_DAYS", "120"))  # NVD window max 120
# Customer vendor (lowercased substring) -> NVD url key in sources.CLEARNET_FEEDS
_NVD_VENDOR_KEY = {"fortinet": "fortios", "palo alto": "pan_os", "cisco": "cisco_asa"}

# NVD url key -> CPE product tokens (substring of the cpeMatch `criteria`). Used to
# keep only the version ranges that apply to the CUSTOMER'S product, not other
# products that may appear in the same CVE configuration (e.g. FortiProxy).
_NVD_PRODUCT_CPE = {
    "fortios": [":fortinet:fortios:"],
    "pan_os": [":paloaltonetworks:pan-os:"],
    "cisco_asa": [":cisco:adaptive_security_appliance:", ":cisco:asa:"],
}


def _extract_affected_ranges(cve: dict, product_cpe_tokens: list[str]) -> list[dict]:
    """Pull CPE version ranges (versionStart/EndIncluding/Excluding or an exact
    version) for the customer's product from an NVD CVE's `configurations`.

    Only `vulnerable: true` matches whose CPE `criteria` names the customer's
    product are kept, so the correlator can later test whether the device's
    installed firmware actually falls inside an affected range (P11 -> high).
    """
    ranges: list[dict] = []
    for cfg in cve.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable"):
                    continue
                crit = (m.get("criteria") or "").lower()
                if product_cpe_tokens and not any(t in crit for t in product_cpe_tokens):
                    continue
                rng = {
                    "startIncl": m.get("versionStartIncluding"),
                    "startExcl": m.get("versionStartExcluding"),
                    "endIncl": m.get("versionEndIncluding"),
                    "endExcl": m.get("versionEndExcluding"),
                }
                parts = crit.split(":")
                exact = parts[5] if len(parts) > 5 else "*"
                if exact not in ("*", "-", ""):
                    rng["exact"] = exact
                if any(rng.get(k) for k in ("startIncl", "startExcl", "endIncl", "endExcl")) or "exact" in rng:
                    ranges.append({k: v for k, v in rng.items() if v})
    return ranges

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
        # Urgency prefix (shared action format): ransomware use or a CISA
        # remediation due date that has already passed -> IMMEDIATE; otherwise
        # 24H (KEV is actively exploited by definition).
        due = (v.get("dueDate") or "").strip()
        overdue = bool(due) and due <= datetime.date.today().isoformat()
        urgency = "IMMEDIATE" if (ransom or overdue) else "24H"

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
                [f"[{urgency}] {required} (target: {cve or vendor_product})"]
                + (["[IMMEDIATE] Activate ransomware IR readiness / verify backups "
                    f"(target: {vendor_product})"] if ransom else [])
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
            affected_ranges = _extract_affected_ranges(cve, _NVD_PRODUCT_CPE.get(urlkey, []))
            out.append({
                "category": "exploit",
                "criticality": crit,
                "severity": "low" if crit == "info" else crit,
                # NVD = recent CVE for the vendor's product, but NOT confirmed
                # actively-exploited and NOT version-matched -> low baseline.
                # The correlator upgrades to high on a real firmware/IOC match,
                # so the "clean" state stays achievable (only CISA KEV at medium
                # and version/IOC matches raise a FW above the clean threshold).
                "relevance_score": 25,
                "relevance_band": "low",
                "relevance_reason": f"NVD CVE for {urlkey.replace('_', '-')} (customer product); not version-confirmed",
                "confidence": 90,
                "title": f"{cid}: {desc[:120]}".strip()[:512],
                "description": desc[:1000],
                "iocs": [{"type": "cve", "value": cid}] if cid else [],
                "source": {
                    "onion_url": None, "search_engine": None, "scraped_at": None,
                    "raw_excerpt": desc[:500], "page_title": "NVD",
                    "marketplace_or_forum": "NVD (NIST)",
                },
                "recommended_actions": [
                    f"[SCHEDULED] Review vendor advisory and patch affected versions (target: {cid})"
                ],
                "tags": ["nvd", "cve"],
                # Internal hints for the correlator (stripped at persistence; not a
                # schema field). Lets version-aware correlation upgrade to high when
                # the installed firmware is inside an affected CPE range.
                "_affected_ranges": affected_ranges,
                "_nvd_product": urlkey,
            })
    logger.info("NVD: %d recent CVE findings for customer products", len(out))
    return out


PAN_PSIRT_API = "https://security.paloaltonetworks.com/json"
FORTINET_PSIRT_RSS = "https://www.fortiguard.com/rss/ir.xml"
_PSIRT_HEADERS = {"User-Agent": "Mozilla/5.0 (LuminaFPM-LTI)"}
_CVE_ID_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def _psirt_urgency(criticality: str) -> str:
    return {"critical": "IMMEDIATE", "high": "24H"}.get(criticality, "SCHEDULED")


def fetch_paloalto_psirt_findings(
    db: Session,
    device_ids: Optional[list[int]] = None,
    timeout: int = 25,
    per_version_cap: int = 10,
) -> list[dict[str, Any]]:
    """Palo Alto PSIRT advisories, queried PER INSTALLED PAN-OS VERSION.

    The vendor API filters by exact version (?product=PAN-OS&version=PAN-OS X),
    so every advisory returned is VENDOR-CONFIRMED to affect the installed
    firmware -> relevance high without any local range math. Free, no auth.
    """
    q = db.query(FirewallDevice)
    if device_ids:
        q = q.filter(FirewallDevice.device_id.in_(device_ids))
    versions: set[str] = set()
    for d in q.all():
        vname = ((d.vendor.name if d.vendor else "") or "").lower()
        if "palo alto" in vname and d.firmware_version:
            versions.add(d.firmware_version.strip())
    out: list[dict[str, Any]] = []
    for ver in sorted(versions):
        try:
            r = requests.get(
                PAN_PSIRT_API,
                params={"product": "PAN-OS", "version": f"PAN-OS {ver}",
                        "sort": "-date"},
                headers=_PSIRT_HEADERS, timeout=timeout)
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            logger.warning("PAN PSIRT fetch failed for %s: %s", ver, str(e)[:120])
            continue
        items = data if isinstance(data, list) else data.get("advisories", []) or []
        for adv in items[:per_version_cap]:
            aid = adv.get("ID", "")
            sev = (adv.get("baseSeverity") or adv.get("threatSeverity") or "").lower()
            crit = sev if sev in ("critical", "high", "medium", "low") else "medium"
            problem = next((p.get("value", "") for p in adv.get("problem", [])
                            if p.get("lang") == "en"), "")
            # fixed[] aligns with version[]; surface the fix for the installed branch
            branch = ".".join(ver.split(".")[:2])
            fixed = ""
            for v_label, fx in zip(adv.get("version", []), adv.get("fixed", [])):
                if v_label.replace("PAN-OS ", "") == branch:
                    fixed = fx
                    break
            urgency = _psirt_urgency(crit)
            out.append({
                "category": "exploit",
                "criticality": crit,
                "severity": "low" if crit == "info" else crit,
                # The vendor itself filtered by installed version -> confirmed.
                "relevance_score": 90,
                "relevance_band": "high",
                "relevance_reason": (
                    f"Palo Alto PSIRT lists installed PAN-OS {ver} as affected "
                    f"by this advisory"
                ),
                "confidence": 95,  # authoritative vendor feed
                "title": f"{aid}: {adv.get('title', '')}"[:512],
                "description": problem[:1000],
                "iocs": ([{"type": "cve", "value": aid}]
                         if aid.upper().startswith("CVE-") else []),
                "source": {
                    "onion_url": None, "search_engine": None, "scraped_at": None,
                    "raw_excerpt": problem[:500],
                    "page_title": "Palo Alto PSIRT",
                    "marketplace_or_forum": "Palo Alto Networks Security Advisories",
                },
                "recommended_actions": [
                    f"[{urgency}] Upgrade PAN-OS on affected devices "
                    f"(target: {fixed or 'per vendor advisory'})"
                ],
                "tags": ["psirt", "palo-alto", "vendor-advisory", "version-confirmed"],
            })
    logger.info("PAN PSIRT: %d advisories affect installed PAN-OS versions", len(out))
    return out


def fetch_fortinet_psirt_findings(
    db: Session,
    device_ids: Optional[list[int]] = None,
    timeout: int = 20,
    cap: int = 15,
) -> list[dict[str, Any]]:
    """Fortinet PSIRT IR advisories (RSS). Free, no auth.

    The RSS is not version-filtered, so relevance starts low (like NVD) and the
    correlator/analyst confirms. Only items naming the customer's Fortinet
    firewall products are kept.
    """
    import xml.etree.ElementTree as ET

    vendor_tokens = _customer_vendor_tokens(db, device_ids)
    if not any(t in ("fortios", "fortigate") for t in vendor_tokens):
        return []
    try:
        r = requests.get(FORTINET_PSIRT_RSS, headers=_PSIRT_HEADERS, timeout=timeout)
        r.raise_for_status()
        root = ET.fromstring(r.content)
    except Exception as e:
        logger.warning("Fortinet PSIRT RSS fetch failed: %s", str(e)[:150])
        return []
    out: list[dict[str, Any]] = []
    for item in root.iter("item"):
        if len(out) >= cap:
            break
        title = (item.findtext("title") or "").strip()
        desc = (item.findtext("description") or "").strip()
        link = (item.findtext("link") or "").strip()
        hay = f"{title} {desc}".lower()
        if not any(t in hay for t in ("fortios", "fortigate")):
            continue
        cves = sorted({m.upper() for m in _CVE_ID_RE.findall(f"{title} {desc} {link}")})
        crit = "high" if "critical" in hay else "medium"
        out.append({
            "category": "exploit",
            "criticality": crit,
            "severity": crit,
            "relevance_score": 30,
            "relevance_band": "low",
            "relevance_reason": ("Fortinet PSIRT advisory for the customer's "
                                 "firewall product; not version-confirmed"),
            "confidence": 95,
            "title": f"Fortinet PSIRT: {title}"[:512],
            "description": (desc or title)[:1000],
            "iocs": [{"type": "cve", "value": c} for c in cves],
            "source": {
                "onion_url": None, "search_engine": None, "scraped_at": None,
                "raw_excerpt": (desc or title)[:500],
                "page_title": "Fortinet PSIRT",
                "marketplace_or_forum": "FortiGuard PSIRT IR Advisories",
            },
            "recommended_actions": [
                "[SCHEDULED] Review Fortinet advisory and patch affected versions "
                f"(target: {cves[0] if cves else link or 'vendor advisory'})"
            ],
            "tags": ["psirt", "fortinet", "vendor-advisory"],
        })
    logger.info("Fortinet PSIRT: %d advisories match customer products", len(out))
    return out


EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_LIKELY_THRESHOLD = float(os.getenv("LTI_EPSS_LIKELY_THRESHOLD", "0.5"))


def _enrich_with_epss(findings: list[dict[str, Any]], timeout: int = 15) -> None:
    """Annotate CVE findings in place with FIRST.org EPSS exploitation
    probabilities (free, no auth, one batched request).

    Above EPSS_LIKELY_THRESHOLD the finding gets a `likely-exploited` tag and
    the probability is appended to relevance_reason. Bands/scores are NOT
    changed here — relevance upgrades stay the correlator's job.
    """
    by_cve: dict[str, dict[str, Any]] = {}
    for f in findings:
        for i in f.get("iocs", []):
            if i.get("type") == "cve" and i.get("value"):
                by_cve.setdefault(i["value"].upper(), f)
    if not by_cve:
        return
    try:
        resp = requests.get(
            EPSS_API_URL,
            params={"cve": ",".join(sorted(by_cve))},
            timeout=timeout,
        )
        resp.raise_for_status()
        rows = resp.json().get("data", [])
    except Exception as e:
        logger.warning("EPSS fetch failed (non-fatal): %s", str(e)[:150])
        return
    enriched = likely = 0
    for row in rows:
        f = by_cve.get((row.get("cve") or "").upper())
        if f is None:
            continue
        try:
            epss = float(row.get("epss", 0))
        except (TypeError, ValueError):
            continue
        enriched += 1
        f.setdefault("tags", []).append(f"epss:{epss:.2f}")
        if epss >= EPSS_LIKELY_THRESHOLD:
            likely += 1
            f["tags"].append("likely-exploited")
            _r = (f.get("relevance_reason") or "").rstrip(". ")
            f["relevance_reason"] = (
                (_r + "; " if _r else "")
                + f"EPSS predicts a {epss:.0%} chance of exploitation in the wild."
            )
    logger.info("EPSS: enriched %d/%d CVEs (%d likely-exploited)",
                enriched, len(by_cve), likely)


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

    # Order = dedup priority: KEV (actively exploited) > PAN PSIRT
    # (vendor-confirmed for the installed version) > Fortinet PSIRT > NVD.
    try:
        _add(fetch_kev_findings(db, device_ids))
    except Exception as e:
        logger.error("KEV connector failed: %s", str(e)[:150])
    try:
        _add(fetch_paloalto_psirt_findings(db, device_ids))
    except Exception as e:
        logger.error("PAN PSIRT connector failed: %s", str(e)[:150])
    try:
        _add(fetch_fortinet_psirt_findings(db, device_ids))
    except Exception as e:
        logger.error("Fortinet PSIRT connector failed: %s", str(e)[:150])
    try:
        _add(fetch_nvd_findings(db, device_ids))
    except Exception as e:
        logger.error("NVD connector failed: %s", str(e)[:150])
    _enrich_with_epss(findings)
    return findings
