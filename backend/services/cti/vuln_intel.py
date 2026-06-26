"""Firmware-CVE intelligence (Volume 9 §6, device axis) — free / deterministic.

Revives the WORKING clearnet CVE logic from the now-retired LTI island as a clean
module that feeds the LIVE pipeline. A matched firmware CVE is surfaced as
DEVICE-scoped CTI evidence — ``cti_indicator(type='firmware_version')`` +
``cti_observation(threat_type='vulnerability')`` — and raises device risk through a
firmware *modifier* (Vol8 §8, device-risk modifiers). It NEVER raises a
``rule_anomaly``, so the config-anomaly benchmark (47/47) is untouched by
construction.

Two axes, deliberately separate:
  * CVE   → "your firmware is vulnerable"  (DEVICE scope, this module)
  * CTI   → "your rules touch bad actors"  (RULE scope, services/cti/runner.py)

Source selection (``VULN_PROVIDER``, default ``offline``):
  * ``offline`` — a curated, network-free lab dataset (:data:`LAB_CVE_FINDINGS`)
    modelled on real CISA-KEV / NVD advisories for the lab firmware, mirroring
    :class:`services.cti.providers.LabOfflineProvider`. This is v1.
  * ``live``    — the real CISA-KEV + NVD fetchers (:func:`fetch_kev_findings`,
    :func:`fetch_nvd_findings`). Wired but DORMANT in v1; flip ``VULN_PROVIDER=live``
    to enable in v2. No API key, no LLM, no Tor, no cost.

Both paths are **Cisco-free** (v1 = Fortinet + Palo Alto only) and match devices on
``FirewallDevice.vendor_type`` (``'fortinet' | 'paloalto'``), not the legacy
``vendor.name`` substring. This module MUST NOT import
``services.lumina_threat_intel.*`` (the retired island) — the two feed URLs are
inlined below.
"""
from __future__ import annotations

import datetime
import json
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, List, Optional

from sqlalchemy.orm import Session

from core.logging import get_logger
from models.models import FirewallDevice

logger = get_logger(__name__)


# ── Vendor / product maps (Cisco stripped; v1 = Fortinet + Palo Alto) ──
# product key -> semantic vendor_type (FirewallDevice.vendor_type)
_PRODUCT_VENDOR = {"fortios": "fortinet", "pan_os": "paloalto"}
# vendor_type -> (NVD product key, CPE token used to scope affected ranges)
_VENDOR_NVD = {
    "fortinet": ("fortios", ":fortinet:fortios:"),
    "paloalto": ("pan_os", ":paloaltonetworks:pan-os:"),
}
# CISA-KEV vendor/product haystack tokens per vendor_type
_VENDOR_KEV_TOKENS = {
    "fortinet": ("fortios", "fortigate"),
    "paloalto": ("pan-os", "globalprotect", "pan os"),
}

# Inlined feed URLs (NO import of the retired sources.py / onion engines).
_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_VIRTUAL_MATCH = {
    "fortios": "cpe:2.3:o:fortinet:fortios",
    "pan_os": "cpe:2.3:o:paloaltonetworks:pan-os",
}
_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_NVD_LOOKBACK_DAYS = 120  # NVD pubStartDate window (max 120)


@dataclass
class CveFinding:
    """One CVE relevant to a firewall product (vendor-agnostic transport object)."""
    cve: str
    product: str                       # 'fortios' | 'pan_os'
    severity: str                      # critical | high | medium | low
    title: str
    summary: str = ""
    cvss: Optional[float] = None
    kev: bool = False                  # CISA Known-Exploited
    ransomware: bool = False
    reference: Optional[str] = None
    source: str = "nvd"                # 'cisa-kev' | 'nvd' | 'lab-offline'
    affected_ranges: List[dict] = field(default_factory=list)

    @property
    def vendor_type(self) -> Optional[str]:
        return _PRODUCT_VENDOR.get(self.product)

    @property
    def provider(self) -> str:
        """cti_observation.provider value (schema: 'nvd' | 'vendor_advisory')."""
        return "vendor_advisory" if self.kev or self.source == "cisa-kev" else "nvd"


# =====================================================================
# Pure version helpers (lifted verbatim from the retired correlator.py;
# stdlib-only, no DB/IO). See LTI P14.
# =====================================================================

def _version_tuple(v: str, length: int = 4) -> Optional[tuple[int, ...]]:
    """Normalize a firmware/CVE version to a fixed-length int tuple for comparison.

    ``'7.4.3' -> (7, 4, 3, 0)``. Non-numeric build suffixes are dropped; returns
    None when no numeric component is present.
    """
    nums = re.findall(r"\d+", v or "")
    if not nums:
        return None
    t = [int(n) for n in nums[:length]]
    t += [0] * (length - len(t))
    return tuple(t)


def _version_in_range(ver: str, rng: dict) -> bool:
    """True if installed version ``ver`` falls inside a CPE range / exact match."""
    v = _version_tuple(ver)
    if v is None:
        return False
    exact = rng.get("exact")
    if exact:
        ev = _version_tuple(exact)
        return ev is not None and v == ev
    has_bound = False
    if rng.get("startIncl"):
        b = _version_tuple(rng["startIncl"])
        if b is None or v < b:
            return False
        has_bound = True
    if rng.get("startExcl"):
        b = _version_tuple(rng["startExcl"])
        if b is None or v <= b:
            return False
        has_bound = True
    if rng.get("endIncl"):
        b = _version_tuple(rng["endIncl"])
        if b is None or v > b:
            return False
        has_bound = True
    if rng.get("endExcl"):
        b = _version_tuple(rng["endExcl"])
        if b is None or v >= b:
            return False
        has_bound = True
    return has_bound


def _cvss_to_severity(score: Optional[float], severity: Optional[str]) -> str:
    """Prefer the NVD baseSeverity string; fall back to CVSS numeric bands."""
    if severity and severity.lower() in ("critical", "high", "medium", "low"):
        return severity.lower()
    if score is None:
        return "low"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _extract_affected_ranges(cve: dict, product_cpe_token: str) -> List[dict]:
    """Pull CPE version ranges for the customer's product from an NVD CVE.

    Only ``vulnerable: true`` matches whose CPE ``criteria`` names the product are
    kept, so the device's installed firmware can later be range-tested.
    """
    ranges: List[dict] = []
    for cfg in cve.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable"):
                    continue
                crit = (m.get("criteria") or "").lower()
                if product_cpe_token and product_cpe_token not in crit:
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


# =====================================================================
# Inventory <-> CVE correlation (device scope only — no rule sweep)
# =====================================================================

def _firmware_vendor_types(db: Session, device_ids: Optional[List[int]]) -> set[str]:
    """vendor_type values present in the (optionally scoped) inventory."""
    q = db.query(FirewallDevice.vendor_type).filter(FirewallDevice.vendor_type.isnot(None))
    if device_ids:
        q = q.filter(FirewallDevice.device_id.in_(device_ids))
    return {vt for (vt,) in q.all() if vt in _VENDOR_NVD}


def cve_affects_device(finding: CveFinding, vendor_type: Optional[str],
                       firmware_version: Optional[str]) -> bool:
    """Pure predicate: does this CVE affect a device of the given vendor_type and
    installed firmware? (vendor match AND firmware inside an affected range.)"""
    if not vendor_type or not firmware_version:
        return False
    if finding.vendor_type != vendor_type or not finding.affected_ranges:
        return False
    return any(_version_in_range(firmware_version, rng) for rng in finding.affected_ranges)


def decide_vulnerable_devices(db: Session, finding: CveFinding,
                              device_ids: Optional[List[int]] = None) -> List[int]:
    """device_ids whose vendor_type matches the finding AND whose installed
    firmware falls inside an affected range. Device scope only (no rules)."""
    target_vendor = finding.vendor_type
    if not target_vendor or not finding.affected_ranges:
        return []
    q = db.query(FirewallDevice).filter(
        FirewallDevice.vendor_type == target_vendor,
        FirewallDevice.firmware_version.isnot(None),
    )
    if device_ids:
        q = q.filter(FirewallDevice.device_id.in_(device_ids))
    return [d.device_id for d in q.all()
            if cve_affects_device(finding, d.vendor_type, d.firmware_version)]


# =====================================================================
# OFFLINE lab dataset (v1) — loaded from a versioned reference FILE, not hardcoded.
# backend/data/cve_reference.json holds curated, network-free CVE entries (real CVE
# ids / CVSS / KEV status; affected ranges curated to the lab firmware), mirroring
# cti.providers.LabOfflineProvider. Keeping the data out of source lets the CVE set
# be edited/refreshed without a code change. Stands in for the live NVD/KEV feed
# (deferred to v2). Override the path with CVE_REFERENCE_PATH.
# =====================================================================

# Only the STORED CveFinding fields are read from JSON; vendor_type/provider are
# derived @property and must never be stored (storing them would shadow the property).
_CVE_FINDING_FIELDS = {
    "cve", "product", "severity", "title", "summary", "cvss",
    "kev", "ransomware", "reference", "source", "affected_ranges",
}
_CVE_REFERENCE_PATH = os.getenv(
    "CVE_REFERENCE_PATH",
    str(Path(__file__).resolve().parents[2] / "data" / "cve_reference.json"),
)


@lru_cache(maxsize=1)
def _load_offline_cve_findings() -> List[CveFinding]:
    """Load the curated offline CVE dataset from the versioned JSON reference file.

    Whitelists known fields (a stray key would raise on CveFinding(**obj)) and
    preserves file order (determinism). Returns [] on any read/parse error for
    runtime resilience; the test suite asserts the file is present and complete
    so a missing/empty file fails loudly in CI rather than silently degrading.
    """
    try:
        with open(_CVE_REFERENCE_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        out: List[CveFinding] = []
        for obj in data.get("findings", []):
            out.append(CveFinding(**{k: v for k, v in obj.items() if k in _CVE_FINDING_FIELDS}))
        return out
    except Exception as exc:  # noqa: BLE001 — never hard-fail import; tests gate completeness
        logger.warning("CVE reference load failed from %s (non-fatal): %s",
                       _CVE_REFERENCE_PATH, str(exc)[:150])
        return []


LAB_CVE_FINDINGS: List[CveFinding] = _load_offline_cve_findings()


def _offline_cve_findings(vendor_types: set[str]) -> List[CveFinding]:
    """Curated lab CVEs scoped to the vendors actually present in the inventory."""
    return [f for f in LAB_CVE_FINDINGS if f.vendor_type in vendor_types]


# =====================================================================
# LIVE fetchers (v2; dormant under VULN_PROVIDER=offline). Cisco-free; keyed off
# vendor_type. Each wrapped so an external outage yields [] (never raises).
# =====================================================================

def fetch_kev_findings(vendor_types: set[str], timeout: int = 20) -> List[CveFinding]:
    """CISA Known-Exploited Vulnerabilities, filtered to the present vendors."""
    tokens = {tok for vt in vendor_types for tok in _VENDOR_KEV_TOKENS.get(vt, ())}
    if not tokens:
        return []
    try:
        import requests  # lazy
        resp = requests.get(_CISA_KEV_URL, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:  # noqa: BLE001 — feed outage must not break the pipeline
        logger.warning("CISA KEV fetch failed (non-fatal): %s", str(exc)[:150])
        return []
    out: List[CveFinding] = []
    for v in data.get("vulnerabilities", []):
        hay = f"{v.get('vendorProject', '')} {v.get('product', '')}".lower()
        product = next((p for p, vt in _PRODUCT_VENDOR.items()
                        if any(t in hay for t in _VENDOR_KEV_TOKENS.get(vt, ()))), None)
        if product is None:
            continue
        cve = v.get("cveID", "")
        ransom = (v.get("knownRansomwareCampaignUse", "") or "").strip().lower() == "known"
        out.append(CveFinding(
            cve=cve, product=product, severity="critical" if ransom else "high",
            kev=True, ransomware=ransom, source="cisa-kev",
            title=v.get("vulnerabilityName", cve) or cve,
            summary=(v.get("shortDescription", "") or "")[:1000],
            reference=f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else None,
            # KEV carries no CPE ranges; live mode pairs it with NVD (below) for ranges.
            affected_ranges=[],
        ))
    logger.info("CISA KEV (live): %d findings for vendors %s", len(out), sorted(vendor_types))
    return out


def fetch_nvd_findings(vendor_types: set[str], timeout: int = 25,
                       per_vendor_cap: int = 20) -> List[CveFinding]:
    """Recent NVD CVEs (CVSS-scored, with CPE ranges) per present vendor product."""
    end = datetime.datetime.utcnow()
    start = end - datetime.timedelta(days=_NVD_LOOKBACK_DAYS)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    out: List[CveFinding] = []
    for vt in sorted(vendor_types):
        nvd = _VENDOR_NVD.get(vt)
        match = _NVD_VIRTUAL_MATCH.get(nvd[0]) if nvd else None
        if not nvd or not match:
            continue
        product, cpe_token = nvd
        url = (f"{_NVD_BASE}?virtualMatchString={match}"
               f"&pubStartDate={start.strftime(fmt)}&pubEndDate={end.strftime(fmt)}"
               f"&resultsPerPage={per_vendor_cap}")
        try:
            import requests  # lazy
            r = requests.get(url, timeout=timeout)
            r.raise_for_status()
            data = r.json()
        except Exception as exc:  # noqa: BLE001
            logger.warning("NVD fetch failed for %s (non-fatal): %s", product, str(exc)[:120])
            continue
        for item in data.get("vulnerabilities", [])[:per_vendor_cap]:
            cve = item.get("cve", {})
            cid = cve.get("id", "")
            desc = next((d.get("value", "") for d in cve.get("descriptions", [])
                         if d.get("lang") == "en"), "")
            score = sev = None
            for mk in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
                if cve.get("metrics", {}).get(mk):
                    cd = cve["metrics"][mk][0].get("cvssData", {})
                    score, sev = cd.get("baseScore"), cd.get("baseSeverity")
                    break
            ranges = _extract_affected_ranges(cve, cpe_token)
            if not ranges:
                continue  # device-axis needs a range to confirm the installed firmware
            out.append(CveFinding(
                cve=cid, product=product, severity=_cvss_to_severity(score, sev),
                cvss=score, kev=False, source="nvd",
                title=(desc[:160] or cid), summary=desc[:1000],
                reference=f"https://nvd.nist.gov/vuln/detail/{cid}" if cid else None,
                affected_ranges=ranges,
            ))
    logger.info("NVD (live): %d range-bearing findings for vendors %s",
                len(out), sorted(vendor_types))
    return out


def build_cve_findings(db: Session, mode: str = "offline",
                       device_ids: Optional[List[int]] = None) -> List[CveFinding]:
    """All CVE findings for the present vendors, per the selected provider mode.

    ``offline`` (v1) -> curated lab dataset; ``live`` (v2) -> CISA-KEV + NVD.
    """
    vendor_types = _firmware_vendor_types(db, device_ids)
    if not vendor_types:
        return []
    if (mode or "offline").lower() == "live":
        return fetch_kev_findings(vendor_types) + fetch_nvd_findings(vendor_types)
    return _offline_cve_findings(vendor_types)
