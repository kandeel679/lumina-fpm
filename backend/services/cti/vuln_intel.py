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
import re
from dataclasses import dataclass, field
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
# OFFLINE lab dataset (v1) — curated, network-free, mirrors LabOfflineProvider.
# Real CVE ids / CVSS / KEV status; affected ranges curated to the lab firmware
# (FortiOS 7.4.x, PAN-OS 11.1.x / 11.0.x). This stands in for the live NVD/KEV
# feed (deferred to v2). Distinguishable in evidence by source='lab-offline'.
# =====================================================================

LAB_CVE_FINDINGS: List[CveFinding] = [
    CveFinding(
        cve="CVE-2024-21762", product="fortios", severity="critical", cvss=9.8,
        kev=True, ransomware=True, source="lab-offline",
        title="FortiOS SSL-VPN out-of-bounds write (pre-auth RCE)",
        summary="Out-of-bounds write in FortiOS SSL-VPN allows a remote unauthenticated "
                "attacker to execute code via crafted requests. CISA KEV, known ransomware use.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2024-21762",
        affected_ranges=[{"startIncl": "7.4.0", "endExcl": "7.4.5"},
                         {"startIncl": "7.2.0", "endExcl": "7.2.8"},
                         {"startIncl": "7.0.0", "endExcl": "7.0.14"}],
    ),
    CveFinding(
        cve="CVE-2024-23113", product="fortios", severity="critical", cvss=9.8,
        kev=True, source="lab-offline",
        title="FortiOS fgfmd format-string RCE",
        summary="Use of an externally-controlled format string in the FortiOS fgfmd daemon "
                "allows a remote unauthenticated attacker to execute code/commands. CISA KEV.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2024-23113",
        affected_ranges=[{"startIncl": "7.4.0", "endExcl": "7.4.5"},
                         {"startIncl": "7.2.0", "endExcl": "7.2.8"}],
    ),
    CveFinding(
        cve="CVE-2024-3400", product="pan_os", severity="critical", cvss=10.0,
        kev=True, ransomware=True, source="lab-offline",
        title="PAN-OS GlobalProtect command injection (pre-auth RCE)",
        summary="Command injection in the GlobalProtect feature of PAN-OS allows an "
                "unauthenticated attacker to execute arbitrary code with root privileges. "
                "CISA KEV, exploited in the wild (Operation MidnightEclipse).",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
        affected_ranges=[{"startIncl": "11.1.0", "endIncl": "11.1.2"},
                         {"startIncl": "11.0.0", "endIncl": "11.0.4"},
                         {"startIncl": "10.2.0", "endIncl": "10.2.9"}],
    ),
    CveFinding(
        cve="CVE-2024-0012", product="pan_os", severity="critical", cvss=9.3,
        kev=True, source="lab-offline",
        title="PAN-OS management web interface authentication bypass",
        summary="Authentication bypass in the PAN-OS management web interface lets a network "
                "attacker gain administrator privileges and run admin actions. CISA KEV.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2024-0012",
        affected_ranges=[{"startIncl": "11.1.0", "endExcl": "11.1.5"},
                         {"startIncl": "11.0.0", "endExcl": "11.0.6"},
                         {"startIncl": "10.2.0", "endExcl": "10.2.12"}],
    ),
    CveFinding(
        cve="CVE-2025-0108", product="pan_os", severity="high", cvss=7.8,
        kev=False, source="lab-offline",
        title="PAN-OS management web interface authentication bypass",
        summary="Authentication bypass in the PAN-OS management web interface allows an "
                "unauthenticated attacker with network access to invoke certain PHP scripts.",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2025-0108",
        affected_ranges=[{"startIncl": "11.1.0", "endExcl": "11.1.7"},
                         {"startIncl": "11.0.0", "endExcl": "11.0.7"}],
    ),
]


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
