"""Keyword extractor — reads Lumina's firewall inventory and produces
a keyword bundle for the query-generator LLM prompt.

Extracts: firmware versions, vendor+model combos, and known CVEs
from the existing FirewallDevice, Vendor, and PolicyRule tables.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Optional

from sqlalchemy.orm import Session

from models.models import FirewallDevice, NetworkObject, RuleAnomaly, Vendor

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")
_PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "169.254.") + tuple(
    f"172.{i}." for i in range(16, 32)
)

logger = logging.getLogger(__name__)


def extract_keywords(db: Session, device_ids: Optional[list[int]] = None) -> dict[str, list[str]]:
    """Extract a keyword bundle from the Lumina DB.

    Args:
        db: SQLAlchemy session.
        device_ids: Optional list of device IDs to scope extraction to.
                    If None or empty, all devices are included.

    Returns:
        {
            "firmwares":      ["PAN-OS 10.2.3", "FortiOS 7.4.1", ...],
            "vendors_models": ["Palo Alto PA-3220", "Fortinet FortiGate-60F", ...],
            "cves":           [],  # populated if any anomaly descriptions contain CVE patterns
            "org_domains":    [],  # populated from network objects of type 'fqdn'/'domain'
        }
    """
    bundle: dict[str, list[str]] = {
        "firmwares": [],
        "vendors_models": [],
        "cves": [],
        "org_domains": [],
        "org_ips": [],
    }

    try:
        # --- Firmware versions ---
        device_query = db.query(FirewallDevice)
        if device_ids:
            device_query = device_query.filter(FirewallDevice.device_id.in_(device_ids))
        devices = device_query.all()
        firmware_set: set[str] = set()
        vendor_model_set: set[str] = set()

        for device in devices:
            if device.firmware_version:
                firmware_set.add(device.firmware_version.strip())

            # Build vendor+model string
            vendor = device.vendor
            if vendor:
                vendor_model = f"{vendor.name} {device.hostname}".strip()
                vendor_model_set.add(vendor_model)

        bundle["firmwares"] = sorted(firmware_set)
        bundle["vendors_models"] = sorted(vendor_model_set)

        # --- Org domains from network objects ---
        domain_objects = (
            db.query(NetworkObject)
            .filter(NetworkObject.type.in_(["fqdn", "domain", "ip-netmask"]))
            .all()
        )
        domain_set: set[str] = set()
        ip_set: set[str] = set()
        for obj in domain_objects:
            val = (obj.value or "").strip().lower()
            if not val or "." not in val:
                continue
            if _IP_RE.match(val):
                # ip-netmask objects: keep PUBLIC IPs separately — they are
                # exposure indicators, not domains (P-test fix: an IP in
                # org_domains polluted prompts and queries).
                if not val.startswith(_PRIVATE_PREFIXES):
                    ip_set.add(val)
            elif any(c.isalpha() for c in val):
                domain_set.add(val)
        bundle["org_domains"] = sorted(domain_set)[:50]  # cap to avoid huge prompts
        bundle["org_ips"] = sorted(ip_set)[:50]

        # --- CVEs mentioned in rule-anomaly descriptions ---
        cve_set: set[str] = set()
        for (desc,) in db.query(RuleAnomaly.description).all():
            for m in _CVE_RE.findall(desc or ""):
                cve_set.add(m.upper())
        bundle["cves"] = sorted(cve_set)[:25]

        logger.info(
            "Keyword extraction complete: %d firmwares, %d vendor_models, "
            "%d cves, %d org_domains, %d org_ips",
            len(bundle["firmwares"]),
            len(bundle["vendors_models"]),
            len(bundle["cves"]),
            len(bundle["org_domains"]),
            len(bundle["org_ips"]),
        )

    except Exception as e:
        logger.error("Keyword extraction failed: %s", str(e))

    return bundle


def keywords_are_empty(bundle: dict[str, Any]) -> bool:
    """Check if the keyword bundle has any meaningful content."""
    return not any(bundle.get(key) for key in (
        "firmwares", "vendors_models", "cves", "org_domains", "org_ips"))
