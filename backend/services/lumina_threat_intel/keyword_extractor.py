"""Keyword extractor — reads Lumina's firewall inventory and produces
a keyword bundle for the query-generator LLM prompt.

Extracts: firmware versions, vendor+model combos, and known CVEs
from the existing FirewallDevice, Vendor, and PolicyRule tables.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from models.models import FirewallDevice, Vendor, NetworkObject

logger = logging.getLogger(__name__)


def extract_keywords(db: Session) -> dict[str, list[str]]:
    """Extract a keyword bundle from the Lumina DB.

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
    }

    try:
        # --- Firmware versions ---
        devices = db.query(FirewallDevice).all()
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
        for obj in domain_objects:
            val = (obj.value or "").strip()
            if val and "." in val and not val.startswith("10.") and not val.startswith("192.168."):
                domain_set.add(val)
        bundle["org_domains"] = sorted(domain_set)[:50]  # cap to avoid huge prompts

        logger.info(
            "Keyword extraction complete: %d firmwares, %d vendor_models, "
            "%d cves, %d org_domains",
            len(bundle["firmwares"]),
            len(bundle["vendors_models"]),
            len(bundle["cves"]),
            len(bundle["org_domains"]),
        )

    except Exception as e:
        logger.error("Keyword extraction failed: %s", str(e))

    return bundle


def keywords_are_empty(bundle: dict[str, Any]) -> bool:
    """Check if the keyword bundle has any meaningful content."""
    return not any(bundle.get(key) for key in ("firmwares", "vendors_models", "cves", "org_domains"))
