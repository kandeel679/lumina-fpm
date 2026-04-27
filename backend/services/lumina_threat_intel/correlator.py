"""Correlator — matches threat-intel findings against firewall rules and devices.

Scans each finding's IOCs (IPs, domains, CVEs) and checks whether any
appear in the existing PolicyRule or NetworkObject tables. Populates
matched_rule_ids, matched_device_ids, and correlation_match_reason.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from sqlalchemy.orm import Session

from models.models import (
    FirewallDevice,
    NetworkObject,
    PolicyRule,
    RuleObjectMapping,
)
from .schemas import Finding

logger = logging.getLogger(__name__)


def correlate_findings(
    db: Session,
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Correlate findings against firewall inventory.

    For each finding, check if any of its IOCs match:
    - NetworkObject values (IPs, domains)
    - FirewallDevice firmware_version or management_ip
    - CVEs mentioned in device context

    Mutates and returns the findings list with correlation fields populated.
    """
    if not findings:
        return findings

    # Pre-load correlation data from DB
    try:
        all_net_objects = db.query(NetworkObject).all()
        all_devices = db.query(FirewallDevice).all()
        all_mappings = db.query(RuleObjectMapping).all()
    except Exception as e:
        logger.error("Failed to load correlation data: %s", str(e))
        return findings

    # Build lookup structures
    # value -> list of (object_id, name, type)
    netobj_by_value: dict[str, list[dict]] = {}
    for obj in all_net_objects:
        val = (obj.value or "").strip().lower()
        if val:
            netobj_by_value.setdefault(val, []).append({
                "object_id": obj.object_id,
                "name": obj.name,
                "type": obj.type,
            })

    # object_id -> list of rule_ids
    obj_to_rules: dict[int, list[int]] = {}
    for mapping in all_mappings:
        obj_to_rules.setdefault(mapping.object_id, []).append(mapping.rule_id)

    # device management IPs and firmware versions
    device_ips: dict[str, int] = {}
    device_firmwares: dict[str, list[int]] = {}
    for device in all_devices:
        if device.management_ip:
            device_ips[device.management_ip.strip().lower()] = device.device_id
        if device.firmware_version:
            fw = device.firmware_version.strip().lower()
            device_firmwares.setdefault(fw, []).append(device.device_id)

    # Correlate each finding
    for finding in findings:
        matched_rule_ids: set[int] = set()
        matched_device_ids: set[int] = set()
        match_reasons: list[str] = []

        iocs = finding.get("iocs", [])
        for ioc in iocs:
            ioc_val = (ioc.get("value") or "").strip().lower()
            ioc_type = ioc.get("type", "")

            if not ioc_val:
                continue

            # Check against network objects
            if ioc_val in netobj_by_value:
                for obj_info in netobj_by_value[ioc_val]:
                    oid = obj_info["object_id"]
                    if oid in obj_to_rules:
                        rule_ids = obj_to_rules[oid]
                        matched_rule_ids.update(rule_ids)
                        match_reasons.append(
                            f"IOC {ioc_val} ({ioc_type}) matches network object "
                            f"'{obj_info['name']}' used in rule(s) {rule_ids}"
                        )

            # Check against device management IPs
            if ioc_type in ("ipv4", "ipv6", "domain") and ioc_val in device_ips:
                did = device_ips[ioc_val]
                matched_device_ids.add(did)
                match_reasons.append(
                    f"IOC {ioc_val} matches management IP of device {did}"
                )

            # Check CVE against firmware versions
            if ioc_type == "cve":
                # If the finding title or description mentions a firmware version
                # that exists in our inventory, correlate
                title = (finding.get("title") or "").lower()
                desc = (finding.get("description") or "").lower()
                full_text = f"{title} {desc}"
                for fw_ver, dev_ids in device_firmwares.items():
                    if fw_ver in full_text or _firmware_matches_cve_context(fw_ver, full_text):
                        matched_device_ids.update(dev_ids)
                        match_reasons.append(
                            f"CVE {ioc_val} context references firmware '{fw_ver}' "
                            f"on device(s) {dev_ids}"
                        )

        # Also check device firmware for general vendor-keyword matches
        finding_text = (
            (finding.get("title") or "")
            + " "
            + (finding.get("description") or "")
        ).lower()
        for device in all_devices:
            if device.firmware_version:
                fw = device.firmware_version.strip().lower()
                if fw and fw in finding_text:
                    matched_device_ids.add(device.device_id)
                    # Get rule_ids for this device
                    device_rules = [
                        r.rule_id
                        for r in db.query(PolicyRule.rule_id)
                        .filter(PolicyRule.device_id == device.device_id)
                        .all()
                    ]
                    matched_rule_ids.update(device_rules)

        finding["matched_rule_ids"] = sorted(matched_rule_ids)
        finding["matched_device_ids"] = sorted(matched_device_ids)
        finding["correlation_match_reason"] = "; ".join(match_reasons) if match_reasons else None

    correlated_count = sum(
        1 for f in findings if f.get("matched_rule_ids") or f.get("matched_device_ids")
    )
    logger.info(
        "Correlation complete: %d/%d findings matched firewall inventory",
        correlated_count, len(findings),
    )

    return findings


def _firmware_matches_cve_context(firmware: str, text: str) -> bool:
    """Check if a firmware version string is contextually mentioned in text."""
    # Extract version numbers from firmware (e.g., "10.2.3" from "PAN-OS 10.2.3")
    versions = re.findall(r"\d+\.\d+(?:\.\d+)?", firmware)
    return any(v in text for v in versions)
