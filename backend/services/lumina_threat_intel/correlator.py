"""Correlator — matches threat-intel findings against firewall rules and devices.

Scans each finding's IOCs (IPs, domains, CVEs) and checks whether any
appear in the existing PolicyRule or NetworkObject tables. Populates
matched_rule_ids, matched_device_ids, and correlation_match_reason.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Optional

from sqlalchemy.orm import Session

from models.models import (
    FirewallDevice,
    NetworkObject,
    PolicyRule,
    RuleObjectMapping,
)
from .schemas import Finding

logger = logging.getLogger(__name__)

# NVD url key (set on clearnet findings as `_nvd_product`) -> customer vendor-name
# token, so a FortiOS CVE only version-matches Fortinet devices, etc.
_NVD_PRODUCT_VENDOR = {"fortios": "fortinet", "pan_os": "palo alto", "cisco_asa": "cisco"}


def _version_tuple(v: str, length: int = 4) -> Optional[tuple[int, ...]]:
    """Normalize a firmware/CVE version to a fixed-length integer tuple for
    comparison. '7.4.3' -> (7, 4, 3, 0). Non-numeric build suffixes are dropped.
    Returns None when no numeric component is present.
    """
    nums = re.findall(r"\d+", v or "")
    if not nums:
        return None
    t = [int(n) for n in nums[:length]]
    t += [0] * (length - len(t))
    return tuple(t)


def _version_in_range(ver: str, rng: dict) -> bool:
    """True if installed version `ver` falls inside an NVD CPE range/exact match."""
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


def correlate_findings(
    db: Session,
    findings: list[dict[str, Any]],
    device_ids: Optional[list[int]] = None,
) -> list[dict[str, Any]]:
    """Correlate findings against firewall inventory.

    For each finding, check if any of its IOCs match:
    - NetworkObject values (IPs, domains)
    - FirewallDevice firmware_version or management_ip
    - CVEs mentioned in device context

    Args:
        device_ids: If provided, only correlate against these devices and their rules.

    Mutates and returns the findings list with correlation fields populated.
    """
    if not findings:
        return findings

    # Pre-load correlation data from DB
    try:
        all_net_objects = db.query(NetworkObject).all()
        device_query = db.query(FirewallDevice)
        if device_ids:
            device_query = device_query.filter(FirewallDevice.device_id.in_(device_ids))
        all_devices = device_query.all()

        scoped_device_id_set = {d.device_id for d in all_devices} if device_ids else None

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

    # object_id -> list of rule_ids (scoped to target devices if applicable)
    obj_to_rules: dict[int, list[int]] = {}
    for mapping in all_mappings:
        # If scoping to specific devices, we need to check if the rule belongs to a scoped device
        if scoped_device_id_set is not None:
            rule = db.query(PolicyRule).filter(PolicyRule.rule_id == mapping.rule_id).first()
            if rule and rule.device_id not in scoped_device_id_set:
                continue
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

        # Version-aware correlation (P14): NVD findings carry CPE version ranges.
        # If a device's INSTALLED firmware falls inside an affected range, that's
        # an authoritative match -> upgrade to high (handled by the block below).
        affected_ranges = finding.get("_affected_ranges") or []
        nvd_product = finding.get("_nvd_product")
        if affected_ranges and nvd_product:
            vendor_token = _NVD_PRODUCT_VENDOR.get(nvd_product, "")
            for device in all_devices:
                if not device.firmware_version:
                    continue
                vname = ((device.vendor.name if device.vendor else "") or "").lower()
                if vendor_token and vendor_token not in vname:
                    continue
                if any(_version_in_range(device.firmware_version, rng) for rng in affected_ranges):
                    matched_device_ids.add(device.device_id)
                    device_rules = [
                        r.rule_id
                        for r in db.query(PolicyRule.rule_id)
                        .filter(PolicyRule.device_id == device.device_id)
                        .all()
                    ]
                    matched_rule_ids.update(device_rules)
                    match_reasons.append(
                        f"installed firmware {device.firmware_version} on device "
                        f"{device.device_id} is within an affected version range for this CVE"
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

        # Hybrid relevance: the LLM proposed a relevance score/band against the
        # fingerprint; here code VERIFIES it against real inventory. A confirmed
        # rule/device match upgrades relevance to high (authoritative).
        # EXCEPTION: `possible-match` findings (e.g. a leak-site victim whose
        # NAME merely resembles the customer) carry the customer's own org
        # domain as the IOC — matching that against the customer's own network
        # objects is circular and proves nothing. They stay at their stated
        # band until a human verifies.
        if "possible-match" in (finding.get("tags") or []):
            finding["matched_rule_ids"] = []
            finding["matched_device_ids"] = []
            finding["correlation_match_reason"] = None
        elif matched_rule_ids or matched_device_ids:
            finding["relevance_band"] = "high"
            try:
                finding["relevance_score"] = max(int(finding.get("relevance_score") or 0), 90)
            except (TypeError, ValueError):
                finding["relevance_score"] = 90
            _reason = finding.get("relevance_reason") or ""
            finding["relevance_reason"] = (
                (_reason + "; " if _reason else "") + "confirmed match against firewall inventory"
            )[:500]
            # A confirmed inventory match means the fix is no longer routine:
            # escalate SCHEDULED actions to 24H (IMMEDIATE ones stay as-is).
            finding["recommended_actions"] = [
                a.replace("[SCHEDULED]", "[24H]", 1) if a.startswith("[SCHEDULED]") else a
                for a in (finding.get("recommended_actions") or [])
            ]

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
