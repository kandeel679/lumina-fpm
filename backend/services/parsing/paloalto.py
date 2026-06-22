"""Palo Alto parser — PAN-OS XML → ParsedDevicePayload.

Validated against a real PAN-OS `rulebase` config-show response. Uses defusedxml
when available (hardened against entity-expansion, V12 §10), falling back to the
stdlib parser. Extraction only — no canonicalization.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from core.logging import get_logger

from .models import (
    ParsedAddressGroup,
    ParsedAddressObject,
    ParsedDevicePayload,
    ParsedRule,
    ParsedServiceGroup,
    ParsedServiceObject,
)

logger = get_logger(__name__)

try:  # hardened parser preferred
    from defusedxml.ElementTree import fromstring as _xml_fromstring
except Exception:  # pragma: no cover
    from xml.etree.ElementTree import fromstring as _xml_fromstring


def _members(entry, path: str) -> List[str]:
    out = []
    for m in entry.findall(f"{path}/member"):
        if m.text:
            out.append(m.text.strip())
    return out


def _text(entry, path: str) -> Optional[str]:
    el = entry.find(path)
    return el.text.strip() if el is not None and el.text else None


def _parse_rules(text: Optional[str], vsys: Optional[str]) -> List[ParsedRule]:
    if not text:
        return []
    try:
        root = _xml_fromstring(text)
    except Exception as exc:  # noqa: BLE001
        logger.warning("PAN rulebase XML parse failed: %s", exc)
        return []

    rules = []
    # Robust to whether the response root is rulebase, security, or the full response.
    entries = root.findall(".//security/rules/entry") or root.findall(".//rules/entry")
    for order, entry in enumerate(entries, start=1):
        disabled = (_text(entry, "disabled") or "no").lower() == "yes"
        log_start = (_text(entry, "log-start") or "no").lower() == "yes"
        log_end = (_text(entry, "log-end") or "no").lower() == "yes"
        # Security inspection = a profile-setting (group or individual profiles) exists.
        prof_el = entry.find("profile-setting")
        has_profile = prof_el is not None and len(list(prof_el)) > 0
        profile_group = None
        if prof_el is not None:
            grp = prof_el.find("group/member")
            if grp is not None and grp.text:
                profile_group = grp.text.strip()

        rules.append(ParsedRule(
            vendor="paloalto",
            rule_name=entry.get("name") or f"rule-{order}",
            rule_order=order,
            vendor_rule_id=entry.get("name"),
            vendor_uuid=entry.get("uuid"),
            vdom_vsys=vsys,
            enabled=not disabled,
            src_zones=_members(entry, "from"),
            dst_zones=_members(entry, "to"),
            src_addrs=_members(entry, "source"),
            dst_addrs=_members(entry, "destination"),
            services=_members(entry, "service"),
            applications=_members(entry, "application"),
            action=_text(entry, "action") or "unknown",
            logging_raw="yes" if (log_start or log_end) else "no",
            security_profiles={"has_profile": has_profile, "profile_group": profile_group},
            schedule=_text(entry, "schedule"),
            nat_enabled=None,  # PAN NAT is a separate policy type (future, V4 Table 7)
            description=_text(entry, "description"),
            src_negate=(_text(entry, "negate-source") or "no").lower() == "yes",
            dst_negate=(_text(entry, "negate-destination") or "no").lower() == "yes",
            raw={"name": entry.get("name"), "uuid": entry.get("uuid")},
        ))
    return rules


def _parse_addresses(text: Optional[str]) -> List[ParsedAddressObject]:
    if not text:
        return []
    try:
        root = _xml_fromstring(text)
    except Exception:
        return []
    objs = []
    for entry in root.findall(".//address/entry") or root.findall(".//entry"):
        name = entry.get("name")
        if not name:
            continue
        ip_netmask = _text(entry, "ip-netmask")
        ip_range = _text(entry, "ip-range")
        fqdn = _text(entry, "fqdn")
        if ip_netmask:
            value, otype = ip_netmask, ("cidr" if "/" in ip_netmask else "ip_address")
        elif fqdn:
            value, otype = fqdn, "fqdn"
        elif ip_range:
            value, otype = ip_range, "cidr"
        else:
            value, otype = "", "unknown"
        objs.append(ParsedAddressObject(name=name, type=otype, value=value, raw_value=value,
                                        vendor_uuid=entry.get("uuid")))
    return objs


def _parse_addrgrps(text: Optional[str]) -> List[ParsedAddressGroup]:
    if not text:
        return []
    try:
        root = _xml_fromstring(text)
    except Exception:
        return []
    groups = []
    for entry in root.findall(".//address-group/entry") or root.findall(".//entry"):
        name = entry.get("name")
        if not name:
            continue
        members = _members(entry, "static")
        groups.append(ParsedAddressGroup(name=name, members=members, vendor_uuid=entry.get("uuid")))
    return groups


def _parse_services(text: Optional[str]) -> List[ParsedServiceObject]:
    if not text:
        return []
    try:
        root = _xml_fromstring(text)
    except Exception:
        return []
    out = []
    for entry in root.findall(".//service/entry") or root.findall(".//entry"):
        name = entry.get("name")
        if not name:
            continue
        proto = ps = pe = None
        for p in ("tcp", "udp"):
            node = entry.find(f"protocol/{p}")
            if node is not None:
                proto = p
                port = _text(node, "port") or ""
                first = port.split(",")[0]
                if "-" in first:
                    a, b = first.split("-", 1)
                    ps, pe = _to_int(a), _to_int(b)
                elif first:
                    ps = pe = _to_int(first)
                break
        out.append(ParsedServiceObject(name=name, protocol=proto, port_start=ps, port_end=pe))
    return out


def _parse_service_groups(text: Optional[str]) -> List[ParsedServiceGroup]:
    if not text:
        return []
    try:
        root = _xml_fromstring(text)
    except Exception:
        return []
    groups = []
    for entry in root.findall(".//service-group/entry"):
        name = entry.get("name")
        if not name:
            continue
        groups.append(ParsedServiceGroup(name=name, members=_members(entry, "members")))
    return groups


def _to_int(v) -> Optional[int]:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _firmware(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    try:
        root = _xml_fromstring(text)
    except Exception:
        return None
    el = root.find(".//sw-version")
    return el.text.strip() if el is not None and el.text else None


def parse(device_id: int, artifacts: Dict[str, str], vsys: Optional[str] = "vsys1") -> ParsedDevicePayload:
    payload = ParsedDevicePayload(
        device_id=device_id,
        vendor="paloalto",
        firmware_version=_firmware(artifacts.get("device_metadata")),
        vdom_vsys=vsys,
        rules=_parse_rules(artifacts.get("policies"), vsys),
        address_objects=_parse_addresses(artifacts.get("address_objects")),
        address_groups=_parse_addrgrps(artifacts.get("address_groups")),
        service_objects=_parse_services(artifacts.get("service_objects")),
        service_groups=_parse_service_groups(artifacts.get("service_groups")),
    )
    logger.info(
        "Parsed Palo Alto device %s: %d rules, %d addr, %d svc (fw=%s)",
        device_id, len(payload.rules), len(payload.address_objects),
        len(payload.service_objects), payload.firmware_version,
    )
    return payload
