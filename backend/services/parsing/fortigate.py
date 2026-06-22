"""FortiGate parser — FortiOS REST JSON → ParsedDevicePayload.

Validated against a real FortiOS v7.0.5 `firewall/policy` response. Extraction only;
no anomaly logic and no canonicalization (normalization owns those).
"""
from __future__ import annotations

import ipaddress
import json
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


def _results(text: Optional[str]) -> List[dict]:
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    res = data.get("results") if isinstance(data, dict) else None
    return res if isinstance(res, list) else []


def _names(items) -> List[str]:
    """FortiGate represents object refs as [{'name': ...}]."""
    out = []
    for it in items or []:
        if isinstance(it, dict) and it.get("name"):
            out.append(it["name"])
        elif isinstance(it, str):
            out.append(it)
    return out


def _firmware(artifacts: Dict[str, str]) -> Optional[str]:
    # Every FortiOS response carries a top-level "version"; prefer system/status.
    for key in ("device_metadata", "policies", "address_objects"):
        text = artifacts.get(key)
        if not text:
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            results = data.get("results")
            if isinstance(results, dict) and results.get("version"):
                return str(results["version"])
            if data.get("version"):
                return str(data["version"])
    return None


def _subnet_to_cidr(subnet: str) -> Optional[str]:
    """FortiGate stores subnets as 'A.B.C.D MASK'. Convert to CIDR."""
    try:
        parts = subnet.split()
        if len(parts) == 2:
            net = ipaddress.ip_network(f"{parts[0]}/{parts[1]}", strict=False)
            return str(net)
        return subnet
    except Exception:
        return subnet or None


def _parse_addresses(text: Optional[str]) -> List[ParsedAddressObject]:
    objs = []
    for r in _results(text):
        name = r.get("name")
        if not name:
            continue
        atype = r.get("type", "ipmask")
        if atype == "iprange":
            start, end = r.get("start-ip", ""), r.get("end-ip", "")
            value = f"{start}-{end}" if end else start
            otype = "range"
        elif atype in ("ipmask", "ipprefix"):
            value = _subnet_to_cidr(r.get("subnet", "")) or ""
            otype = "cidr"
        elif atype == "fqdn":
            value, otype = r.get("fqdn", ""), "fqdn"
        else:
            value, otype = r.get("subnet", "") or r.get("fqdn", ""), "unknown"
        objs.append(ParsedAddressObject(
            name=name, type=otype, value=str(value), raw_value=r.get("subnet") or r.get("fqdn"),
            vendor_uuid=r.get("uuid"),
        ))
    return objs


def _parse_addrgrps(text: Optional[str]) -> List[ParsedAddressGroup]:
    return [
        ParsedAddressGroup(name=r["name"], members=_names(r.get("member")), vendor_uuid=r.get("uuid"))
        for r in _results(text) if r.get("name")
    ]


def _parse_services(text: Optional[str]) -> List[ParsedServiceObject]:
    out = []
    for r in _results(text):
        name = r.get("name")
        if not name:
            continue
        proto = None
        ps = pe = None
        tcp = r.get("tcp-portrange") or ""
        udp = r.get("udp-portrange") or ""
        rng = tcp or udp
        if tcp:
            proto = "tcp"
        elif udp:
            proto = "udp"
        elif (r.get("protocol") or "").upper() == "ICMP":
            proto = "icmp"
        if rng:
            first = str(rng).split()[0]
            if "-" in first:
                a, b = first.split("-", 1)
                ps, pe = _int(a), _int(b)
            else:
                ps = pe = _int(first)
        out.append(ParsedServiceObject(
            name=name, protocol=proto, port_start=ps, port_end=pe, raw_value=rng or None,
        ))
    return out


def _parse_service_groups(text: Optional[str]) -> List[ParsedServiceGroup]:
    return [
        ParsedServiceGroup(name=r["name"], members=_names(r.get("member")))
        for r in _results(text) if r.get("name")
    ]


def _int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _parse_rules(text: Optional[str], vdom: Optional[str]) -> List[ParsedRule]:
    rules = []
    for order, r in enumerate(_results(text), start=1):
        profiles = {
            "utm_status": r.get("utm-status"),
            "profile_group": r.get("profile-group") or None,
            "profile_type": r.get("profile-type"),
            "av_profile": r.get("av-profile") or None,
            "ips_sensor": r.get("ips-sensor") or None,
            "webfilter_profile": r.get("webfilter-profile") or None,
            "application_list": r.get("application-list") or None,
            "ssl_ssh_profile": r.get("ssl-ssh-profile") or None,
        }
        rules.append(ParsedRule(
            vendor="fortinet",
            rule_name=r.get("name") or f"policy-{r.get('policyid')}",
            rule_order=order,
            vendor_rule_id=str(r.get("policyid")) if r.get("policyid") is not None else None,
            vendor_uuid=r.get("uuid"),
            vdom_vsys=vdom,
            enabled=(r.get("status") == "enable"),
            src_zones=_names(r.get("srcintf")),
            dst_zones=_names(r.get("dstintf")),
            src_addrs=_names(r.get("srcaddr")),
            dst_addrs=_names(r.get("dstaddr")),
            services=_names(r.get("service")),
            action=r.get("action", "unknown"),
            logging_raw=r.get("logtraffic"),
            security_profiles=profiles,
            schedule=r.get("schedule"),
            nat_enabled=(r.get("nat") == "enable") if r.get("nat") is not None else None,
            description=r.get("comments") or None,
            src_negate=(r.get("srcaddr-negate") == "enable"),
            dst_negate=(r.get("dstaddr-negate") == "enable"),
            raw=r,
        ))
    return rules


def parse(device_id: int, artifacts: Dict[str, str]) -> ParsedDevicePayload:
    """Parse a FortiGate acquisition (artifact_type -> raw text) into a ParsedDevicePayload."""
    # vdom is reported at the top level of the policy response.
    vdom = None
    try:
        pol = json.loads(artifacts.get("policies", "") or "{}")
        vdom = pol.get("vdom") if isinstance(pol, dict) else None
    except json.JSONDecodeError:
        pass

    payload = ParsedDevicePayload(
        device_id=device_id,
        vendor="fortinet",
        firmware_version=_firmware(artifacts),
        vdom_vsys=vdom,
        rules=_parse_rules(artifacts.get("policies"), vdom),
        address_objects=_parse_addresses(artifacts.get("address_objects")),
        address_groups=_parse_addrgrps(artifacts.get("address_groups")),
        service_objects=_parse_services(artifacts.get("service_objects")),
        service_groups=_parse_service_groups(artifacts.get("service_groups")),
    )
    logger.info(
        "Parsed FortiGate device %s: %d rules, %d addr, %d svc (fw=%s)",
        device_id, len(payload.rules), len(payload.address_objects),
        len(payload.service_objects), payload.firmware_version,
    )
    return payload
