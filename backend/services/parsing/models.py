"""Parser output models (V2 §7.3, V3 §11).

Vendor-tagged but uniformly-shaped so the normalization layer can consume both
vendors. Raw vendor values are preserved (e.g. action 'accept'/'allow',
logtraffic 'utm') — canonicalization happens in normalization, not here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ParsedAddressObject:
    name: str
    type: str                       # ip_address | cidr | fqdn | any | unknown
    value: str                      # canonical-ish value (e.g. 10.10.10.0/24)
    raw_value: Optional[str] = None
    vendor_uuid: Optional[str] = None


@dataclass
class ParsedAddressGroup:
    name: str
    members: List[str] = field(default_factory=list)
    vendor_uuid: Optional[str] = None


@dataclass
class ParsedServiceObject:
    name: str
    protocol: Optional[str] = None  # tcp | udp | icmp | application | any | unknown
    port_start: Optional[int] = None
    port_end: Optional[int] = None
    app_id: Optional[str] = None
    raw_value: Optional[str] = None


@dataclass
class ParsedServiceGroup:
    name: str
    members: List[str] = field(default_factory=list)


@dataclass
class ParsedRule:
    vendor: str                     # fortinet | paloalto
    rule_name: str
    rule_order: int
    vendor_rule_id: Optional[str] = None
    vendor_uuid: Optional[str] = None
    vdom_vsys: Optional[str] = None
    enabled: bool = True
    src_zones: List[str] = field(default_factory=list)
    dst_zones: List[str] = field(default_factory=list)
    src_addrs: List[str] = field(default_factory=list)
    dst_addrs: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    applications: List[str] = field(default_factory=list)
    action: str = "unknown"         # raw vendor action
    logging_raw: Optional[str] = None
    security_profiles: Dict[str, Any] = field(default_factory=dict)
    schedule: Optional[str] = None
    nat_enabled: Optional[bool] = None
    description: Optional[str] = None
    src_negate: bool = False
    dst_negate: bool = False
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ParsedDevicePayload:
    """Everything a single device's acquisition produced, structured for normalization."""

    device_id: int
    vendor: str
    firmware_version: Optional[str] = None
    vdom_vsys: Optional[str] = None
    rules: List[ParsedRule] = field(default_factory=list)
    address_objects: List[ParsedAddressObject] = field(default_factory=list)
    address_groups: List[ParsedAddressGroup] = field(default_factory=list)
    service_objects: List[ParsedServiceObject] = field(default_factory=list)
    service_groups: List[ParsedServiceGroup] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
