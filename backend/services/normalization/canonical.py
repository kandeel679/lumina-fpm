"""Canonical mapping rules (Volume 4 §5-11).

Pure functions that convert vendor-native values into canonical LuminaFPM values.
No DB, no I/O — deterministic and unit-testable.
"""
from __future__ import annotations

import hashlib
from typing import Optional, Tuple

from services.parsing.models import ParsedRule

# ── Canonical action enum (V4 Table 6) ──
_FGT_ACTION = {"accept": "allow", "deny": "deny", "ipsec": "ipsec"}
_PAN_ACTION = {
    "allow": "allow", "deny": "deny", "drop": "drop",
    "reset-client": "reset", "reset-server": "reset", "reset-both": "reset",
}


def canonical_action(vendor: str, raw: Optional[str]) -> str:
    if not raw:
        return "unknown"
    raw = raw.lower()
    if vendor == "fortinet":
        return _FGT_ACTION.get(raw, "unknown")
    if vendor == "paloalto":
        return _PAN_ACTION.get(raw, "unknown")
    return "unknown"


# ── Logging abstraction (V4 §11.2) → 'true' | 'false' | 'unknown' ──
def canonical_logging(vendor: str, rule: ParsedRule) -> str:
    raw = (rule.logging_raw or "").lower()
    if vendor == "fortinet":
        if raw in ("all", "utm"):
            return "true"
        if raw in ("disable", ""):
            return "false" if raw == "disable" else "unknown"
        return "unknown"
    if vendor == "paloalto":
        if raw == "yes":
            return "true"
        if raw == "no":
            return "false"
    return "unknown"


# ── Security inspection abstraction (V4 §11.1) → 'true' | 'false' | 'unknown' ──
_FGT_PROFILE_KEYS = ("profile_group", "av_profile", "ips_sensor", "webfilter_profile", "application_list")


def canonical_inspection(vendor: str, rule: ParsedRule) -> str:
    action = canonical_action(vendor, rule.action)
    if vendor == "fortinet":
        sp = rule.security_profiles or {}
        if (sp.get("utm_status") == "enable") or any(sp.get(k) for k in _FGT_PROFILE_KEYS):
            return "true"
        return "false" if action == "allow" else "unknown"
    if vendor == "paloalto":
        sp = rule.security_profiles or {}
        if sp.get("has_profile"):
            return "true"
        return "false" if action == "allow" else "unknown"
    return "unknown"


def canonical_profile_strength(inspection: str, rule: ParsedRule) -> str:
    if inspection == "true":
        return "strong"
    if inspection == "false":
        return "missing"
    return "unknown"


def canonical_schedule_scope(schedule: Optional[str]) -> str:
    if not schedule:
        return "unknown"
    return "always" if schedule.lower() == "always" else "limited"


# ── ANY detection (V4 Table 13) ──
_ANY_NAMES = {"all", "any"}
_ANY_VALUES = {"0.0.0.0/0", "::/0", "0.0.0.0 0.0.0.0", "0.0.0.0/0.0.0.0"}


def is_any_object(name: str, value: str) -> bool:
    return (name or "").strip().lower() in _ANY_NAMES or (value or "").strip() in _ANY_VALUES


# ── Canonical object value/type ──
def canonical_object(name: str, otype: str, value: str) -> Tuple[str, str]:
    """Return (canonical_type, canonical_value)."""
    if is_any_object(name, value):
        return "any", "0.0.0.0/0"
    return otype or "unknown", (value or "").strip()


# ── Predefined PAN-OS services (so rules referencing service-https resolve) ──
PREDEFINED_SERVICES = {
    "service-http": ("tcp", 80, 80),
    "service-https": ("tcp", 443, 443),
    "any": ("any", None, None),
    "application-default": ("application", None, None),
}


def service_key(protocol: Optional[str], port_start: Optional[int], port_end: Optional[int],
                app_id: Optional[str] = None) -> str:
    if app_id:
        return f"app:{app_id}"
    p = (protocol or "unknown").lower()
    if port_start is None and port_end is None:
        return f"{p}:any"
    return f"{p}:{port_start}-{port_end}"


# ── "All services" canonicalization (V4 Table 13, service axis) ──
# Vendor service objects that mean "all services". FortiGate's predefined "ALL"
# carries NO port range, so without this it keys as 'unknown:any' and the coverage
# logic (shadowing/redundancy) would not treat it as the ANY sentinel — while PAN's
# 'any' resolves correctly via PREDEFINED_SERVICES. We also map the FortiGate
# ALL_TCP/ALL_UDP/ALL_ICMP predefined services to full ranges.
_ANY_SERVICE_NAMES = {"all", "any"}
_BROAD_SERVICES = {
    "all": ("any", None, None),
    "all_tcp": ("tcp", 1, 65535),
    "all_udp": ("udp", 1, 65535),
    "all_icmp": ("icmp", None, None),
    "all_icmp6": ("icmp6", None, None),
}


def is_any_service(name: Optional[str]) -> bool:
    return (name or "").strip().lower() in _ANY_SERVICE_NAMES


def canonical_service(name: Optional[str], protocol: Optional[str],
                      port_start: Optional[int], port_end: Optional[int]
                      ) -> Tuple[Optional[str], Optional[int], Optional[int]]:
    """Canonicalize a service's (protocol, port_start, port_end).

    Maps vendor 'all'/'any' services to the canonical ANY service and the FortiGate
    ALL_TCP/ALL_UDP/ALL_ICMP predefined services to full ranges, so the deterministic
    coverage and wide-port logic recognize them. Other services pass through unchanged.
    """
    n = (name or "").strip().lower()
    if n in _BROAD_SERVICES:
        return _BROAD_SERVICES[n]
    return (protocol, port_start, port_end)


def object_key(canonical_type: str, canonical_value: str) -> str:
    return f"{canonical_type}:{canonical_value}"


def content_hash(*parts: str) -> str:
    """Deterministic normalized-content hash (V4 §13.1, Table 8 derived id)."""
    joined = "|".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def derive_vendor_uuid(device_id: int, vdom_vsys: Optional[str], vendor_rule_id: Optional[str],
                       rule_name: str, vendor_path: str = "") -> str:
    """Stable derived vendor_uuid when the device exposes none (V4 Table 8)."""
    return content_hash(str(device_id), vdom_vsys or "", vendor_rule_id or "", rule_name, vendor_path)


# ── Sensitivity inference for normalized objects (V5 normalized_object.sensitivity) ──
def infer_sensitivity(name: str, value: str) -> str:
    n = (name or "").upper()
    if "ADMIN" in n or "MGMT" in n:
        return "admin"
    if "DB" in n or "DATABASE" in n or "SQL" in n:
        return "database"
    if "DMZ" in n or "WEB" in n or "MAIL" in n:
        return "dmz"
    if "MALICIOUS" in n or "THREAT" in n or "BAD" in n:
        return "critical"
    if is_any_object(name, value):
        return "public"
    return "internal"
