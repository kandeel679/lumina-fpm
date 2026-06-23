"""Indicator extraction (Volume 9 §4) — pure.

Extracts candidate threat indicators from normalized object values. **Private
RFC1918 / loopback / link-local / reserved addresses are NOT public** and are
excluded unless internal correlation is explicitly enabled (V9 §4, V12 §10). The
'any' sentinel (0.0.0.0/0) is never an indicator.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Indicator:
    type: str            # ip_address | cidr | fqdn
    value: str
    is_public: bool
    object_id: Optional[int] = None
    device_id: Optional[int] = None


def is_public_ip(value: str) -> Optional[bool]:
    """True/False for a parseable IP/CIDR (global vs private), None if not an IP."""
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    if net.num_addresses == 0:
        return False
    # 0.0.0.0/0 / ::/0 are the ANY sentinel, never an indicator
    if int(net.network_address) == 0 and net.prefixlen == 0:
        return False
    return net.is_global


def classify(value: str) -> Optional[str]:
    """Return indicator type for a value, or None if it should be skipped."""
    v = (value or "").strip().lower()
    if not v or v in ("any", "0.0.0.0/0", "::/0", "0.0.0.0/0.0.0.0"):
        return None  # the ANY sentinel is never an indicator
    pub = is_public_ip(value)
    if pub is not None:
        return "cidr" if "/" in value and not value.endswith("/32") else "ip_address"
    # crude FQDN check: contains a dot, no spaces, not a wildcard-only token
    if "." in v and " " not in v and not v.startswith("*"):
        return "fqdn"
    return None


def extract_indicators(objects, allow_internal: bool = False) -> List[Indicator]:
    """objects: iterable of (object_id, device_id, value). Dedupes by value."""
    seen = set()
    out: List[Indicator] = []
    for object_id, device_id, value in objects:
        itype = classify(value)
        if itype is None:
            continue
        pub = is_public_ip(value)
        is_public = True if pub is None else bool(pub)  # FQDNs treated as public
        if not is_public and not allow_internal:
            continue  # never send internal indicators to external providers
        # canonicalize a single-host indicator to its bare IP (strip /32, /128)
        norm = value.strip()
        if itype == "ip_address" and "/" in norm:
            norm = norm.split("/", 1)[0]
        if norm in seen:
            continue
        seen.add(norm)
        out.append(Indicator(type=itype, value=norm, is_public=is_public,
                             object_id=object_id, device_id=device_id))
    return out
