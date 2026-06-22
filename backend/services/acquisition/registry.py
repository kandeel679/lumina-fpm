"""Connector registry — dispatch on vendor_type (V3 §5.2).

Never hardcodes device IPs or credentials; the caller resolves device metadata
from PostgreSQL and the decrypted secret from the credential store.
"""
from __future__ import annotations

from .base import ConnectorConfig, ConnectorInterface
from .errors import UnsupportedVendorError
from .fortigate import FortiGateConnector
from .paloalto import PaloAltoConnector

_CONNECTORS = {
    "fortinet": FortiGateConnector,
    "paloalto": PaloAltoConnector,
}


def normalize_vendor_type(value: str | None) -> str:
    """Map any vendor label (name/api_type/semantic) to the canonical connector key."""
    v = (value or "").strip().lower()
    if not v:
        return ""
    if "forti" in v:
        return "fortinet"
    if "palo" in v or "pan-os" in v or v == "panos":
        return "paloalto"
    return v


def resolve_device_vendor_type(device) -> str:
    """Resolve a device's connector vendor_type, deriving from its vendor if unset.

    Duck-typed (no models import): reads device.vendor_type, falling back to the
    related vendor's name / api_type. Returns '' if it cannot be determined.
    """
    vt = normalize_vendor_type(getattr(device, "vendor_type", None))
    if vt:
        return vt
    vendor = getattr(device, "vendor", None)
    if vendor is not None:
        return normalize_vendor_type(getattr(vendor, "name", None)) or \
            normalize_vendor_type(getattr(vendor, "api_type", None))
    return ""


def get_connector(config: ConnectorConfig) -> ConnectorInterface:
    vendor = (config.vendor_type or "").lower()
    cls = _CONNECTORS.get(vendor)
    if cls is None:
        raise UnsupportedVendorError(f"No connector for vendor_type '{config.vendor_type}'")
    return cls(config)


def supported_vendors() -> list[str]:
    return sorted(_CONNECTORS.keys())
