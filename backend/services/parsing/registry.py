"""Parser dispatch by vendor (V3 §11)."""
from __future__ import annotations

from typing import Dict

from .models import ParsedDevicePayload
from . import fortigate, paloalto


def parse_artifacts(vendor_type: str, device_id: int, artifacts: Dict[str, str]) -> ParsedDevicePayload:
    """Parse stored raw artifacts (type -> text) into a ParsedDevicePayload."""
    vendor = (vendor_type or "").lower()
    if vendor == "fortinet":
        return fortigate.parse(device_id, artifacts)
    if vendor == "paloalto":
        return paloalto.parse(device_id, artifacts)
    raise ValueError(f"No parser for vendor_type '{vendor_type}'")
