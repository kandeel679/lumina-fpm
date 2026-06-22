"""Parsing layer (Volume 2 §7, Volume 3 §11).

Converts raw vendor API responses (FortiGate JSON / Palo Alto XML) into structured,
vendor-tagged parser models. Parsers extract and structure data ONLY — they perform
no anomaly logic and no canonicalization (that is the normalization layer's job).
Parsers can replay from stored raw artifacts without re-polling the device.
"""
from .models import (
    ParsedAddressGroup,
    ParsedAddressObject,
    ParsedDevicePayload,
    ParsedRule,
    ParsedServiceGroup,
    ParsedServiceObject,
)
from .registry import parse_artifacts

__all__ = [
    "ParsedRule",
    "ParsedAddressObject",
    "ParsedAddressGroup",
    "ParsedServiceObject",
    "ParsedServiceGroup",
    "ParsedDevicePayload",
    "parse_artifacts",
]
