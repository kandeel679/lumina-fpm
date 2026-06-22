"""Acquisition data contracts (V3 §11) — vendor-neutral bundle handed to the parser layer."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class AcquisitionStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    AUTHENTICATION_FAILED = "authentication_failed"
    AUTHORIZATION_FAILED = "authorization_failed"
    CONNECTION_FAILED = "connection_failed"
    RATE_LIMITED = "rate_limited"
    PARSING_QUEUED = "parsing_queued"
    PARSING_FAILED = "parsing_failed"


class ErrorCode(str, enum.Enum):
    AUTH_FAILED = "AUTH_FAILED"
    AUTHZ_FAILED = "AUTHZ_FAILED"
    CONNECTION_FAILED = "CONNECTION_FAILED"
    TIMEOUT = "TIMEOUT"
    TLS_FAILED = "TLS_FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    UNSUPPORTED_ENDPOINT = "UNSUPPORTED_ENDPOINT"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    PARTIAL_DATA = "PARTIAL_DATA"


# Canonical raw artifact types (V3 Table 11).
ARTIFACT_POLICIES = "policies"
ARTIFACT_ADDRESS_OBJECTS = "address_objects"
ARTIFACT_ADDRESS_GROUPS = "address_groups"
ARTIFACT_SERVICE_OBJECTS = "service_objects"
ARTIFACT_SERVICE_GROUPS = "service_groups"
ARTIFACT_DEVICE_METADATA = "device_metadata"
ARTIFACT_INTERFACES = "interfaces"
ARTIFACT_ZONES = "zones"
ARTIFACT_SCHEDULES = "schedules"
ARTIFACT_MANIFEST = "acquisition_manifest"


@dataclass
class RawArtifact:
    """One raw API response captured for replay/audit (V3 §8)."""

    type: str
    # Raw content as text (JSON for FortiGate, XML for Palo Alto).
    content: str
    content_type: str = "application/json"
    sha256: Optional[str] = None
    path: Optional[str] = None  # set once persisted to disk


@dataclass
class AcquisitionWarning:
    type: str
    message: str
    reference: Optional[str] = None


@dataclass
class AcquisitionBundle:
    """Vendor-neutral acquisition result handed to the parser layer (V3 §11)."""

    device_id: int
    vendor_type: str  # fortinet | paloalto
    management_ip: str
    connector_version: str
    status: AcquisitionStatus = AcquisitionStatus.RUNNING
    firmware_version: Optional[str] = None
    device_metadata: Dict[str, Any] = field(default_factory=dict)
    raw_artifacts: List[RawArtifact] = field(default_factory=list)
    warnings: List[AcquisitionWarning] = field(default_factory=list)
    error_code: Optional[str] = None
    error_message: Optional[str] = None

    def add_artifact(self, artifact: RawArtifact) -> None:
        self.raw_artifacts.append(artifact)

    def add_warning(self, type_: str, message: str, reference: Optional[str] = None) -> None:
        self.warnings.append(AcquisitionWarning(type=type_, message=message, reference=reference))
