"""Firewall acquisition layer (Volume 3).

Read-only extraction of firewall configuration from FortiGate (FortiOS REST) and
Palo Alto (PAN-OS XML) devices. Connectors collect data only — they perform NO
anomaly logic and NO write/commit operations. Acquisition runs asynchronously via
Celery workers (never inside the FastAPI request cycle).
"""
from .base import ConnectorInterface
from .models import (
    AcquisitionBundle,
    AcquisitionStatus,
    AcquisitionWarning,
    ErrorCode,
    RawArtifact,
)
from .errors import (
    AcquisitionError,
    AuthenticationError,
    AuthorizationError,
    ConnectionFailedError,
    RateLimitedError,
    TimeoutError as AcqTimeoutError,
    UnsupportedVendorError,
)
from .registry import get_connector, normalize_vendor_type, resolve_device_vendor_type

__all__ = [
    "ConnectorInterface",
    "AcquisitionBundle",
    "AcquisitionStatus",
    "AcquisitionWarning",
    "ErrorCode",
    "RawArtifact",
    "AcquisitionError",
    "AuthenticationError",
    "AuthorizationError",
    "ConnectionFailedError",
    "RateLimitedError",
    "AcqTimeoutError",
    "UnsupportedVendorError",
    "get_connector",
    "normalize_vendor_type",
    "resolve_device_vendor_type",
]
