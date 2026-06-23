"""Shared connector interface (V3 §5).

Every vendor connector implements this read-only contract. Connectors must use
GET/show/monitor/keygen/op-show only — NEVER set/edit/delete/move/commit (V3 Table 24).
"""
from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Optional

from .models import AcquisitionBundle


@dataclass
class ConnectorConfig:
    """Connection parameters resolved from the device record + decrypted credential."""

    device_id: int
    vendor_type: str
    management_ip: str
    secret: str               # decrypted token / api-key / userpass — in-memory only
    auth_type: str            # fortigate_api_token | panos_api_key | panos_userpass
    verify_tls: bool = True
    timeout_seconds: int = 60
    scheme: str = "https"     # "http" only as a lab escape hatch (see settings.firewall_insecure_http_hosts)


class ConnectorInterface(abc.ABC):
    """Read-only vendor connector contract."""

    vendor_type: str = "unknown"
    connector_version: str = "1.0.0"

    def __init__(self, config: ConnectorConfig):
        self.config = config

    # -- connection lifecycle --
    @abc.abstractmethod
    def authenticate(self) -> None:
        """Establish/validate authentication (no config changes)."""

    @abc.abstractmethod
    def validate_connection(self) -> bool:
        """Lightweight read to confirm connectivity + auth. Returns True on success."""

    # -- extraction (each returns nothing; appends artifacts to the bundle) --
    @abc.abstractmethod
    def collect(self) -> AcquisitionBundle:
        """Run the full read-only extraction and return an AcquisitionBundle.

        Implementations must call ONLY read endpoints and capture each response as
        a RawArtifact. Failure of an optional endpoint → warning + partial_success;
        failure of a required endpoint (policies) → raise an AcquisitionError.
        """
