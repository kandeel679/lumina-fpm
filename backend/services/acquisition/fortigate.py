"""FortiGate connector — FortiOS REST API, read-only (V3 §9).

Authentication: Bearer API token (dedicated read-only API admin account).
ONLY GET requests to /api/v2/cmdb/... and /api/v2/monitor/... are issued. There
is no code path that performs set/edit/delete/move — this is enforced by using a
single ``_get`` helper and never a write verb (V3 Table 24, V12 §3).
"""
from __future__ import annotations

import json
from typing import Any, Dict

from core.logging import get_logger

from .base import ConnectorInterface
from .errors import (
    AuthenticationError,
    AuthorizationError,
    ConnectionFailedError,
    MalformedResponseError,
    TimeoutError as AcqTimeoutError,
    TLSError,
    UnsupportedEndpointError,
)
from .models import (
    ARTIFACT_ADDRESS_GROUPS,
    ARTIFACT_ADDRESS_OBJECTS,
    ARTIFACT_DEVICE_METADATA,
    ARTIFACT_INTERFACES,
    ARTIFACT_POLICIES,
    ARTIFACT_SCHEDULES,
    ARTIFACT_SERVICE_GROUPS,
    ARTIFACT_SERVICE_OBJECTS,
    AcquisitionBundle,
    AcquisitionStatus,
    RawArtifact,
)

logger = get_logger(__name__)

# Required + recommended read endpoints (V3 Table 13). (artifact_type, path, required)
_ENDPOINTS = [
    (ARTIFACT_POLICIES, "/api/v2/cmdb/firewall/policy", True),
    (ARTIFACT_ADDRESS_OBJECTS, "/api/v2/cmdb/firewall/address", True),
    (ARTIFACT_ADDRESS_GROUPS, "/api/v2/cmdb/firewall/addrgrp", True),
    (ARTIFACT_SERVICE_OBJECTS, "/api/v2/cmdb/firewall.service/custom", True),
    (ARTIFACT_SERVICE_GROUPS, "/api/v2/cmdb/firewall.service/group", True),
    (ARTIFACT_DEVICE_METADATA, "/api/v2/monitor/system/status", True),
    (ARTIFACT_INTERFACES, "/api/v2/cmdb/system/interface", False),
    (ARTIFACT_SCHEDULES, "/api/v2/cmdb/firewall.schedule/recurring", False),
]


class FortiGateConnector(ConnectorInterface):
    vendor_type = "fortinet"
    connector_version = "1.0.0"

    def _base_url(self) -> str:
        return f"{self.config.scheme}://{self.config.management_ip}"

    def _headers(self) -> Dict[str, str]:
        # Bearer token auth (V3 §9.2). The token is held in memory only.
        return {"Authorization": f"Bearer {self.config.secret}", "Accept": "application/json"}

    def _get(self, path: str) -> "tuple[int, str]":
        """Issue a single read-only GET. Returns (status_code, text). Maps errors."""
        import requests  # imported lazily so the module compiles without the dep present

        url = self._base_url() + path
        try:
            resp = requests.get(
                url,
                headers=self._headers(),
                verify=self.config.verify_tls,
                timeout=self.config.timeout_seconds,
            )
        except requests.exceptions.SSLError as exc:
            raise TLSError("TLS verification failed") from exc
        except requests.exceptions.Timeout as exc:
            raise AcqTimeoutError(f"Timeout calling {path}") from exc
        except requests.exceptions.ConnectionError as exc:
            raise ConnectionFailedError(f"Connection failed to {path}") from exc

        if resp.status_code == 401:
            raise AuthenticationError("FortiGate token rejected (401)")
        if resp.status_code == 403:
            raise AuthorizationError("FortiGate token lacks permission (403)")
        if resp.status_code == 404:
            raise UnsupportedEndpointError(f"Endpoint not found: {path}")
        if resp.status_code >= 400:
            raise ConnectionFailedError(f"HTTP {resp.status_code} from {path}")
        return resp.status_code, resp.text

    def authenticate(self) -> None:
        # FortiGate REST is stateless token auth; validate by a cheap read.
        self.validate_connection()

    def validate_connection(self) -> bool:
        _code, _text = self._get("/api/v2/monitor/system/status")
        return True

    def _extract_firmware(self, status_text: str) -> "str | None":
        try:
            data = json.loads(status_text)
        except json.JSONDecodeError:
            return None
        results: Any = data.get("results") if isinstance(data, dict) else None
        # FortiOS returns version under results.version or top-level 'version'.
        if isinstance(results, dict):
            v = results.get("version") or results.get("os_version")
            if v:
                return str(v)
        return data.get("version") if isinstance(data, dict) else None

    def collect(self) -> AcquisitionBundle:
        bundle = AcquisitionBundle(
            device_id=self.config.device_id,
            vendor_type=self.vendor_type,
            management_ip=self.config.management_ip,
            connector_version=self.connector_version,
        )
        had_optional_failure = False
        for artifact_type, path, required in _ENDPOINTS:
            try:
                _code, text = self._get(path)
            except UnsupportedEndpointError as exc:
                if required:
                    raise
                had_optional_failure = True
                bundle.add_warning("unsupported_endpoint", f"{artifact_type}: {exc}", path)
                continue
            bundle.add_artifact(RawArtifact(type=artifact_type, content=text, content_type="application/json"))
            if artifact_type == ARTIFACT_DEVICE_METADATA:
                fw = self._extract_firmware(text)
                if fw:
                    bundle.firmware_version = fw
                    bundle.device_metadata["firmware_version"] = fw

        bundle.status = (
            AcquisitionStatus.PARTIAL_SUCCESS if had_optional_failure else AcquisitionStatus.SUCCESS
        )
        return bundle
