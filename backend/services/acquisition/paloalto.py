"""Palo Alto connector — PAN-OS XML API, read-only (V3 §10).

Authentication: API key (via X-PAN-KEY header). The key may be provided directly
or generated with type=keygen from a stored user/password. Only read operations
are issued: type=keygen, type=config&action=show, type=op (show ...). There is NO
set/edit/delete/move/commit path (V3 Table 24, V12 §3).
"""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

from core.logging import get_logger

from .base import ConnectorInterface
from .errors import (
    AuthenticationError,
    ConnectionFailedError,
    MalformedResponseError,
    TimeoutError as AcqTimeoutError,
    TLSError,
)
from .models import (
    ARTIFACT_ADDRESS_GROUPS,
    ARTIFACT_ADDRESS_OBJECTS,
    ARTIFACT_DEVICE_METADATA,
    ARTIFACT_INTERFACES,
    ARTIFACT_POLICIES,
    ARTIFACT_SERVICE_GROUPS,
    ARTIFACT_SERVICE_OBJECTS,
    ARTIFACT_ZONES,
    AcquisitionBundle,
    AcquisitionStatus,
    RawArtifact,
)

logger = get_logger(__name__)

def _vsys_xpath(vsys: str, leaf: str) -> str:
    """Unqualified vsys xpath — the form proven working against the lab PAN-OS.

    Lab validation showed `/config/devices/entry/vsys/entry/rulebase` returns the
    rulebase without `[@name=...]` predicates (single-vsys device). For multi-vsys
    deployments a predicate `vsys/entry[@name='<vsys>']` can be reintroduced; kept
    simple here to match the validated query.
    """
    return f"/config/devices/entry/vsys/entry/{leaf}"


class PaloAltoConnector(ConnectorInterface):
    vendor_type = "paloalto"
    connector_version = "1.0.0"

    def __init__(self, config):
        super().__init__(config)
        self.vsys = "vsys1"
        self._api_key: str | None = None

    def _base_url(self) -> str:
        return f"https://{self.config.management_ip}/api/"

    def _request(self, params: Dict[str, str], *, with_key: bool = True) -> str:
        import requests  # lazy import (dep present in container)

        headers = {}
        if with_key and self._api_key:
            headers["X-PAN-KEY"] = self._api_key
        try:
            resp = requests.get(
                self._base_url(),
                params=params,
                headers=headers,
                verify=self.config.verify_tls,
                timeout=self.config.timeout_seconds,
            )
        except requests.exceptions.SSLError as exc:
            raise TLSError("TLS verification failed") from exc
        except requests.exceptions.Timeout as exc:
            raise AcqTimeoutError("PAN-OS request timed out") from exc
        except requests.exceptions.ConnectionError as exc:
            raise ConnectionFailedError("PAN-OS connection failed") from exc

        if resp.status_code == 403:
            raise AuthenticationError("PAN-OS API key rejected (403)")
        if resp.status_code >= 400:
            raise ConnectionFailedError(f"PAN-OS HTTP {resp.status_code}")
        text = resp.text or ""
        # PAN-OS returns 200 with status="error" in the XML body for bad auth.
        if 'status="error"' in text and "Invalid credential" in text:
            raise AuthenticationError("PAN-OS invalid credentials")
        return text

    def authenticate(self) -> None:
        if self.config.auth_type == "panos_userpass":
            # secret is "user:password"; generate an ephemeral key (read-only op).
            if ":" not in self.config.secret:
                raise AuthenticationError("panos_userpass secret must be 'user:password'")
            user, password = self.config.secret.split(":", 1)
            xml = self._request(
                {"type": "keygen", "user": user, "password": password}, with_key=False
            )
            m = re.search(r"<key>(.+?)</key>", xml, re.DOTALL)
            if not m:
                raise AuthenticationError("PAN-OS keygen did not return a key")
            self._api_key = m.group(1).strip()
        else:
            # secret IS the API key.
            self._api_key = self.config.secret

    def validate_connection(self) -> bool:
        if not self._api_key:
            self.authenticate()
        self._request({"type": "op", "cmd": "<show><system><info></info></system></show>"})
        return True

    def _config_show(self, leaf: str) -> str:
        return self._request(
            {"type": "config", "action": "show", "xpath": _vsys_xpath(self.vsys, leaf)}
        )

    def _extract_firmware(self, sysinfo_xml: str) -> "str | None":
        m = re.search(r"<sw-version>(.+?)</sw-version>", sysinfo_xml, re.DOTALL)
        return m.group(1).strip() if m else None

    def collect(self) -> AcquisitionBundle:
        if not self._api_key:
            self.authenticate()

        bundle = AcquisitionBundle(
            device_id=self.config.device_id,
            vendor_type=self.vendor_type,
            management_ip=self.config.management_ip,
            connector_version=self.connector_version,
        )

        # Required: system info (firmware) via op command.
        sysinfo = self._request(
            {"type": "op", "cmd": "<show><system><info></info></system></show>"}
        )
        bundle.add_artifact(
            RawArtifact(type=ARTIFACT_DEVICE_METADATA, content=sysinfo, content_type="application/xml")
        )
        fw = self._extract_firmware(sysinfo)
        if fw:
            bundle.firmware_version = fw
            bundle.device_metadata["firmware_version"] = fw

        # Required config leaves (V3 Table 18).
        required: List[Tuple[str, str]] = [
            (ARTIFACT_POLICIES, "rulebase/security"),
            (ARTIFACT_ADDRESS_OBJECTS, "address"),
            (ARTIFACT_ADDRESS_GROUPS, "address-group"),
            (ARTIFACT_SERVICE_OBJECTS, "service"),
            (ARTIFACT_SERVICE_GROUPS, "service-group"),
        ]
        for artifact_type, leaf in required:
            xml = self._config_show(leaf)
            bundle.add_artifact(
                RawArtifact(type=artifact_type, content=xml, content_type="application/xml")
            )

        # Recommended: zones.
        try:
            zones_xml = self._config_show("zone")
            bundle.add_artifact(
                RawArtifact(type=ARTIFACT_ZONES, content=zones_xml, content_type="application/xml")
            )
        except ConnectionFailedError as exc:
            bundle.add_warning("unsupported_endpoint", f"zones: {exc}")

        bundle.status = AcquisitionStatus.SUCCESS
        return bundle
