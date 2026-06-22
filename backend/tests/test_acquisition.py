"""Acquisition connector + storage tests (V3 acceptance, fixture-based).

These run WITHOUT a live firewall, network, or database: the HTTP layer of each
connector is monkeypatched with canned FortiOS JSON / PAN-OS XML responses. They
validate read-only collection, firmware extraction, partial-success handling, and
raw-artifact persistence (manifest + SHA-256).

Run: `python -m pytest backend/tests/test_acquisition.py`  (or `python backend/tests/test_acquisition.py`).
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("ENCRYPTION_KEY", "lab-dev-passphrase")

from services.acquisition.base import ConnectorConfig
from services.acquisition.fortigate import FortiGateConnector
from services.acquisition.paloalto import PaloAltoConnector
from services.acquisition.models import AcquisitionStatus
from services.acquisition import storage
from core.config import settings


# ── FortiOS canned REST responses (per endpoint path) ──
_FGT = {
    "/api/v2/cmdb/firewall/policy": '{"results":[{"policyid":1,"name":"FGT_ALLOW_LAN_DMZ","action":"accept"}]}',
    "/api/v2/cmdb/firewall/address": '{"results":[{"name":"LAN_NET","subnet":"10.10.10.0 255.255.255.0"}]}',
    "/api/v2/cmdb/firewall/addrgrp": '{"results":[]}',
    "/api/v2/cmdb/firewall.service/custom": '{"results":[{"name":"HTTPS","tcp-portrange":"443"}]}',
    "/api/v2/cmdb/firewall.service/group": '{"results":[]}',
    "/api/v2/monitor/system/status": '{"results":{"version":"v7.4.1","hostname":"FGT-LAB"}}',
    "/api/v2/cmdb/system/interface": '{"results":[{"name":"port1"}]}',
    "/api/v2/cmdb/firewall.schedule/recurring": '{"results":[]}',
}

# ── PAN-OS canned XML responses ──
_PAN_SYSINFO = '<response status="success"><result><system><sw-version>11.1.3</sw-version><hostname>PA-LAB</hostname></system></result></response>'
_PAN_SECURITY = '<response status="success"><result><security><rules><entry name="PA_ALLOW_LAN_DMZ"><action>allow</action></entry></rules></security></result></response>'
_PAN_EMPTY = '<response status="success"><result/></response>'


def _config(vendor):
    return ConnectorConfig(
        device_id=1, vendor_type=vendor, management_ip="192.168.55.10",
        secret="dummy", auth_type="fortigate_api_token" if vendor == "fortinet" else "panos_api_key",
        verify_tls=False, timeout_seconds=5,
    )


def test_fortigate_collect():
    c = FortiGateConnector(_config("fortinet"))
    c._get = lambda path: (200, _FGT[path])  # monkeypatch HTTP
    bundle = c.collect()
    types = {a.type for a in bundle.raw_artifacts}
    assert "policies" in types and "address_objects" in types and "service_objects" in types
    assert bundle.firmware_version == "v7.4.1", bundle.firmware_version
    assert bundle.status == AcquisitionStatus.SUCCESS
    assert len(bundle.raw_artifacts) == 8
    return bundle


def test_fortigate_partial_success_on_optional_404():
    from services.acquisition.errors import UnsupportedEndpointError

    c = FortiGateConnector(_config("fortinet"))

    def _get(path):
        if path == "/api/v2/cmdb/system/interface":  # optional → 404
            raise UnsupportedEndpointError("404")
        return (200, _FGT[path])

    c._get = _get
    bundle = c.collect()
    assert bundle.status == AcquisitionStatus.PARTIAL_SUCCESS
    assert any(w.type == "unsupported_endpoint" for w in bundle.warnings)


def test_paloalto_collect():
    c = PaloAltoConnector(_config("paloalto"))
    c._api_key = "k"  # skip keygen

    def _request(params, with_key=True):
        t = params.get("type")
        if t == "op":
            return _PAN_SYSINFO
        if t == "config":
            return _PAN_SECURITY if params.get("xpath", "").endswith("security") else _PAN_EMPTY
        return _PAN_EMPTY

    c._request = _request
    bundle = c.collect()
    types = {a.type for a in bundle.raw_artifacts}
    assert "device_metadata" in types and "policies" in types
    assert bundle.firmware_version == "11.1.3", bundle.firmware_version
    assert bundle.status == AcquisitionStatus.SUCCESS
    return bundle


def test_storage_writes_manifest_and_hashes():
    bundle = test_fortigate_collect()
    with tempfile.TemporaryDirectory() as tmp:
        settings.acquisition_raw_dir = tmp  # override raw dir for the test
        meta = storage.store_bundle(job_id=42, bundle=bundle)
        # manifest + every artifact recorded with a sha256
        assert any(m["type"] == "acquisition_manifest" for m in meta)
        assert all(m["sha256"] and os.path.exists(m["path"]) for m in meta)
        # replay
        pol = next(m for m in meta if m["type"] == "policies")
        assert "FGT_ALLOW_LAN_DMZ" in storage.load_artifact(pol["path"])


if __name__ == "__main__":
    test_fortigate_collect()
    test_fortigate_partial_success_on_optional_404()
    test_paloalto_collect()
    test_storage_writes_manifest_and_hashes()
    print("OK: all acquisition tests passed")
