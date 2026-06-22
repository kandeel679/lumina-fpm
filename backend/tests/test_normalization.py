"""Normalization tests — cross-vendor correlation against REAL lab data.

Proves the keystone: FortiGate and Palo Alto objects/services/rules normalize into
one canonical model where equivalent assets correlate across vendors. Pure (no DB).

Run: `python backend/tests/test_normalization.py`  or  `python -m pytest ...`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("ENCRYPTION_KEY", "lab-dev-passphrase")

from services.parsing import parse_artifacts
from services.normalization import normalize_payloads
from services.normalization import canonical as C

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def _read(name):
    with open(os.path.join(FIX, name), "r", encoding="utf-8") as fh:
        return fh.read()


def _payloads():
    fgt = parse_artifacts("fortinet", 1, {
        "policies": _read("fortigate_policy.json"),
        "address_objects": _read("fortigate_address.json"),
        "address_groups": _read("fortigate_addrgrp.json"),
        "service_objects": _read("fortigate_service.json"),
        "service_groups": _read("fortigate_service_group.json"),
    })
    pan = parse_artifacts("paloalto", 2, {
        "policies": _read("paloalto_rulebase.xml"),
        "address_objects": _read("paloalto_address.xml"),
        "service_objects": _read("paloalto_service.xml"),
        "service_groups": _read("paloalto_service_group.xml"),
    })
    return fgt, pan


def test_object_correlation():
    fgt, pan = _payloads()
    res = normalize_payloads([fgt, pan])
    lan_key = C.object_key("cidr", "10.10.10.0/24")
    web_key = C.object_key("cidr", "10.10.20.10/32")
    assert lan_key in res.normalized_objects, list(res.normalized_objects)[:8]
    assert web_key in res.normalized_objects
    # LAN_NET present on BOTH vendors, mapped to the one canonical object at 1.00.
    lan_maps = [m for m in res.object_mappings if m.normalized_key == lan_key]
    devs = {m.device_id for m in lan_maps}
    assert devs == {1, 2}, devs
    assert all(m.confidence == 1.00 and m.match_method == "exact_name_value" for m in lan_maps)
    return res


def test_service_correlation_incl_predefined():
    fgt, pan = _payloads()
    res = normalize_payloads([fgt, pan])
    https_key = C.service_key("tcp", 443, 443)
    assert https_key in res.normalized_services
    # FortiGate custom HTTPS maps here...
    svc_maps = [m for m in res.service_mappings if m.normalized_key == https_key]
    assert any(m.device_id == 1 for m in svc_maps)
    # ...and the PAN rule's predefined 'service-https' resolves to the SAME canonical service.
    pan_rule = next(r for r in res.rules if r.vendor == "paloalto")
    assert https_key in pan_rule.service_keys, pan_rule.service_keys


def test_cross_device_rule_equivalence():
    fgt, pan = _payloads()
    res = normalize_payloads([fgt, pan])
    fgt_rule = next(r for r in res.rules if r.vendor == "fortinet")
    pan_rule = next(r for r in res.rules if r.vendor == "paloalto")
    # Canonical action + posture
    assert fgt_rule.action == "allow" and pan_rule.action == "allow"
    assert fgt_rule.logging_enabled == "true" and pan_rule.logging_enabled == "true"
    assert fgt_rule.security_inspection_enabled == "false"   # unprotected allow
    assert pan_rule.security_inspection_enabled == "false"
    # Same canonical access set across vendors → cross-device equivalent (anomaly engine input)
    assert set(fgt_rule.src_object_keys) == set(pan_rule.src_object_keys)
    assert set(fgt_rule.dst_object_keys) == set(pan_rule.dst_object_keys)
    assert set(fgt_rule.service_keys) == set(pan_rule.service_keys)
    # Different devices → different content hashes (zones/vendor differ)
    assert fgt_rule.normalized_content_hash != pan_rule.normalized_content_hash


def test_idempotent_determinism():
    fgt, pan = _payloads()
    r1 = normalize_payloads([fgt, pan])
    r2 = normalize_payloads([fgt, pan])
    h1 = sorted(r.normalized_content_hash for r in r1.rules)
    h2 = sorted(r.normalized_content_hash for r in r2.rules)
    assert h1 == h2, "normalization must be deterministic"


if __name__ == "__main__":
    test_object_correlation()
    test_service_correlation_incl_predefined()
    test_cross_device_rule_equivalence()
    test_idempotent_determinism()
    print("OK: all normalization tests passed")
