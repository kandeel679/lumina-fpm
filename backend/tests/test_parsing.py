"""Parser tests against REAL captured lab artifacts (FortiOS v7.0.5, PAN-OS).

Validates that both vendors parse into the uniform ParsedDevicePayload and that the
two lab rules are recognized as the same logical access (LAN_NET -> WEB_SERVER HTTPS,
allow, no inspection) — the cross-device benchmark pair.

Run: `python backend/tests/test_parsing.py`  or  `python -m pytest backend/tests/test_parsing.py`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("ENCRYPTION_KEY", "lab-dev-passphrase")

from services.parsing import parse_artifacts

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def _read(name):
    with open(os.path.join(FIX, name), "r", encoding="utf-8") as fh:
        return fh.read()


def test_fortigate_parse():
    payload = parse_artifacts("fortinet", 1, {"policies": _read("fortigate_policy.json")})
    assert payload.firmware_version == "v7.0.5", payload.firmware_version
    assert len(payload.rules) == 1
    r = payload.rules[0]
    assert r.rule_name == "FGT_ALLOW_WEB"
    assert r.vendor_uuid == "c5dd6374-6c25-51f1-a791-b4b826e502d1"
    assert r.action == "accept" and r.enabled is True
    assert r.src_zones == ["port1"] and r.dst_zones == ["port2"]
    assert r.src_addrs == ["LAN_NET"] and r.dst_addrs == ["WEB_SERVER"]
    assert r.services == ["HTTPS"]
    assert r.logging_raw == "utm"                       # logging on
    assert r.security_profiles["utm_status"] == "disable"
    assert not r.security_profiles["profile_group"]     # no inspection
    assert r.schedule == "always" and r.nat_enabled is True
    return r


def test_paloalto_parse():
    payload = parse_artifacts("paloalto", 2, {"policies": _read("paloalto_rulebase.xml")})
    assert len(payload.rules) == 1
    r = payload.rules[0]
    assert r.rule_name == "PA_ALLOW_WEB"
    assert r.vendor_uuid == "97c0f0d9-3842-45a1-9252-84eec1cf7221"
    assert r.action == "allow" and r.enabled is True
    assert r.src_zones == ["trust"] and r.dst_zones == ["dmz"]
    assert r.src_addrs == ["LAN_NET"] and r.dst_addrs == ["WEB_SERVER"]
    assert r.services == ["service-https"]
    assert r.logging_raw == "yes"                       # log-end yes
    assert r.security_profiles["has_profile"] is False  # no inspection
    return r


def test_cross_vendor_equivalence_at_parse_level():
    fgt = test_fortigate_parse()
    pan = test_paloalto_parse()
    # Same logical access by object names — the normalization layer will canonicalize
    # zones/actions and the anomaly engine will flag the security-posture similarity.
    assert fgt.src_addrs == pan.src_addrs
    assert fgt.dst_addrs == pan.dst_addrs
    # Both allow, both no inspection → both "unprotected allow" candidates.
    assert fgt.action == "accept" and pan.action == "allow"
    assert not fgt.security_profiles["profile_group"] and pan.security_profiles["has_profile"] is False


if __name__ == "__main__":
    test_fortigate_parse()
    test_paloalto_parse()
    test_cross_vendor_equivalence_at_parse_level()
    print("OK: all parsing tests passed")
