"""Anomaly engine tests (Volume 5).

Two layers:
  1. Ground-truth on REAL fixtures: analyze() yields exactly 2 unprotected_allow +
     2 missing_description and NO cross-device findings.
  2. Crafted-input unit tests for shadowing / duplicate / conflict /
     any_to_sensitive / overly_permissive using hand-built NormalizedRule lists.

Pure (no DB). Run: `python backend/tests/test_anomaly.py`.
"""
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("ENCRYPTION_KEY", "lab-dev-passphrase")

from services.parsing import parse_artifacts
from services.parsing.models import (
    ParsedAddressObject,
    ParsedDevicePayload,
    ParsedRule,
    ParsedServiceObject,
)
from services.normalization import normalize_payloads
from services.normalization import canonical as C
from services.normalization.model import (
    NormalizationResult,
    NormalizedObjectRec,
    NormalizedRule,
)
from services.anomaly import analyze
from services.anomaly import detectors as D

FIX = os.path.join(os.path.dirname(__file__), "fixtures")

ANY_OBJ = C.object_key("any", "0.0.0.0/0")
ANY_SVC = C.service_key("any", None, None)


def _read(name):
    with open(os.path.join(FIX, name), "r", encoding="utf-8") as fh:
        return fh.read()


def _fixture_result():
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
    return normalize_payloads([fgt, pan])


def _rule(device_id, order, name, action, src, dst, svc, **kw):
    defaults = dict(
        vendor="test",
        rule_name=name,
        rule_order=order,
        vendor_rule_id=str(order),
        vendor_uuid=f"{device_id}:{name}",
        vdom_vsys=None,
        enabled=True,
        src_zone="z",
        dst_zone="z",
        action=action,
        logging_enabled="true",
        security_inspection_enabled="true",
        security_profile_group="g",
        security_profile_strength="strong",
        schedule="always",
        schedule_scope="always",
        nat_enabled=False,
        description="desc",
        src_negate=False,
        dst_negate=False,
        src_object_keys=list(src),
        dst_object_keys=list(dst),
        service_keys=list(svc),
        src_object_names=[],
        dst_object_names=[],
        service_names=[],
        normalized_content_hash=f"h{device_id}{order}",
    )
    defaults.update(kw)
    return NormalizedRule(device_id=device_id, **defaults)


def _result(rules, objects=None):
    return NormalizationResult(
        normalized_objects=objects or {},
        rules=list(rules),
    )


# ───────────────────── ground truth on real fixtures ─────────────────────
def test_fixtures_ground_truth():
    res = _fixture_result()
    counts = collections.Counter(f.anomaly_type for f in analyze(res))
    assert counts.get("unprotected_allow") == 2, counts
    assert counts.get("missing_description") == 2, counts
    assert "cross_device_inconsistency" not in counts, counts
    assert "cross_device_security_posture_inconsistency" not in counts, counts
    # severities
    for f in analyze(res):
        if f.anomaly_type == "unprotected_allow":
            assert f.severity == "high"
        if f.anomaly_type == "missing_description":
            assert f.severity == "low"


def test_determinism_on_fixtures():
    res = _fixture_result()
    a = [(f.anomaly_type, f.device_id, f.rule_uuid) for f in analyze(res)]
    b = [(f.anomaly_type, f.device_id, f.rule_uuid) for f in analyze(res)]
    assert a == b


# ───────────────────── crafted unit tests ─────────────────────
def test_duplicate_rules():
    web = C.object_key("cidr", "10.0.0.0/24")
    dst = C.object_key("cidr", "10.0.1.10/32")
    svc = C.service_key("tcp", 443, 443)
    rules = [
        _rule(1, 1, "A", "allow", [web], [dst], [svc]),
        _rule(1, 2, "B", "allow", [web], [dst], [svc]),
    ]
    finds = D.detect_duplicate_rules(_result(rules))
    assert len(finds) == 1, finds
    f = finds[0]
    assert f.anomaly_type == "duplicate_rules"
    assert f.rule_uuid == "1:B" and f.related_rule_uuid == "1:A"


def test_shadowing():
    web = C.object_key("cidr", "10.0.0.0/24")
    svc = C.service_key("tcp", 443, 443)
    rules = [
        # earlier broad DENY (src=web; ANY dst/svc) is a superset of the later allow
        _rule(1, 1, "BLOCK", "deny", [web], [ANY_OBJ], [ANY_SVC]),
        _rule(1, 2, "PERMIT", "allow", [web], [web], [svc]),
    ]
    finds = D.detect_shadowing(_result(rules))
    assert len(finds) == 1, finds
    f = finds[0]
    assert f.anomaly_type == "shadowing"
    assert f.rule_uuid == "1:PERMIT" and f.related_rule_uuid == "1:BLOCK"
    assert f.severity == "high"


def test_conflict():
    web = C.object_key("cidr", "10.0.0.0/24")
    dst = C.object_key("cidr", "10.0.1.10/32")
    svc = C.service_key("tcp", 443, 443)
    rules = [
        _rule(1, 1, "ALLOW_IT", "allow", [web], [dst], [svc]),
        _rule(1, 2, "DENY_IT", "deny", [web], [dst], [svc]),
    ]
    finds = D.detect_conflict(_result(rules))
    assert len(finds) == 1, finds
    f = finds[0]
    assert f.anomaly_type == "conflict"
    assert {f.rule_uuid, f.related_rule_uuid} == {"1:ALLOW_IT", "1:DENY_IT"}


def test_any_to_sensitive():
    db_key = C.object_key("cidr", "10.0.5.5/32")
    svc = C.service_key("tcp", 1433, 1433)
    objs = {
        db_key: NormalizedObjectRec(
            key=db_key, canonical_name="DB_SERVER", canonical_type="cidr",
            canonical_value="10.0.5.5/32", sensitivity="database",
        ),
    }
    rules = [
        _rule(1, 1, "ANY_DB", "allow", [ANY_OBJ], [db_key], [svc]),
    ]
    finds = D.detect_any_to_sensitive(_result(rules, objs))
    assert len(finds) == 1, finds
    f = finds[0]
    assert f.anomaly_type == "any_to_sensitive"
    assert f.severity == "critical"
    assert db_key in f.evidence["sensitive_destinations"]


def test_overly_permissive():
    rules = [
        _rule(1, 1, "ANY_ANY", "allow", [ANY_OBJ], [ANY_OBJ], [ANY_SVC]),
        # a constrained rule must NOT trigger
        _rule(1, 2, "TIGHT", "allow",
              [C.object_key("cidr", "10.0.0.0/24")],
              [C.object_key("cidr", "10.0.1.0/24")],
              [C.service_key("tcp", 443, 443)]),
    ]
    finds = D.detect_overly_permissive(_result(rules))
    assert len(finds) == 1, finds
    assert finds[0].rule_uuid == "1:ANY_ANY"
    assert finds[0].severity == "critical"


def test_no_cross_device_when_same_action_and_posture():
    web = C.object_key("cidr", "10.0.0.0/24")
    dst = C.object_key("cidr", "10.0.1.10/32")
    svc = C.service_key("tcp", 443, 443)
    rules = [
        _rule(1, 1, "A", "allow", [web], [dst], [svc]),
        _rule(2, 1, "B", "allow", [web], [dst], [svc]),
    ]
    res = _result(rules)
    assert D.detect_cross_device_inconsistency(res) == []
    assert D.detect_cross_device_security_posture_inconsistency(res) == []


def test_cross_device_inconsistency_fires_on_action_diff():
    web = C.object_key("cidr", "10.0.0.0/24")
    dst = C.object_key("cidr", "10.0.1.10/32")
    svc = C.service_key("tcp", 443, 443)
    rules = [
        _rule(1, 1, "A", "allow", [web], [dst], [svc]),
        _rule(2, 1, "B", "deny", [web], [dst], [svc]),
    ]
    finds = D.detect_cross_device_inconsistency(_result(rules))
    assert len(finds) == 1, finds
    assert finds[0].anomaly_type == "cross_device_inconsistency"


# ───────────────── FortiGate "ALL" service normalization (regression) ─────────────────
def test_canonical_service_all_maps_to_any():
    assert C.canonical_service("ALL", None, None, None) == ("any", None, None)
    assert C.canonical_service("all", None, None, None) == ("any", None, None)
    assert C.is_any_service("ALL") and C.is_any_service("any")
    assert C.canonical_service("ALL_TCP", None, None, None) == ("tcp", 1, 65535)
    # ordinary services pass through unchanged
    assert C.canonical_service("HTTPS", "tcp", 443, 443) == ("tcp", 443, 443)


def test_fortigate_all_service_fires_shadowing_and_redundancy():
    """The FortiGate predefined 'ALL' service carries no port range; it must normalize
    to the canonical ANY service so superset-based shadowing/redundancy fire (E-014)."""
    fgt = ParsedDevicePayload(
        device_id=1, vendor="fortinet",
        address_objects=[
            ParsedAddressObject(name="LAN_NET", type="cidr", value="10.10.10.0/24"),
            ParsedAddressObject(name="WEB2", type="cidr", value="10.10.20.20/32"),
            ParsedAddressObject(name="WEBSRV", type="cidr", value="10.10.20.10/32"),
        ],
        service_objects=[
            ParsedServiceObject(name="ALL"),  # predefined: no protocol/port range
            ParsedServiceObject(name="HTTPS", protocol="tcp", port_start=443, port_end=443),
        ],
        rules=[
            # shadowing: earlier DENY ALL ⊇ later allow HTTPS (same src/dst)
            ParsedRule(vendor="fortinet", rule_name="BLOCK_WEB2", rule_order=1, action="deny",
                       src_addrs=["LAN_NET"], dst_addrs=["WEB2"], services=["ALL"]),
            ParsedRule(vendor="fortinet", rule_name="SHADOWED_WEB2", rule_order=2, action="accept",
                       src_addrs=["LAN_NET"], dst_addrs=["WEB2"], services=["HTTPS"]),
            # redundancy: earlier allow ALL covers later allow HTTPS (same src/dst, same action)
            ParsedRule(vendor="fortinet", rule_name="BROAD_WEB", rule_order=3, action="accept",
                       src_addrs=["LAN_NET"], dst_addrs=["WEBSRV"], services=["ALL"]),
            ParsedRule(vendor="fortinet", rule_name="REDUNDANT_WEB", rule_order=4, action="accept",
                       src_addrs=["LAN_NET"], dst_addrs=["WEBSRV"], services=["HTTPS"]),
        ],
    )
    res = normalize_payloads([fgt])
    by_name = {r.rule_name: r.vendor_uuid for r in res.rules}
    block = next(r for r in res.rules if r.rule_name == "BLOCK_WEB2")
    assert ANY_SVC in block.service_keys, block.service_keys

    shad = D.detect_shadowing(res)
    assert any(f.rule_uuid == by_name["SHADOWED_WEB2"] for f in shad), [f.rule_uuid for f in shad]
    red = D.detect_redundancy(res)
    assert any(f.rule_uuid == by_name["REDUNDANT_WEB"] for f in red), [f.rule_uuid for f in red]


if __name__ == "__main__":
    test_fixtures_ground_truth()
    test_determinism_on_fixtures()
    test_duplicate_rules()
    test_shadowing()
    test_conflict()
    test_any_to_sensitive()
    test_overly_permissive()
    test_no_cross_device_when_same_action_and_posture()
    test_cross_device_inconsistency_fires_on_action_diff()
    test_canonical_service_all_maps_to_any()
    test_fortigate_all_service_fires_shadowing_and_redundancy()
    print("OK: all anomaly tests passed")
