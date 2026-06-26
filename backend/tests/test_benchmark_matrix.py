"""Benchmark matrix gate (Volume 7) — runs the REAL anomaly engine over the enriched
26-rule lab matrix and asserts the emitted findings match ground_truth.py EXACTLY
(0 false positives / 0 false negatives / 0 severity mismatches).

This is the OFFLINE acceptance gate for the lab enrichment: it proves the dataset +
ground_truth are engine-coherent BEFORE anything is provisioned to a firewall, and
guards against drift if the engine or ground_truth changes.

The rule specs below mirror lab/benchmark_dataset.py (lab/ is not mounted into the API
container, so they are inlined here). The EXPECTED matrix is imported from the real
backend ground_truth.py. Run inside the api container:
    docker compose exec -T api python tests/test_benchmark_matrix.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.normalization import canonical as C
from services.normalization.model import (
    NormalizationResult,
    NormalizedObjectRec,
    NormalizedRule,
    NormalizedServiceRec,
)
from services.anomaly.engine import analyze
from services.benchmark.ground_truth import CROSS_DEVICE, EXPECTED_SEVERITY, INTRA

# ── lab baseline: logical name -> canonical (type, value) / (proto, start, end) ──
ANY_OBJ = ("any", "0.0.0.0/0")
OBJECTS = {
    "LAN_NET": ("cidr", "10.10.10.0/24"), "DMZ_NET": ("cidr", "10.10.20.0/24"),
    "DB_NET": ("cidr", "10.10.30.0/24"), "WEB_SERVER": ("ip", "10.10.20.10"),
    "WEB_SERVER_2": ("ip", "10.10.20.11"), "DB_SERVER": ("ip", "10.10.30.10"),
    "ADMIN_PC": ("ip", "10.10.10.50"), "MALICIOUS_IP": ("ip", "185.220.101.1"),
    "all": ANY_OBJ, "any": ANY_OBJ,
}
SERVICES = {
    "HTTP": ("tcp", 80, 80), "service-http": ("tcp", 80, 80),
    "HTTPS": ("tcp", 443, 443), "service-https": ("tcp", 443, 443),
    "SSH": ("tcp", 22, 22), "MYSQL": ("tcp", 3306, 3306), "RDP": ("tcp", 3389, 3389),
    "DNS": ("udp", 53, 53), "ALL": ("any", None, None), "any": ("any", None, None),
    "ALL_TCP": ("tcp", 1, 65535), "TCP_HIGH": ("tcp", 1024, 65535),
}

# Inlined rule specs — MIRROR lab/benchmark_dataset.py (FORTIGATE_RULES / PALOALTO_RULES).
FORTIGATE_RULES = [
    dict(name="FGT_ALLOW_WEB", src=["LAN_NET"], dst=["WEB_SERVER"], service=["HTTPS"], action="allow", logging=True, inspection=False, description="", enabled=True),
    dict(name="FGT_DUP_WEB", src=["LAN_NET"], dst=["WEB_SERVER"], service=["HTTPS"], action="allow", logging=True, inspection=False, description="duplicate of FGT_ALLOW_WEB", enabled=True),
    dict(name="FGT_REDUNDANT_WEB", src=["LAN_NET"], dst=["WEB_SERVER"], service=["HTTPS"], action="allow", logging=True, inspection=True, description="inspected web allow", enabled=True),
    dict(name="FGT_BLOCK_WEB2", src=["LAN_NET"], dst=["WEB_SERVER_2"], service=["ALL"], action="deny", logging=True, inspection=False, description="block all to web2", enabled=True),
    dict(name="FGT_SHADOWED_WEB2", src=["LAN_NET"], dst=["WEB_SERVER_2"], service=["HTTPS"], action="allow", logging=True, inspection=True, description="shadowed by FGT_BLOCK_WEB2", enabled=True),
    dict(name="FGT_ANY_DB", src=["all"], dst=["DB_SERVER", "MALICIOUS_IP"], service=["ALL"], action="allow", logging=False, inspection=False, description="", enabled=True),
    dict(name="FGT_ANY_ANY", src=["all"], dst=["all"], service=["ALL"], action="allow", logging=False, inspection=False, description="", enabled=True),
    dict(name="FGT_WIDE_PORTS", src=["LAN_NET"], dst=["DB_SERVER"], service=["ALL_TCP"], action="allow", logging=True, inspection=True, description="wide tcp port range", enabled=True),
    dict(name="FGT_ADMIN_DB_NOLOG", src=["ADMIN_PC"], dst=["DB_SERVER"], service=["MYSQL"], action="allow", logging=False, inspection=True, description="admin db access, logging off", enabled=True),
    dict(name="FGT_DB_ACCESS_XDEV", src=["LAN_NET"], dst=["DB_SERVER"], service=["MYSQL"], action="allow", logging=True, inspection=True, description="cross-device pair", enabled=True),
]
PALOALTO_RULES = [
    dict(name="PA_ALLOW_WEB", src=["LAN_NET"], dst=["WEB_SERVER"], service=["service-https"], action="allow", logging=True, inspection=False, description="", enabled=True),
    dict(name="PA_DUP_WEB", src=["LAN_NET"], dst=["WEB_SERVER"], service=["service-https"], action="allow", logging=True, inspection=False, description="duplicate of PA_ALLOW_WEB", enabled=True),
    dict(name="PA_BLOCK_WEB2", src=["LAN_NET"], dst=["WEB_SERVER_2"], service=["any"], action="deny", logging=True, inspection=False, description="block all to web2", enabled=True),
    dict(name="PA_SHADOWED_WEB2", src=["LAN_NET"], dst=["WEB_SERVER_2"], service=["service-https"], action="allow", logging=True, inspection=True, description="shadowed by PA_BLOCK_WEB2", enabled=True),
    dict(name="PA_WIDE_PORTS", src=["LAN_NET"], dst=["DB_SERVER"], service=["TCP_HIGH"], action="allow", logging=True, inspection=True, description="ephemeral high-port range to db", enabled=True),
    dict(name="PA_DB_ACCESS_XDEV", src=["LAN_NET"], dst=["DB_SERVER"], service=["MYSQL"], action="deny", logging=True, inspection=True, description="cross-device pair", enabled=True),
    dict(name="PA_ALLOW_MALICIOUS", src=["ADMIN_PC"], dst=["MALICIOUS_IP"], service=["service-https"], action="allow", logging=True, inspection=True, description="CTI demo: monitored egress", enabled=True),
    dict(name="PA_CLEAN_DNS", src=["LAN_NET"], dst=["DB_NET"], service=["DNS"], action="allow", logging=True, inspection=True, description="LAN clients resolve DNS", enabled=True),
    dict(name="PA_CLEAN_WEB2_HTTP", src=["DMZ_NET"], dst=["WEB_SERVER_2"], service=["service-http"], action="allow", logging=True, inspection=True, description="DMZ hosts to web2 http", enabled=True),
    dict(name="PA_CLEAN_SSH_ADMIN", src=["ADMIN_PC"], dst=["DMZ_NET"], service=["SSH"], action="allow", logging=True, inspection=True, description="admin ssh to dmz", enabled=True),
    dict(name="PA_CLEAN_RDP_ADMIN", src=["ADMIN_PC"], dst=["WEB_SERVER"], service=["RDP"], action="allow", logging=True, inspection=True, description="admin rdp to web1", enabled=True),
    dict(name="PA_CLEAN_WEB_HTTP", src=["DMZ_NET"], dst=["WEB_SERVER"], service=["service-http"], action="allow", logging=True, inspection=True, description="DMZ hosts to web1 http", enabled=True),
    dict(name="PA_DISABLED_RISKY", src=["any"], dst=["DB_NET"], service=["any"], action="allow", logging=False, inspection=False, description="disabled but would expose DB", enabled=False),
    dict(name="PA_ADMIN_DB_NOLOG", src=["ADMIN_PC"], dst=["DB_SERVER"], service=["MYSQL"], action="allow", logging=False, inspection=True, description="admin db access, logging off", enabled=True),
    dict(name="PA_ANY_DB", src=["any"], dst=["DB_SERVER"], service=["any"], action="allow", logging=False, inspection=False, description="", enabled=True),
    dict(name="PA_ANY_ANY", src=["any"], dst=["any"], service=["any"], action="allow", logging=False, inspection=False, description="", enabled=True),
]

CROSS_TYPES = {"cross_device_inconsistency", "cross_device_security_posture_inconsistency"}


def _build_objects():
    out = {}
    for name, (ct, cv) in OBJECTS.items():
        k = C.object_key(ct, cv)
        out[k] = NormalizedObjectRec(key=k, canonical_name=name, canonical_type=ct,
                                     canonical_value=cv, sensitivity=C.infer_sensitivity(name, cv))
    return out


def _build_services():
    out = {}
    for name, (proto, ps, pe) in SERVICES.items():
        k = C.service_key(proto, ps, pe)
        out[k] = NormalizedServiceRec(key=k, canonical_name=name, protocol=proto,
                                      port_start=ps, port_end=pe, app_id=None)
    return out


def _make_rule(device_id, vendor, order, spec):
    insp = "true" if spec["inspection"] else "false"
    return NormalizedRule(
        device_id=device_id, vendor=vendor, rule_name=spec["name"], rule_order=order,
        vendor_rule_id=str(order), vendor_uuid=f"{vendor}-{spec['name']}", vdom_vsys=None,
        enabled=spec["enabled"], src_zone="any", dst_zone="any",
        action="allow" if spec["action"] == "allow" else "deny",
        logging_enabled="true" if spec["logging"] else "false",
        security_inspection_enabled=insp, security_profile_group=None,
        security_profile_strength="strong" if insp == "true" else "missing",
        schedule=None, schedule_scope="always", nat_enabled=None,
        description=spec.get("description") or "", src_negate=False, dst_negate=False,
        src_object_keys=[C.object_key(*OBJECTS[o]) for o in spec["src"]],
        dst_object_keys=[C.object_key(*OBJECTS[o]) for o in spec["dst"]],
        service_keys=[C.service_key(*SERVICES[s]) for s in spec["service"]],
    )


def _run_engine():
    rules = ([_make_rule(1, "fortinet", i, s) for i, s in enumerate(FORTIGATE_RULES, 1)]
             + [_make_rule(2, "paloalto", i, s) for i, s in enumerate(PALOALTO_RULES, 1)])
    result = NormalizationResult(normalized_objects=_build_objects(),
                                 normalized_services=_build_services(), rules=rules)
    findings = analyze(result)
    by_uuid = {r.vendor_uuid: r.rule_name for r in rules}
    return findings, by_uuid


def _diff():
    findings, by_uuid = _run_engine()
    emitted, emitted_sev, cross_emitted = set(), {}, {}
    for f in findings:
        name = by_uuid.get(f.rule_uuid, f.rule_uuid)
        if f.anomaly_type in CROSS_TYPES:
            rel = by_uuid.get(f.related_rule_uuid, f.related_rule_uuid)
            cross_emitted.setdefault(f.anomaly_type, set()).update({name, rel})
            cross_emitted.setdefault(f.anomaly_type + "_sev", {})[frozenset({name, rel})] = f.severity
        else:
            emitted.add((name, f.anomaly_type))
            emitted_sev[(name, f.anomaly_type)] = f.severity

    expected, expected_sev = set(), {}
    for rulemap in INTRA.values():
        for rname, types in rulemap.items():
            for t in types:
                expected.add((rname, t))
                expected_sev[(rname, t)] = EXPECTED_SEVERITY[t]

    fp = sorted(f"{n}/{t}" for (n, t) in emitted - expected)
    fn = sorted(f"{n}/{t}" for (n, t) in expected - emitted)
    sev = [f"{n}/{t}: exp {expected_sev[(n, t)]} got {emitted_sev[(n, t)]}"
           for (n, t) in (emitted & expected) if emitted_sev[(n, t)] != expected_sev[(n, t)]]

    # cross-device: a pair matches if the type appears on EITHER paired rule
    cross_fn, cross_fp = [], []
    gt_pairs = {(frozenset({p["a"], p["b"]}), p["anomaly_type"]) for p in CROSS_DEVICE}
    for p in CROSS_DEVICE:
        got = cross_emitted.get(p["anomaly_type"], set())
        if {p["a"], p["b"]} & got:
            s = cross_emitted.get(p["anomaly_type"] + "_sev", {}).get(frozenset({p["a"], p["b"]}))
            if s and s != EXPECTED_SEVERITY[p["anomaly_type"]]:
                sev.append(f"{p['a']}<->{p['b']}/{p['anomaly_type']}: exp {EXPECTED_SEVERITY[p['anomaly_type']]} got {s}")
        else:
            cross_fn.append(f"{p['a']}<->{p['b']}/{p['anomaly_type']}")
    for f in findings:
        if f.anomaly_type in CROSS_TYPES:
            n, rel = by_uuid.get(f.rule_uuid), by_uuid.get(f.related_rule_uuid)
            if (frozenset({n, rel}), f.anomaly_type) not in gt_pairs:
                cross_fp.append(f"{n}<->{rel}/{f.anomaly_type}")
    return fp + sorted(set(cross_fp)), fn + sorted(set(cross_fn)), sev, len(expected) + len(CROSS_DEVICE)


def test_benchmark_matrix_is_engine_coherent():
    fp, fn, sev, total = _diff()
    assert not fp, f"false positives: {fp}"
    assert not fn, f"false negatives: {fn}"
    assert not sev, f"severity mismatches: {sev}"
    assert total == 43, f"expected 43 cases (40 intra + 3 cross), got {total}"


if __name__ == "__main__":
    fp, fn, sev, total = _diff()
    print(f"expected cases: {total} | FP: {len(fp)} | FN: {len(fn)} | sev-mismatch: {len(sev)}")
    for x in fp:
        print("  +FP", x)
    for x in fn:
        print("  -FN", x)
    for x in sev:
        print("  !SEV", x)
    test_benchmark_matrix_is_engine_coherent()
    print("OK: benchmark matrix is engine-coherent (0 FP / 0 FN / 0 severity mismatch)")
