#!/usr/bin/env python3
"""LAB-ONLY benchmark provisioner (Volume 7 §13).

⚠️ THIS IS A WRITE TOOL AND IS NOT PART OF THE READ-ONLY LuminaFPM PLATFORM. ⚠️
It pushes the phase-1 benchmark policy set to the lab FortiGate (REST) and Palo
Alto (XML API + commit) so the deterministic anomaly engine has data to detect.
The platform's connectors remain strictly read-only; provisioning is an operator
action performed with a SEPARATE write-capable credential.

Safety:
  * Default mode is --dry-run: prints the exact payloads and writes the ground
    truth JSON, but contacts NO firewall.
  * Applying changes requires BOTH --apply and --confirm.
  * Intended for the controlled VMware lab (192.168.55.0/24) only.

Usage:
  # preview + write ground truth (no network):
  python lab/provision_benchmark.py --dry-run --out lab/benchmark_ground_truth.json

  # push to the lab firewalls:
  python lab/provision_benchmark.py --apply --confirm \
      --fgt-host 192.168.55.10 --fgt-token <WRITE_TOKEN> \
      --pan-host 192.168.55.20 --pan-key <API_KEY>
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from benchmark_dataset import (  # noqa: E402
    CROSS_DEVICE_PAIRS,
    FORTIGATE_RULES,
    MALICIOUS_IP_VALUE,
    PALOALTO_RULES,
)

# Logical zone token (used in benchmark_dataset src_zone/dst_zone) -> vendor selector.
# FortiGate now uses NAMED ZONES (created on the VM, bound to interfaces) so the topology
# surfaces named segments (LAN/DMZ/DB-TIER) instead of bare port1/2/3. Keys stay the
# uppercase logical tokens; only the VALUE is the VM-side name. 'ANY' = literal vendor 'any'.
FGT_INTF = {"LAN": "LAN", "DMZ": "DMZ", "DB": "DB-TIER", "ANY": "any"}
PAN_ZONE = {"LAN": "trust", "DMZ": "dmz", "DB": "db", "ANY": "any"}

# FortiGate zone NAME -> (member interface, "ip netmask") created idempotently before
# policies. Asset placement in the topology needs the interface to carry the segment subnet.
FGT_ZONES = {
    "LAN": ("port1", "10.10.10.1 255.255.255.0"),
    "DMZ": ("port2", "10.10.20.1 255.255.255.0"),
    "DB-TIER": ("port3", "10.10.30.1 255.255.255.0"),
}


def _fgt_sel(token: str) -> str:
    sel = FGT_INTF.get(token)
    if sel is None:
        raise KeyError(f"unknown FortiGate zone token {token!r}; expected {sorted(FGT_INTF)}")
    return sel


def _pan_sel(token: str) -> str:
    sel = PAN_ZONE.get(token)
    if sel is None:
        raise KeyError(f"unknown Palo Alto zone token {token!r}; expected {sorted(PAN_ZONE)}")
    return sel

PAN_XPATH = "/config/devices/entry/vsys/entry/rulebase/security/rules/entry[@name='{name}']"

# The lab PAN-OS has NO security profile group, so the provisioner creates one that
# references PAN-OS predefined profiles, and the inspection-ON benchmark rules use it.
PAN_PROFILE_GROUP = "lumina-inspect"
PAN_PROFILE_GROUP_XPATH = "/config/devices/entry/vsys/entry/profile-group/entry[@name='{name}']"
# References PAN-OS predefined profiles confirmed present in the lab. If a 'set'
# rejects one of these names on your PAN-OS version, trim the offending line.
PAN_PROFILE_GROUP_ELEMENT = (
    "<virus><member>default</member></virus>"
    "<spyware><member>default</member></spyware>"
    "<vulnerability><member>default</member></vulnerability>"
    "<url-filtering><member>default</member></url-filtering>"
    "<wildfire-analysis><member>default</member></wildfire-analysis>"
    "<file-blocking><member>basic file blocking</member></file-blocking>"
)


# ─────────────────────────── payload builders ───────────────────────────
def build_fgt_payload(r: dict) -> dict:
    body = {
        "name": r["name"],
        "srcintf": [{"name": _fgt_sel(r["src_zone"])}],
        "dstintf": [{"name": _fgt_sel(r["dst_zone"])}],
        "srcaddr": [{"name": o} for o in r["src"]],
        "dstaddr": [{"name": o} for o in r["dst"]],
        "action": "accept" if r["action"] == "allow" else "deny",
        "schedule": r.get("schedule") or "always",
        "service": [{"name": s} for s in r["service"]],
        "logtraffic": "all" if r["logging"] else "disable",
        "status": "enable" if r["enabled"] else "disable",
        "comments": r.get("description", ""),
        "nat": "disable",
    }
    if r["inspection"]:
        body.update({"utm-status": "enable", "av-profile": "default",
                     "ssl-ssh-profile": "certificate-inspection"})
    else:
        body["utm-status"] = "disable"
    return body


def _members(tag: str, names) -> str:
    return f"<{tag}>" + "".join(f"<member>{n}</member>" for n in names) + f"</{tag}>"


def build_pan_element(r: dict) -> str:
    parts = [
        _members("from", [_pan_sel(r["src_zone"])]),
        _members("to", [_pan_sel(r["dst_zone"])]),
        _members("source", r["src"]),
        _members("destination", r["dst"]),
        "<application><member>any</member></application>",
        _members("service", r["service"]),
        f"<action>{'allow' if r['action'] == 'allow' else 'deny'}</action>",
        f"<log-end>{'yes' if r['logging'] else 'no'}</log-end>",
    ]
    if r["inspection"]:
        parts.append(
            f"<profile-setting><group><member>{PAN_PROFILE_GROUP}</member></group></profile-setting>"
        )
    if r.get("description"):
        parts.append(f"<description>{r['description']}</description>")
    if not r["enabled"]:
        parts.append("<disabled>yes</disabled>")
    return "".join(parts)


# ─────────────────────────── apply (live) ───────────────────────────
def _ensure_fgt_zones(api_root: str, headers: dict, verify: bool) -> None:
    """Idempotently create the named zones (LAN/DMZ/DB-TIER) bound to their interfaces and
    set the member-interface subnets, BEFORE policies, so the topology surfaces named
    segments and places /32 assets by subnet containment. Skip-if-present."""
    import requests
    zone_base = f"{api_root}/system/zone"
    intf_base = f"{api_root}/system/interface"
    try:
        existing = {z["name"] for z in requests.get(
            zone_base, headers=headers, verify=verify, timeout=30).json().get("results", [])}
    except Exception as exc:  # noqa: BLE001
        print(f"  [FGT] zone list failed: {str(exc)[:100]}")
        existing = set()
    for zname, (intf, ipmask) in FGT_ZONES.items():
        # set the member interface IP/subnet (PUT — idempotent)
        requests.put(f"{intf_base}/{intf}", headers=headers, verify=verify, timeout=30,
                     data=json.dumps({"ip": ipmask, "mode": "static"}))
        if zname in existing:
            print(f"  [FGT] zone {zname} exists ({intf})")
            continue
        resp = requests.post(zone_base, headers=headers, verify=verify, timeout=30,
                             data=json.dumps({"name": zname,
                                              "interface": [{"interface-name": intf}],
                                              "intrazone": "allow"}))
        print(f"  [FGT] zone {zname} {'created' if resp.status_code < 400 else 'FAILED'} "
              f"({intf}, http {resp.status_code})")


def _ensure_fgt_objects(api_root: str, headers: dict, verify: bool) -> None:
    """Idempotently ensure the MALICIOUS_IP address object (FGT_ANY_DB references it), so a
    fresh lab does not push a rule with a dangling reference. Skip-if-present; the remaining
    referenced objects (LAN_NET/WEB_SERVER/DB_SERVER/...) are pre-existing lab baseline."""
    import requests
    addr_base = f"{api_root}/firewall/address"
    try:
        existing = {a["name"] for a in requests.get(
            addr_base, headers=headers, verify=verify, timeout=30).json().get("results", [])}
    except Exception as exc:  # noqa: BLE001
        print(f"  [FGT] address list failed: {str(exc)[:100]}")
        existing = set()
    if "MALICIOUS_IP" in existing:
        print("  [FGT] address MALICIOUS_IP exists")
        return
    resp = requests.post(addr_base, headers=headers, verify=verify, timeout=30,
                         data=json.dumps({"name": "MALICIOUS_IP",
                                          "subnet": f"{MALICIOUS_IP_VALUE} 255.255.255.255"}))
    print(f"  [FGT] address MALICIOUS_IP {'created' if resp.status_code < 400 else 'FAILED'} "
          f"(http {resp.status_code})")


def apply_fortigate(host: str, token: str, verify: bool, replace: bool, scheme: str = "https") -> None:
    import requests
    assert len(FORTIGATE_RULES) <= 10, (
        f"FortiGate (unlicensed VM) cap is 10 policies; dataset has {len(FORTIGATE_RULES)}")
    api_root = f"{scheme}://{host}/api/v2/cmdb"
    base = f"{api_root}/firewall/policy"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    _ensure_fgt_zones(api_root, headers, verify)
    _ensure_fgt_objects(api_root, headers, verify)
    existing = requests.get(base, headers=headers, verify=verify, timeout=30).json()
    by_name = {e["name"]: e["policyid"] for e in existing.get("results", [])}
    expected = {r["name"] for r in FORTIGATE_RULES}
    # delete stale policies (present on the device, absent from the new set) so the 10-cap is
    # respected and no orphan rule pollutes the benchmark (requires --replace).
    if replace:
        for name, pid in list(by_name.items()):
            if name not in expected:
                requests.delete(f"{base}/{pid}", headers=headers, verify=verify, timeout=30)
                print(f"  [FGT] deleted stale {name}")
    for r in FORTIGATE_RULES:
        name = r["name"]
        if name in by_name:
            if not replace:
                print(f"  [FGT] skip existing {name}")
                continue
            requests.delete(f"{base}/{by_name[name]}", headers=headers, verify=verify, timeout=30)
        resp = requests.post(base, headers=headers, data=json.dumps(build_fgt_payload(r)),
                             verify=verify, timeout=30)
        ok = resp.status_code < 400 and resp.json().get("status") == "success"
        print(f"  [FGT] {'created' if ok else 'FAILED'} {name} (http {resp.status_code})")


def _ensure_pan_objects(base: str, key: str, verify: bool) -> None:
    """Idempotently create the benchmark object dependencies (set = upsert) BEFORE the rules
    and the commit, so a referential-validation failure cannot silently sink the commit. The
    remaining referenced objects are pre-existing lab baseline. TCP_HIGH must be tcp 1024-65535
    (the wide_port_range case); MALICIOUS_IP must match the CTI known-bad IP."""
    import requests
    objects = [
        ("address MALICIOUS_IP",
         "/config/devices/entry/vsys/entry/address/entry[@name='MALICIOUS_IP']",
         f"<ip-netmask>{MALICIOUS_IP_VALUE}/32</ip-netmask>"),
        ("service TCP_HIGH",
         "/config/devices/entry/vsys/entry/service/entry[@name='TCP_HIGH']",
         "<protocol><tcp><port>1024-65535</port></tcp></protocol>"),
    ]
    for label, xpath, element in objects:
        resp = requests.get(base, params={"type": "config", "action": "set", "key": key,
                                          "xpath": xpath, "element": element},
                            headers={"X-PAN-KEY": key}, verify=verify, timeout=30)
        ok = resp.status_code < 400 and 'status="success"' in resp.text
        print(f"  [PAN] object {label} {'set' if ok else 'FAILED'} (http {resp.status_code})")


def _pan_commit(base: str, key: str, verify: bool) -> bool:
    """Issue a candidate->running commit and VERIFY it actually succeeded. PAN-OS commits are
    asynchronous and can return HTTP 200 with status="error" (referential validation) or enqueue
    a job that later FAILs — a bare status-code check would report a failed provision as success
    and the operator would believe the benchmark is live when it is not. Returns True only when
    the commit job finishes result=OK (or there was nothing to commit)."""
    import time
    import xml.etree.ElementTree as ET
    import requests
    resp = requests.get(base, params={"type": "commit", "cmd": "<commit></commit>", "key": key},
                        headers={"X-PAN-KEY": key}, verify=verify, timeout=60)
    try:
        root = ET.fromstring(resp.text)
    except ET.ParseError:
        print(f"  [PAN] commit FAILED — unparseable response (http {resp.status_code})")
        return False
    if root.get("status") != "success":
        msg = " ".join(t.strip() for t in root.itertext() if t.strip())
        print(f"  [PAN] commit FAILED (http {resp.status_code}): {msg[:200]}")
        return False
    job = root.findtext(".//job")
    if not job:
        print(f"  [PAN] commit: nothing to commit (http {resp.status_code})")
        return True
    print(f"  [PAN] commit job {job} enqueued; polling job-status ...")
    for _ in range(60):  # bounded poll, ~120s
        time.sleep(2)
        jr = requests.get(base, params={"type": "op", "key": key,
                                        "cmd": f"<show><jobs><id>{job}</id></jobs></show>"},
                          headers={"X-PAN-KEY": key}, verify=verify, timeout=30)
        try:
            jroot = ET.fromstring(jr.text)
        except ET.ParseError:
            continue
        if jroot.findtext(".//job/status") != "FIN":
            continue
        result = jroot.findtext(".//job/result")
        if result == "OK":
            print(f"  [PAN] commit job {job} OK")
            return True
        details = " | ".join(t.strip() for t in jroot.itertext() if t.strip())
        print(f"  [PAN] commit job {job} {result}: {details[:300]}")
        return False
    print(f"  [PAN] commit job {job} did not reach FIN within the poll window")
    return False


def _pan_delete_stale(base: str, key: str, verify: bool) -> None:
    """Under --replace, delete security rules present on the device but absent from the new set, so
    a re-provision does not leave OLD benchmark rules polluting the result (mirrors the FortiGate
    stale-policy cleanup). Only custom rules in vsys rulebase/security/rules are touched; PAN-OS
    predefined intrazone/interzone defaults live under rulebase/default-security-rules and are
    untouched. Deletes run on the candidate config and are committed by the caller."""
    import xml.etree.ElementTree as ET
    import requests
    expected = {r["name"] for r in PALOALTO_RULES}
    resp = requests.get(base, params={
        "type": "config", "action": "get", "key": key,
        "xpath": "/config/devices/entry/vsys/entry/rulebase/security/rules",
    }, headers={"X-PAN-KEY": key}, verify=verify, timeout=30)
    try:
        root = ET.fromstring(resp.text)
    except ET.ParseError:
        print("  [PAN] rule list unparseable — skipping stale cleanup")
        return
    names = [e.get("name") for e in root.findall(".//rules/entry") if e.get("name")]
    for name in names:
        if name in expected:
            continue
        d = requests.get(base, params={"type": "config", "action": "delete", "key": key,
                                       "xpath": PAN_XPATH.format(name=name)},
                         headers={"X-PAN-KEY": key}, verify=verify, timeout=30)
        ok = d.status_code < 400 and 'status="success"' in d.text
        print(f"  [PAN] {'deleted stale' if ok else 'FAILED delete'} {name} (http {d.status_code})")


def apply_paloalto(host: str, key: str, verify: bool, replace: bool = False) -> bool:
    """Push the PA rule set and commit. Returns True only if the commit is VERIFIED live."""
    import requests
    base = f"https://{host}/api/"
    # Bootstrap the benchmark object dependencies first so the rule 'set's + commit validate.
    _ensure_pan_objects(base, key, verify)
    # Remove stale benchmark rules (present on device, absent from the new set) before adding new.
    if replace:
        _pan_delete_stale(base, key, verify)
    # Create the inspection profile group next (the lab PAN-OS has none) so the
    # inspection-ON rules can reference it. Idempotent (set).
    if any(r["inspection"] for r in PALOALTO_RULES):
        resp = requests.get(base, params={
            "type": "config", "action": "set", "key": key,
            "xpath": PAN_PROFILE_GROUP_XPATH.format(name=PAN_PROFILE_GROUP),
            "element": PAN_PROFILE_GROUP_ELEMENT,
        }, headers={"X-PAN-KEY": key}, verify=verify, timeout=30)
        ok = resp.status_code < 400 and 'status="success"' in resp.text
        print(f"  [PAN] profile-group {PAN_PROFILE_GROUP} {'created' if ok else 'FAILED'} "
              f"(http {resp.status_code})")
    for r in PALOALTO_RULES:
        params = {"type": "config", "action": "set", "key": key,
                  "xpath": PAN_XPATH.format(name=r["name"]), "element": build_pan_element(r)}
        resp = requests.get(base, params=params, headers={"X-PAN-KEY": key}, verify=verify, timeout=30)
        ok = resp.status_code < 400 and 'status="success"' in resp.text
        print(f"  [PAN] {'set' if ok else 'FAILED'} {r['name']} (http {resp.status_code})")
    # Commit candidate config to running — VERIFIED (a silent commit failure would mask a
    # benchmark that never went live).
    return _pan_commit(base, key, verify)


# ─────────────────────────── ground truth ───────────────────────────
def export_ground_truth(path: str) -> int:
    cases = []
    for vendor, rules in (("fortinet", FORTIGATE_RULES), ("paloalto", PALOALTO_RULES)):
        for order, r in enumerate(rules, start=1):
            for atype in r["expected"]:
                cases.append({
                    "vendor": vendor, "rule_name": r["name"], "rule_order": order,
                    "expected_anomaly": atype, "expected_severity": r["severity"],
                    "detection_mode": "config_only",
                })
    payload = {"atomic_and_compound_cases": cases, "cross_device_pairs": CROSS_DEVICE_PAIRS}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return len(cases)


def dry_run() -> None:
    print("# Object dependencies ensured first (idempotent set/skip-if-present):")
    print(f"  [FGT] address MALICIOUS_IP = {MALICIOUS_IP_VALUE}/32")
    print(f"  [PAN] address MALICIOUS_IP = <ip-netmask>{MALICIOUS_IP_VALUE}/32</ip-netmask>")
    print("  [PAN] service TCP_HIGH = <protocol><tcp><port>1024-65535</port></tcp></protocol>")
    print("\n# FortiGate payloads (POST /api/v2/cmdb/firewall/policy):")
    for r in FORTIGATE_RULES:
        print(f"  {r['name']}: {json.dumps(build_fgt_payload(r))}")
    print("\n# Palo Alto set elements (type=config&action=set ... + commit):")
    if any(r["inspection"] for r in PALOALTO_RULES):
        print(f"  [profile-group {PAN_PROFILE_GROUP}]: {PAN_PROFILE_GROUP_ELEMENT}")
    for r in PALOALTO_RULES:
        print(f"  {r['name']}: {build_pan_element(r)}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="LAB-ONLY benchmark provisioner (read-only platform unaffected).")
    ap.add_argument("--apply", action="store_true", help="actually push to firewalls (requires --confirm)")
    ap.add_argument("--confirm", action="store_true", help="confirm write operations to the lab firewalls")
    ap.add_argument("--dry-run", action="store_true", help="preview payloads only (default)")
    ap.add_argument("--replace", action="store_true", help="replace existing FortiGate rules by name")
    ap.add_argument("--vendor", choices=["fortinet", "paloalto", "both"], default="both")
    ap.add_argument("--fgt-host", default=os.getenv("FGT_HOST", "192.168.55.10"))
    ap.add_argument("--fgt-token", default=os.getenv("FGT_WRITE_TOKEN", ""))
    ap.add_argument("--fgt-scheme", choices=["https", "http"], default=os.getenv("FGT_SCHEME", "https"),
                    help="LAB-ONLY: use http when the FortiGate's HTTPS admin service is unavailable")
    ap.add_argument("--pan-host", default=os.getenv("PAN_HOST", "192.168.55.20"))
    ap.add_argument("--pan-key", default=os.getenv("PAN_API_KEY", ""))
    ap.add_argument("--verify-tls", action="store_true", help="verify TLS (lab certs are self-signed)")
    ap.add_argument("--out", default="lab/benchmark_ground_truth.json", help="ground-truth JSON output path")
    args = ap.parse_args(argv)

    n = export_ground_truth(args.out)
    print(f"Ground truth written: {args.out} ({n} expected-anomaly cases, "
          f"{len(CROSS_DEVICE_PAIRS)} cross-device pairs)\n")

    if not args.apply:
        dry_run()
        print("\n(dry-run — no firewall was contacted. Use --apply --confirm to push.)")
        return 0

    if not args.confirm:
        print("ERROR: --apply requires --confirm (this writes to the lab firewalls).", file=sys.stderr)
        return 2

    verify = args.verify_tls
    pan_ok = True
    if args.vendor in ("fortinet", "both"):
        if not args.fgt_token:
            print("ERROR: FortiGate write token required (--fgt-token / FGT_WRITE_TOKEN).", file=sys.stderr)
            return 2
        print(f"Pushing FortiGate rules to {args.fgt_host} ({args.fgt_scheme}) ...")
        apply_fortigate(args.fgt_host, args.fgt_token, verify, args.replace, args.fgt_scheme)
    if args.vendor in ("paloalto", "both"):
        if not args.pan_key:
            print("ERROR: Palo Alto API key required (--pan-key / PAN_API_KEY).", file=sys.stderr)
            return 2
        print(f"Pushing Palo Alto rules to {args.pan_host} ...")
        pan_ok = apply_paloalto(args.pan_host, args.pan_key, verify, args.replace)
    if not pan_ok:
        print("\nWARNING: the Palo Alto commit did NOT confirm success — the benchmark may not be "
              "live. Review the commit job output above (a likely cause is a missing object the "
              "rules reference) BEFORE polling LuminaFPM.", file=sys.stderr)
        return 1
    print("\nDone. Now run a LuminaFPM poll on each device, then POST /api/v1/anomalies/run (all-scope).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
