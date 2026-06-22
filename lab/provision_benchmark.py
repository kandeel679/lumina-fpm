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
    PALOALTO_RULES,
)

# Logical zone -> vendor selector (override here if your lab differs).
FGT_INTF = {"LAN": "port1", "DMZ": "port2", "DB": "port3", "ANY": "any"}
PAN_ZONE = {"LAN": "trust", "DMZ": "dmz", "DB": "db", "ANY": "any"}

PAN_XPATH = "/config/devices/entry/vsys/entry/rulebase/security/rules/entry[@name='{name}']"


# ─────────────────────────── payload builders ───────────────────────────
def build_fgt_payload(r: dict) -> dict:
    body = {
        "name": r["name"],
        "srcintf": [{"name": FGT_INTF[r["src_zone"]]}],
        "dstintf": [{"name": FGT_INTF[r["dst_zone"]]}],
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
        _members("from", [PAN_ZONE[r["src_zone"]]]),
        _members("to", [PAN_ZONE[r["dst_zone"]]]),
        _members("source", r["src"]),
        _members("destination", r["dst"]),
        "<application><member>any</member></application>",
        _members("service", r["service"]),
        f"<action>{'allow' if r['action'] == 'allow' else 'deny'}</action>",
        f"<log-end>{'yes' if r['logging'] else 'no'}</log-end>",
    ]
    if r["inspection"]:
        parts.append("<profile-setting><group><member>default</member></group></profile-setting>")
    if r.get("description"):
        parts.append(f"<description>{r['description']}</description>")
    if not r["enabled"]:
        parts.append("<disabled>yes</disabled>")
    return "".join(parts)


# ─────────────────────────── apply (live) ───────────────────────────
def apply_fortigate(host: str, token: str, verify: bool, replace: bool) -> None:
    import requests
    base = f"https://{host}/api/v2/cmdb/firewall/policy"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    existing = requests.get(base, headers=headers, verify=verify, timeout=30).json()
    by_name = {e["name"]: e["policyid"] for e in existing.get("results", [])}
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


def apply_paloalto(host: str, key: str, verify: bool) -> None:
    import requests
    base = f"https://{host}/api/"
    for r in PALOALTO_RULES:
        params = {"type": "config", "action": "set", "key": key,
                  "xpath": PAN_XPATH.format(name=r["name"]), "element": build_pan_element(r)}
        resp = requests.get(base, params=params, headers={"X-PAN-KEY": key}, verify=verify, timeout=30)
        ok = resp.status_code < 400 and 'status="success"' in resp.text
        print(f"  [PAN] {'set' if ok else 'FAILED'} {r['name']} (http {resp.status_code})")
    # Commit candidate config to running.
    resp = requests.get(base, params={"type": "commit", "cmd": "<commit></commit>", "key": key},
                        headers={"X-PAN-KEY": key}, verify=verify, timeout=60)
    print(f"  [PAN] commit issued (http {resp.status_code})")


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
    print("# FortiGate payloads (POST /api/v2/cmdb/firewall/policy):")
    for r in FORTIGATE_RULES:
        print(f"  {r['name']}: {json.dumps(build_fgt_payload(r))}")
    print("\n# Palo Alto set elements (type=config&action=set ... + commit):")
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
    if args.vendor in ("fortinet", "both"):
        if not args.fgt_token:
            print("ERROR: FortiGate write token required (--fgt-token / FGT_WRITE_TOKEN).", file=sys.stderr)
            return 2
        print(f"Pushing FortiGate rules to {args.fgt_host} ...")
        apply_fortigate(args.fgt_host, args.fgt_token, verify, args.replace)
    if args.vendor in ("paloalto", "both"):
        if not args.pan_key:
            print("ERROR: Palo Alto API key required (--pan-key / PAN_API_KEY).", file=sys.stderr)
            return 2
        print(f"Pushing Palo Alto rules to {args.pan_host} ...")
        apply_paloalto(args.pan_host, args.pan_key, verify)
    print("\nDone. Now run a LuminaFPM poll on each device, then POST /api/v1/anomalies/run (all-scope).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
