"""Phase-1 benchmark dataset + design ground truth (Volume 7). LAB-ONLY DATA.

Logical rule specs for FortiGate + Palo Alto that intentionally trigger the
config-only anomaly taxonomy. `provision_benchmark.py` translates these to vendor
API payloads and pushes them to the lab firewalls (a WRITE operation done OUTSIDE
the read-only LuminaFPM platform).

`expected` lists the *intended* anomalies (design ground truth). The Phase-6
benchmark runner computes real precision/recall by comparing the deterministic
engine's findings against these. List ORDER is the rule evaluation order, which
matters for shadowing / redundancy / conflict.

All referenced objects/services use the lab baseline that already exists on both
firewalls: LAN_NET, DMZ_NET, DB_NET, WEB_SERVER(_2), DB_SERVER(_2), ADMIN_PC,
MALICIOUS_IP, all/any; services HTTP, HTTPS, SSH, MYSQL, RDP, ALL/ALL_TCP, DNS.

Logical zones: LAN | DMZ | DB | ANY  (mapped to interfaces/zones in the pusher).
"""

# ── FortiGate phase-1 rules (order = rule_order) ──
FORTIGATE_RULES = [
    dict(name="FGT_ALLOW_WEB", src_zone="LAN", dst_zone="DMZ", src=["LAN_NET"], dst=["WEB_SERVER"],
         service=["HTTPS"], action="allow", logging=True, inspection=False, schedule="always",
         description="", enabled=True,
         expected=["unprotected_allow", "missing_description"], severity="high"),
    dict(name="FGT_DUP_WEB", src_zone="LAN", dst_zone="DMZ", src=["LAN_NET"], dst=["WEB_SERVER"],
         service=["HTTPS"], action="allow", logging=True, inspection=False, schedule="always",
         description="duplicate of FGT_ALLOW_WEB", enabled=True,
         expected=["duplicate_rules", "unprotected_allow"], severity="medium"),
    dict(name="FGT_BROAD_WEB", src_zone="LAN", dst_zone="DMZ", src=["LAN_NET"], dst=["WEB_SERVER"],
         service=["ALL"], action="allow", logging=True, inspection=True, schedule="always",
         description="broad web allow", enabled=True, expected=[], severity="low"),
    dict(name="FGT_REDUNDANT_WEB", src_zone="LAN", dst_zone="DMZ", src=["LAN_NET"], dst=["WEB_SERVER"],
         service=["HTTPS"], action="allow", logging=True, inspection=True, schedule="always",
         description="redundant; covered by FGT_BROAD_WEB", enabled=True,
         expected=["redundancy"], severity="medium"),
    dict(name="FGT_BLOCK_WEB2", src_zone="LAN", dst_zone="DMZ", src=["LAN_NET"], dst=["WEB_SERVER_2"],
         service=["ALL"], action="deny", logging=True, inspection=False, schedule="always",
         description="block all to web2", enabled=True, expected=[], severity="low"),
    dict(name="FGT_SHADOWED_WEB2", src_zone="LAN", dst_zone="DMZ", src=["LAN_NET"], dst=["WEB_SERVER_2"],
         service=["HTTPS"], action="allow", logging=True, inspection=True, schedule="always",
         description="shadowed by FGT_BLOCK_WEB2", enabled=True,
         expected=["shadowing"], severity="high"),
    dict(name="FGT_ANY_DB", src_zone="ANY", dst_zone="DB", src=["all"], dst=["DB_SERVER"],
         service=["ALL"], action="allow", logging=False, inspection=False, schedule="always",
         description="", enabled=True,
         expected=["any_to_sensitive", "unprotected_allow", "missing_logging", "missing_description"],
         severity="critical"),
    dict(name="FGT_ANY_ANY", src_zone="ANY", dst_zone="ANY", src=["all"], dst=["all"],
         service=["ALL"], action="allow", logging=False, inspection=False, schedule="always",
         description="", enabled=True,
         expected=["overly_permissive", "unprotected_allow", "missing_logging", "missing_description"],
         severity="critical"),
    dict(name="FGT_WIDE_PORTS", src_zone="LAN", dst_zone="DB", src=["LAN_NET"], dst=["DB_SERVER"],
         service=["ALL_TCP"], action="allow", logging=True, inspection=True, schedule="always",
         description="wide tcp port range", enabled=True,
         expected=["wide_port_range"], severity="medium"),
    dict(name="FGT_ADMIN_DB_NOLOG", src_zone="ANY", dst_zone="DB", src=["ADMIN_PC"], dst=["DB_SERVER"],
         service=["MYSQL"], action="allow", logging=False, inspection=True, schedule="always",
         description="admin db access, logging off", enabled=True,
         expected=["missing_logging"], severity="medium"),
    dict(name="FGT_DISABLED_RISKY", src_zone="ANY", dst_zone="DB", src=["all"], dst=["DB_SERVER"],
         service=["ALL"], action="allow", logging=False, inspection=False, schedule="always",
         description="disabled but would expose DB", enabled=False,
         expected=["disabled_rule_review"], severity="low"),
    dict(name="FGT_DB_ACCESS_XDEV", src_zone="LAN", dst_zone="DB", src=["LAN_NET"], dst=["DB_SERVER"],
         service=["MYSQL"], action="allow", logging=True, inspection=True, schedule="always",
         description="cross-device pair: FGT allows, PAN denies", enabled=True,
         expected=["cross_device_inconsistency"], severity="high"),
]

# ── Palo Alto phase-1 rules (order = rule_order) ──
PALOALTO_RULES = [
    dict(name="PA_ALLOW_WEB", src_zone="LAN", dst_zone="DMZ", src=["LAN_NET"], dst=["WEB_SERVER"],
         service=["service-https"], action="allow", logging=True, inspection=False, schedule=None,
         description="", enabled=True,
         expected=["unprotected_allow", "missing_description"], severity="high"),
    dict(name="PA_DUP_WEB", src_zone="LAN", dst_zone="DMZ", src=["LAN_NET"], dst=["WEB_SERVER"],
         service=["service-https"], action="allow", logging=True, inspection=False, schedule=None,
         description="duplicate of PA_ALLOW_WEB", enabled=True,
         expected=["duplicate_rules", "unprotected_allow"], severity="medium"),
    dict(name="PA_BLOCK_WEB2", src_zone="LAN", dst_zone="DMZ", src=["LAN_NET"], dst=["WEB_SERVER_2"],
         service=["any"], action="deny", logging=True, inspection=False, schedule=None,
         description="block all to web2", enabled=True, expected=[], severity="low"),
    dict(name="PA_SHADOWED_WEB2", src_zone="LAN", dst_zone="DMZ", src=["LAN_NET"], dst=["WEB_SERVER_2"],
         service=["service-https"], action="allow", logging=True, inspection=True, schedule=None,
         description="shadowed by PA_BLOCK_WEB2", enabled=True,
         expected=["shadowing"], severity="high"),
    dict(name="PA_ANY_DB", src_zone="ANY", dst_zone="DB", src=["any"], dst=["DB_SERVER"],
         service=["any"], action="allow", logging=False, inspection=False, schedule=None,
         description="", enabled=True,
         expected=["any_to_sensitive", "unprotected_allow", "missing_logging", "missing_description"],
         severity="critical"),
    dict(name="PA_ANY_ANY", src_zone="ANY", dst_zone="ANY", src=["any"], dst=["any"],
         service=["any"], action="allow", logging=False, inspection=False, schedule=None,
         description="", enabled=True,
         expected=["overly_permissive", "unprotected_allow", "missing_logging", "missing_description"],
         severity="critical"),
    dict(name="PA_ADMIN_DB_NOLOG", src_zone="ANY", dst_zone="DB", src=["ADMIN_PC"], dst=["DB_SERVER"],
         service=["MYSQL"], action="allow", logging=False, inspection=True, schedule=None,
         description="admin db access, logging off", enabled=True,
         expected=["missing_logging"], severity="medium"),
    dict(name="PA_DB_ACCESS_XDEV", src_zone="LAN", dst_zone="DB", src=["LAN_NET"], dst=["DB_SERVER"],
         service=["MYSQL"], action="deny", logging=True, inspection=True, schedule=None,
         description="cross-device pair: PAN denies what FGT allows", enabled=True,
         expected=["cross_device_inconsistency"], severity="high"),
]

# Cross-device ground-truth pairs (by rule name) — informational for the Phase-6 runner.
CROSS_DEVICE_PAIRS = [
    {"fortinet": "FGT_DB_ACCESS_XDEV", "paloalto": "PA_DB_ACCESS_XDEV",
     "expected": "cross_device_inconsistency",
     "reason": "Same canonical LAN_NET->DB_SERVER MYSQL access; FortiGate allows, Palo Alto denies."},
]
