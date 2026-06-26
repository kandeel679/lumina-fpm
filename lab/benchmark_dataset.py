"""Phase-1 benchmark dataset + design ground truth (Volume 7). LAB-ONLY DATA.

Logical rule specs for FortiGate + Palo Alto that intentionally trigger the
config-only anomaly taxonomy. `provision_benchmark.py` translates these to vendor
API payloads and pushes them to the lab firewalls (a WRITE operation done OUTSIDE
the read-only LuminaFPM platform).

`expected` lists the *intended* anomalies (design ground truth). The Phase-6
benchmark runner computes real precision/recall by comparing the deterministic
engine's findings against these. List ORDER is the rule evaluation order, which
matters for shadowing / redundancy / conflict (findings attach to the LATER rule).

This set is engine-validated: every `expected` entry maps to a real detector
trigger and every incidental pairwise finding (redundancy/duplicate/shadowing/
conflict from canonical set overlap) is enumerated. CLEAN rules emit ZERO findings.

Sizing (matches the unlicensed-VM lab):
  * FortiGate: EXACTLY 10 rules (unlicensed-VM hard policy cap). Densely covers all
    FG-provisionable config-detectable types; `disabled_rule_review` lives on Palo
    Alto (no cap) instead, since the FG slate is full.
  * Palo Alto: 16 rules — a realistic mix of single-anomaly, compound (mixed), and
    clean production rules, plus the disabled-review rule and the dedicated CTI
    malicious-egress rule.

CTI (separate `cti` detection mode — EXCLUDED from this config benchmark):
  * FortiGate references MALICIOUS_IP by adding it to FGT_ANY_DB's destination. That
    rule ALREADY trips any_to_sensitive (src=any -> sensitive DB_SERVER), so the extra
    sensitive destination adds NO new config finding — validated. The CTI runner still
    raises threat_exposure because FGT_ANY_DB is an ALLOW rule referencing the object.
  * Palo Alto uses a dedicated PA_ALLOW_MALICIOUS rule kept config-clean
    (inspected + logged + described + narrow src/svc) so it adds ZERO config cases and
    only trips the CTI runner.

All referenced objects/services use the lab baseline that already exists on both
firewalls: LAN_NET, DMZ_NET, DB_NET, WEB_SERVER(_2), DB_SERVER, ADMIN_PC,
MALICIOUS_IP, all/any; services HTTP, HTTPS, SSH, MYSQL, RDP, DNS, ALL/ALL_TCP,
and the custom TCP_HIGH (tcp 1024-65535) for a Palo Alto wide-port case.

Canonical sensitivity is inferred from object NAME (canonical.infer_sensitivity):
  DB*/SQL -> database, ADMIN/MGMT -> admin, MALICIOUS/THREAT/BAD -> critical. So both
  any->DB_SERVER and any->MALICIOUS_IP trip any_to_sensitive (only when src is ANY).

Logical zones: LAN | DMZ | DB | ANY  (mapped to interfaces/zones in the pusher).
Zones are DETECTION-NEUTRAL — no detector reads src_zone/dst_zone; they only shape
the lab topology.
"""

# Benchmark object dependencies the provisioner self-bootstraps (idempotent). MALICIOUS_IP
# MUST resolve to the known-bad IP the CTI axis matches (backend/data/cti_indicators.json);
# if these drift, the CTI threat_exposure on FGT_ANY_DB / PA_ALLOW_MALICIOUS silently stops.
MALICIOUS_IP_VALUE = "185.220.101.1"

# ── FortiGate phase-1 rules (order = rule_order) — EXACTLY 10 (unlicensed-VM cap) ──
FORTIGATE_RULES = [
    dict(name="FGT_ALLOW_WEB", src_zone="LAN", dst_zone="DMZ", src=["LAN_NET"], dst=["WEB_SERVER"],
         service=["HTTPS"], action="allow", logging=True, inspection=False, schedule="always",
         description="", enabled=True,
         expected=["unprotected_allow", "missing_description"], severity="high"),
    dict(name="FGT_DUP_WEB", src_zone="LAN", dst_zone="DMZ", src=["LAN_NET"], dst=["WEB_SERVER"],
         service=["HTTPS"], action="allow", logging=True, inspection=False, schedule="always",
         description="duplicate of FGT_ALLOW_WEB", enabled=True,
         expected=["unprotected_allow", "duplicate_rules"], severity="medium"),
    dict(name="FGT_REDUNDANT_WEB", src_zone="LAN", dst_zone="DMZ", src=["LAN_NET"], dst=["WEB_SERVER"],
         service=["HTTPS"], action="allow", logging=True, inspection=True, schedule="always",
         description="inspected web allow (cross-device posture peer)", enabled=True,
         # exact LAN->WEB HTTPS allow like FGT_ALLOW_WEB/FGT_DUP_WEB -> duplicate_rules
         # (exact duplicates are excluded from redundancy by design). Inspected, so it is
         # the FortiGate side of the cross-device posture pair vs the unprotected PA web allows.
         expected=["duplicate_rules"], severity="medium"),
    dict(name="FGT_BLOCK_WEB2", src_zone="LAN", dst_zone="DMZ", src=["LAN_NET"], dst=["WEB_SERVER_2"],
         service=["ALL"], action="deny", logging=True, inspection=False, schedule="always",
         description="block all to web2", enabled=True, expected=[], severity="low"),
    dict(name="FGT_SHADOWED_WEB2", src_zone="LAN", dst_zone="DMZ", src=["LAN_NET"], dst=["WEB_SERVER_2"],
         service=["HTTPS"], action="allow", logging=True, inspection=True, schedule="always",
         description="shadowed by FGT_BLOCK_WEB2", enabled=True,
         # earlier FGT_BLOCK_WEB2 (deny, ALL) is a superset -> shadowing; opposite action -> conflict
         expected=["shadowing", "conflict"], severity="high"),
    dict(name="FGT_ANY_DB", src_zone="ANY", dst_zone="DB", src=["all"], dst=["DB_SERVER", "MALICIOUS_IP"],
         service=["ALL"], action="allow", logging=False, inspection=False, schedule="always",
         description="", enabled=True,
         # CTI: dst carries MALICIOUS_IP alongside DB_SERVER. The rule already trips
         # any_to_sensitive via DB_SERVER, so the known-bad object adds NO new config
         # finding (validated) — it only feeds the separate CTI threat_exposure runner.
         expected=["any_to_sensitive", "unprotected_allow", "missing_logging", "missing_description"],
         severity="critical"),
    dict(name="FGT_ANY_ANY", src_zone="ANY", dst_zone="ANY", src=["all"], dst=["all"],
         service=["ALL"], action="allow", logging=False, inspection=False, schedule="always",
         description="", enabled=True,
         # any/any/any allow -> overly_permissive; overlaps earlier FGT_BLOCK_WEB2 (deny) -> conflict
         expected=["overly_permissive", "unprotected_allow", "missing_logging", "missing_description",
                   "conflict"],
         severity="critical"),
    dict(name="FGT_WIDE_PORTS", src_zone="LAN", dst_zone="DB", src=["LAN_NET"], dst=["DB_SERVER"],
         service=["ALL_TCP"], action="allow", logging=True, inspection=True, schedule="always",
         description="wide tcp port range", enabled=True,
         # tcp 1-65535 span > 1024 -> wide_port_range; match set covered by earlier
         # any->DB / any->any allows -> redundancy
         expected=["wide_port_range", "redundancy"], severity="medium"),
    dict(name="FGT_ADMIN_DB_NOLOG", src_zone="ANY", dst_zone="DB", src=["ADMIN_PC"], dst=["DB_SERVER"],
         service=["MYSQL"], action="allow", logging=False, inspection=True, schedule="always",
         description="admin db access, logging off", enabled=True,
         # logging off -> missing_logging; ADMIN_PC->DB_SERVER MYSQL covered by earlier
         # any->DB / any->any allows -> redundancy
         expected=["missing_logging", "redundancy"], severity="medium"),
    dict(name="FGT_DB_ACCESS_XDEV", src_zone="LAN", dst_zone="DB", src=["LAN_NET"], dst=["DB_SERVER"],
         service=["MYSQL"], action="allow", logging=True, inspection=True, schedule="always",
         description="cross-device pair: FGT allows, PAN denies", enabled=True,
         # cross_device_inconsistency is scored as a PAIR (see CROSS_DEVICE_PAIRS); per-rule this
         # allow is covered by the earlier any->DB / any->any allows -> redundancy
         expected=["redundancy"], severity="high"),
]

# ── Palo Alto phase-1 rules (order = rule_order) — 16 rules ──
# Narrow/specific + clean rules come FIRST so the broad any-allows (placed LAST) do
# not pre-cover them with redundancy. The broad any-allows are the compound cases.
PALOALTO_RULES = [
    dict(name="PA_ALLOW_WEB", src_zone="LAN", dst_zone="DMZ", src=["LAN_NET"], dst=["WEB_SERVER"],
         service=["service-https"], action="allow", logging=True, inspection=False, schedule=None,
         description="", enabled=True,
         expected=["unprotected_allow", "missing_description"], severity="high"),
    dict(name="PA_DUP_WEB", src_zone="LAN", dst_zone="DMZ", src=["LAN_NET"], dst=["WEB_SERVER"],
         service=["service-https"], action="allow", logging=True, inspection=False, schedule=None,
         description="duplicate of PA_ALLOW_WEB", enabled=True,
         expected=["unprotected_allow", "duplicate_rules"], severity="medium"),
    dict(name="PA_BLOCK_WEB2", src_zone="LAN", dst_zone="DMZ", src=["LAN_NET"], dst=["WEB_SERVER_2"],
         service=["any"], action="deny", logging=True, inspection=False, schedule=None,
         description="block all to web2", enabled=True, expected=[], severity="low"),
    dict(name="PA_SHADOWED_WEB2", src_zone="LAN", dst_zone="DMZ", src=["LAN_NET"], dst=["WEB_SERVER_2"],
         service=["service-https"], action="allow", logging=True, inspection=True, schedule=None,
         description="shadowed by PA_BLOCK_WEB2", enabled=True,
         # earlier PA_BLOCK_WEB2 (deny, any) is a superset -> shadowing; opposite action -> conflict
         expected=["shadowing", "conflict"], severity="high"),
    dict(name="PA_WIDE_PORTS", src_zone="LAN", dst_zone="DB", src=["LAN_NET"], dst=["DB_SERVER"],
         service=["TCP_HIGH"], action="allow", logging=True, inspection=True, schedule=None,
         description="ephemeral high-port range to db", enabled=True,
         # custom TCP_HIGH = tcp 1024-65535, span > 1024 -> wide_port_range. No earlier
         # broad allow precedes it (any-allows are later) so it is NOT redundant. SINGLE.
         expected=["wide_port_range"], severity="medium"),
    dict(name="PA_DB_ACCESS_XDEV", src_zone="LAN", dst_zone="DB", src=["LAN_NET"], dst=["DB_SERVER"],
         service=["MYSQL"], action="deny", logging=True, inspection=True, schedule=None,
         description="cross-device pair: PAN denies what FGT allows", enabled=True,
         # intra-clean (no earlier opposite-action allow overlaps this exact MYSQL set);
         # the cross_device_inconsistency vs FGT_DB_ACCESS_XDEV is scored as a PAIR.
         expected=[], severity="high"),
    dict(name="PA_ALLOW_MALICIOUS", src_zone="ANY", dst_zone="ANY", src=["ADMIN_PC"], dst=["MALICIOUS_IP"],
         service=["service-https"], action="allow", logging=True, inspection=True, schedule=None,
         description="CTI demo: monitored egress to a known-bad indicator", enabled=True,
         # CONFIG-CLEAN by construction: inspected + logged + described + narrow src(ADMIN_PC)/
         # svc(https), and src is NOT any so any_to_sensitive does not fire. Adds ZERO config
         # cases; only the separate CTI runner raises threat_exposure (allow -> MALICIOUS_IP).
         expected=[], severity="low"),
    # ── CLEAN production rules (mimic a real environment) — emit ZERO findings ──
    dict(name="PA_CLEAN_DNS", src_zone="LAN", dst_zone="DB", src=["LAN_NET"], dst=["DB_NET"],
         service=["DNS"], action="allow", logging=True, inspection=True, schedule=None,
         description="LAN clients resolve DNS at infra subnet", enabled=True,
         expected=[], severity="low"),
    dict(name="PA_CLEAN_WEB2_HTTP", src_zone="DMZ", dst_zone="DMZ", src=["DMZ_NET"], dst=["WEB_SERVER_2"],
         service=["service-http"], action="allow", logging=True, inspection=True, schedule=None,
         description="DMZ hosts to web2 over http", enabled=True,
         expected=[], severity="low"),
    dict(name="PA_CLEAN_SSH_ADMIN", src_zone="ANY", dst_zone="DMZ", src=["ADMIN_PC"], dst=["DMZ_NET"],
         service=["SSH"], action="allow", logging=True, inspection=True, schedule=None,
         description="admin workstation ssh to dmz hosts", enabled=True,
         expected=[], severity="low"),
    dict(name="PA_CLEAN_RDP_ADMIN", src_zone="ANY", dst_zone="DMZ", src=["ADMIN_PC"], dst=["WEB_SERVER"],
         service=["RDP"], action="allow", logging=True, inspection=True, schedule=None,
         description="admin workstation rdp to web1", enabled=True,
         expected=[], severity="low"),
    dict(name="PA_CLEAN_WEB_HTTP", src_zone="DMZ", dst_zone="DMZ", src=["DMZ_NET"], dst=["WEB_SERVER"],
         service=["service-http"], action="allow", logging=True, inspection=True, schedule=None,
         description="DMZ hosts to web1 over http", enabled=True,
         expected=[], severity="low"),
    # ── disabled review (PA carries this; the FortiGate slate is at the 10-policy cap) ──
    dict(name="PA_DISABLED_RISKY", src_zone="ANY", dst_zone="DB", src=["any"], dst=["DB_NET"],
         service=["any"], action="allow", logging=False, inspection=False, schedule=None,
         description="disabled but would expose the DB subnet", enabled=False,
         # disabled -> disabled_rule_review (single-rule detectors skip disabled rules, so no
         # unprotected_allow/missing_logging/etc.). dst DB_NET (subnet) differs from every
         # DB_SERVER (host) rule's key, so it does NOT overlap them -> no duplicate/conflict.
         expected=["disabled_rule_review"], severity="low"),
    # ── broad/messy any-allows LAST (compound cases) ──
    dict(name="PA_ADMIN_DB_NOLOG", src_zone="ANY", dst_zone="DB", src=["ADMIN_PC"], dst=["DB_SERVER"],
         service=["MYSQL"], action="allow", logging=False, inspection=True, schedule=None,
         description="admin db access, logging off", enabled=True,
         # logging off -> missing_logging. Placed before the any->DB / any->any allows, so it
         # is NOT redundant. SINGLE.
         expected=["missing_logging"], severity="medium"),
    dict(name="PA_ANY_DB", src_zone="ANY", dst_zone="DB", src=["any"], dst=["DB_SERVER"],
         service=["any"], action="allow", logging=False, inspection=False, schedule=None,
         description="", enabled=True,
         # any -> sensitive DB_SERVER -> any_to_sensitive; unprotected + nolog + nodesc;
         # overlaps the earlier PA_DB_ACCESS_XDEV (deny LAN->DB MYSQL) -> conflict.
         expected=["any_to_sensitive", "unprotected_allow", "missing_logging", "missing_description",
                   "conflict"],
         severity="critical"),
    dict(name="PA_ANY_ANY", src_zone="ANY", dst_zone="ANY", src=["any"], dst=["any"],
         service=["any"], action="allow", logging=False, inspection=False, schedule=None,
         description="", enabled=True,
         # any/any/any allow -> overly_permissive; overlaps the earlier PA_DB_ACCESS_XDEV
         # (deny) and PA_BLOCK_WEB2 (deny) -> conflict.
         expected=["overly_permissive", "unprotected_allow", "missing_logging", "missing_description",
                   "conflict"],
         severity="critical"),
]

# Cross-device ground-truth pairs (by rule name) — informational for the Phase-6 runner.
CROSS_DEVICE_PAIRS = [
    {"fortinet": "FGT_DB_ACCESS_XDEV", "paloalto": "PA_DB_ACCESS_XDEV",
     "expected": "cross_device_inconsistency",
     "reason": "Same canonical LAN_NET->DB_SERVER MYSQL access; FortiGate allows, Palo Alto denies."},
    # Equivalent LAN->WEB HTTPS allow on both vendors, but FGT_REDUNDANT_WEB is inspected while the
    # Palo Alto web-allow rules are unprotected -> posture inconsistency (engine attributes it to PA).
    {"fortinet": "FGT_REDUNDANT_WEB", "paloalto": "PA_ALLOW_WEB",
     "expected": "cross_device_security_posture_inconsistency",
     "reason": "Equivalent LAN_NET->WEB_SERVER HTTPS allow; FortiGate inspected, Palo Alto unprotected."},
    {"fortinet": "FGT_REDUNDANT_WEB", "paloalto": "PA_DUP_WEB",
     "expected": "cross_device_security_posture_inconsistency",
     "reason": "Equivalent LAN_NET->WEB_SERVER HTTPS allow; FortiGate inspected, Palo Alto unprotected."},
]

# ── Module-load invariant (enforced on EVERY path: dry-run, PAN-only, tests, live) ──
# FortiGate unlicensed-VM hard policy cap. Asserted at import so an over-cap edit fails
# immediately everywhere, not only on a live FortiGate push (apply_fortigate also re-asserts).
assert len(FORTIGATE_RULES) <= 10, (
    f"FortiGate (unlicensed VM) cap is 10 policies; dataset has {len(FORTIGATE_RULES)}")
