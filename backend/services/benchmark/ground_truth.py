"""Phase-1 benchmark ground truth (Volume 7) — the `benchmark_case` seed.

This is the authoritative expected-anomaly matrix the engine is scored against.
It mirrors the *design intent* in `lab/benchmark_dataset.py` (`expected` lists +
CROSS_DEVICE_PAIRS); kept in the backend so the runner is self-contained (lab/ is
not mounted into the API container). Each expected anomaly is derived from the
rule's configuration + the detector definitions, NOT from engine output.

This matrix is engine-validated and kept in LOCKSTEP with lab/benchmark_dataset.py:
EXACTLY 10 FortiGate rules (unlicensed-VM policy cap) + 16 Palo Alto rules. Every
listed anomaly maps to a real detector trigger and every incidental pairwise finding
is enumerated, so a clean run yields zero false positives / false negatives.

CTI threat_exposure is raised by the SEPARATE cti runner (detection_mode='cti') and
is intentionally absent here — the config benchmark filters to detection_mode
'config_only'. The CTI-flaggable rules are FGT_ANY_DB (MALICIOUS_IP added to its
destination, config findings unchanged) and PA_ALLOW_MALICIOUS (config-clean).

Severity is per anomaly TYPE (V6 Table 7), independent of the engine, so the
severity-match rate is a real check on the engine's severity assignment.
"""
from __future__ import annotations

# Expected severity per anomaly type (V6 Table 7).
EXPECTED_SEVERITY = {
    "any_to_sensitive": "critical",
    "overly_permissive": "critical",
    "cross_device_inconsistency": "critical",
    "unprotected_allow": "high",
    "shadowing": "high",
    "conflict": "high",
    "redundancy": "medium",
    "duplicate_rules": "medium",
    "missing_logging": "medium",
    "wide_port_range": "medium",
    "cross_device_security_posture_inconsistency": "medium",
    "missing_description": "low",
    "disabled_rule_review": "low",
}

# Per-rule intra-device expected anomalies (config_only). Rules not deployed are
# filtered out by the runner against the live policy_rule table. Kept EXACTLY in
# lockstep with the engine output for lab/benchmark_dataset.py.
INTRA = {
    "fortinet": {
        "FGT_ALLOW_WEB": ["unprotected_allow", "missing_description"],
        "FGT_DUP_WEB": ["unprotected_allow", "duplicate_rules"],
        # exact LAN->WEB HTTPS allow -> duplicate_rules (exact dups excluded from redundancy).
        "FGT_REDUNDANT_WEB": ["duplicate_rules"],
        "FGT_BLOCK_WEB2": [],
        "FGT_SHADOWED_WEB2": ["shadowing", "conflict"],
        # CTI: dst also carries MALICIOUS_IP, but any_to_sensitive already fires via DB_SERVER,
        # so the known-bad object adds NO config finding (threat_exposure is cti-mode, separate).
        "FGT_ANY_DB": ["any_to_sensitive", "unprotected_allow", "missing_logging", "missing_description"],
        "FGT_ANY_ANY": ["overly_permissive", "unprotected_allow", "missing_logging",
                        "missing_description", "conflict"],
        "FGT_WIDE_PORTS": ["wide_port_range", "redundancy"],
        "FGT_ADMIN_DB_NOLOG": ["missing_logging", "redundancy"],
        "FGT_DB_ACCESS_XDEV": ["redundancy"],
    },
    "paloalto": {
        "PA_ALLOW_WEB": ["unprotected_allow", "missing_description"],
        "PA_DUP_WEB": ["unprotected_allow", "duplicate_rules"],
        "PA_BLOCK_WEB2": [],
        "PA_SHADOWED_WEB2": ["shadowing", "conflict"],
        "PA_WIDE_PORTS": ["wide_port_range"],
        # deny LAN->DB MYSQL; intra-clean. cross_device_inconsistency scored as a PAIR.
        "PA_DB_ACCESS_XDEV": [],
        # CTI demo rule: config-clean (inspected+logged+described+narrow, src!=any). Only the
        # separate cti runner raises threat_exposure (allow -> MALICIOUS_IP).
        "PA_ALLOW_MALICIOUS": [],
        # clean production rules — zero findings:
        "PA_CLEAN_DNS": [],
        "PA_CLEAN_WEB2_HTTP": [],
        "PA_CLEAN_SSH_ADMIN": [],
        "PA_CLEAN_RDP_ADMIN": [],
        "PA_CLEAN_WEB_HTTP": [],
        "PA_DISABLED_RISKY": ["disabled_rule_review"],
        "PA_ADMIN_DB_NOLOG": ["missing_logging"],
        "PA_ANY_DB": ["any_to_sensitive", "unprotected_allow", "missing_logging",
                      "missing_description", "conflict"],
        "PA_ANY_ANY": ["overly_permissive", "unprotected_allow", "missing_logging",
                       "missing_description", "conflict"],
    },
}

# Cross-device pairs (scored if the anomaly appears on EITHER paired rule).
CROSS_DEVICE = [
    {"a": "FGT_DB_ACCESS_XDEV", "b": "PA_DB_ACCESS_XDEV",
     "anomaly_type": "cross_device_inconsistency",
     "reason": "Same canonical LAN_NET->DB_SERVER MYSQL access; FortiGate allows, Palo Alto denies."},
    {"a": "FGT_REDUNDANT_WEB", "b": "PA_ALLOW_WEB",
     "anomaly_type": "cross_device_security_posture_inconsistency",
     "reason": "Equivalent LAN->WEB HTTPS allow; FortiGate inspected, Palo Alto unprotected."},
    {"a": "FGT_REDUNDANT_WEB", "b": "PA_DUP_WEB",
     "anomaly_type": "cross_device_security_posture_inconsistency",
     "reason": "Equivalent LAN->WEB HTTPS allow; FortiGate inspected, Palo Alto unprotected."},
]
