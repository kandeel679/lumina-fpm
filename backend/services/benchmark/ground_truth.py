"""Phase-1 benchmark ground truth (Volume 7) — the `benchmark_case` seed.

This is the authoritative expected-anomaly matrix the engine is scored against.
It mirrors the *design intent* in `lab/benchmark_dataset.py` (`expected` lists +
CROSS_DEVICE_PAIRS); kept in the backend so the runner is self-contained (lab/ is
not mounted into the API container). Each expected anomaly is derived from the
rule's configuration + the detector definitions, NOT from engine output.

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
# filtered out by the runner against the live policy_rule table.
INTRA = {
    "fortinet": {
        "FGT_ALLOW_WEB": ["unprotected_allow", "missing_description"],
        "FGT_DUP_WEB": ["duplicate_rules", "unprotected_allow"],
        "FGT_BROAD_WEB": [],
        "FGT_REDUNDANT_WEB": ["redundancy", "duplicate_rules"],
        "FGT_BLOCK_WEB2": [],
        "FGT_SHADOWED_WEB2": ["shadowing", "conflict"],
        "FGT_ANY_DB": ["any_to_sensitive", "unprotected_allow", "missing_logging", "missing_description"],
        "FGT_ANY_ANY": ["overly_permissive", "unprotected_allow", "missing_logging",
                        "missing_description", "conflict"],
        "FGT_WIDE_PORTS": ["wide_port_range", "redundancy"],
        "FGT_DB_ACCESS_XDEV": ["redundancy"],
        # not deployed on the eval FGT (10-policy cap) — kept for documentation:
        "FGT_ADMIN_DB_NOLOG": ["missing_logging"],
        "FGT_DISABLED_RISKY": ["disabled_rule_review"],
    },
    "paloalto": {
        "PA_ALLOW_WEB": ["unprotected_allow", "missing_description"],
        "PA_DUP_WEB": ["duplicate_rules", "unprotected_allow"],
        "PA_BLOCK_WEB2": [],
        "PA_SHADOWED_WEB2": ["shadowing", "conflict"],
        "PA_ANY_DB": ["any_to_sensitive", "unprotected_allow", "missing_logging", "missing_description"],
        "PA_ANY_ANY": ["overly_permissive", "unprotected_allow", "missing_logging",
                       "missing_description", "conflict"],
        "PA_ADMIN_DB_NOLOG": ["missing_logging", "redundancy"],
        "PA_DB_ACCESS_XDEV": ["conflict"],
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
