"""Risk scoring (Volume 8 §5-10) — pure, deterministic, versioned.

risk_score = min(100, anomaly + exposure + asset_sensitivity + security_posture
                      + logging + cross_vendor + cti + lifecycle)

Factors are derived from the rule's findings (which already encode the relevant
conditions). Each factor stays within its V8 Table 4 range; the breakdown is kept
so SOC engineers see *why* a rule scored high. cti/lifecycle land in later phases.
"""
from __future__ import annotations

from typing import Dict, List

RISK_VERSION = "1.0.0"

# Anomaly-severity base points (V8 Table 4: critical 30-45, high 20-30, medium 10-20, low 1-9).
_SEVERITY_POINTS = {"critical": 35, "high": 22, "medium": 12, "low": 4}

# finding type -> (factor, points). Each factor is taken as a MAX across findings,
# so it stays inside its V8 Table 4 range regardless of how many findings hit it.
_FACTOR_CONTRIB = {
    "overly_permissive": ("exposure", 20),
    "wide_port_range": ("exposure", 10),
    "any_to_sensitive": ("asset_sensitivity", 15),
    "unprotected_allow": ("security_posture", 20),
    "missing_logging": ("logging", 15),
    "cross_device_inconsistency": ("cross_vendor", 28),
    "cross_device_security_posture_inconsistency": ("cross_vendor", 18),
    "disabled_rule_review": ("lifecycle", 6),
}


def tier_of(score: int) -> str:
    """V8 Table 2 risk tiers."""
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 1:
        return "low"
    return "informational"


def score_rule(findings: List[Dict[str, str]]) -> dict:
    """Score one rule from its findings: [{'anomaly_type': str, 'severity': str}, ...]."""
    factors: Dict[str, int] = {}

    # anomaly factor: dominant severity + a small compound bonus for stacked findings
    if findings:
        sev_points = [_SEVERITY_POINTS.get(f.get("severity"), 4) for f in findings]
        factors["anomaly"] = max(sev_points) + min(8, 2 * (len(findings) - 1))

    for f in findings:
        contrib = _FACTOR_CONTRIB.get(f.get("anomaly_type"))
        if contrib:
            factor, pts = contrib
            factors[factor] = max(factors.get(factor, 0), pts)

    # ANY-source-to-sensitive also widens exposure breadth (V8 Table 5)
    if any(f.get("anomaly_type") == "any_to_sensitive" for f in findings):
        factors["exposure"] = max(factors.get("exposure", 0), 8)

    score = min(100, sum(factors.values()))
    return {
        "risk_score": score,
        "risk_tier": tier_of(score),
        "factor_breakdown": factors,
        "calculation_version": RISK_VERSION,
    }


def score_device(rule_scores: List[int]) -> dict:
    """Device risk = weighted avg of the top-5 rule risks + a critical-count modifier (V8 §8)."""
    if not rule_scores:
        return {
            "risk_score": 0, "risk_tier": "informational",
            "factor_breakdown": {"top_rules_avg": 0, "critical_rule_count": 0, "modifier": 0},
            "calculation_version": RISK_VERSION,
        }
    top = sorted(rule_scores, reverse=True)[:5]
    max_rule = top[0]
    avg = sum(top) / len(top)
    # weighted toward the worst rule so a single critical rule isn't diluted away
    blend = 0.6 * max_rule + 0.4 * avg
    crit_count = sum(1 for s in rule_scores if s >= 90)
    modifier = min(10, crit_count * 4)
    score = min(100, round(blend + modifier))
    return {
        "risk_score": score,
        "risk_tier": tier_of(score),
        "factor_breakdown": {
            "max_rule_risk": max_rule,
            "top_rules_avg": round(avg, 1),
            "critical_rule_count": crit_count,
            "modifier": modifier,
        },
        "calculation_version": RISK_VERSION,
    }
