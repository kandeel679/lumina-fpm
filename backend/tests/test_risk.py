"""Risk scorer band tests (Volume 8). Pure (no DB).

Run: `python backend/tests/test_risk.py`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.risk.scorer import score_device, score_rule, tier_of


def _f(atype, severity):
    return {"anomaly_type": atype, "severity": severity}


def test_tiers():
    assert tier_of(95) == "critical"
    assert tier_of(75) == "high"
    assert tier_of(50) == "medium"
    assert tier_of(10) == "low"
    assert tier_of(0) == "informational"


def test_clean_rule_is_informational():
    r = score_rule([])
    assert r["risk_score"] == 0 and r["risk_tier"] == "informational"


def test_governance_only_is_low():
    r = score_rule([_f("missing_description", "low")])
    assert r["risk_tier"] == "low" and r["risk_score"] < 40


def test_unprotected_web_allow_is_medium():
    r = score_rule([_f("unprotected_allow", "high"), _f("missing_description", "low")])
    assert r["risk_tier"] == "medium"
    assert "security_posture" in r["factor_breakdown"]


def test_broad_unprotected_unlogged_is_critical():
    r = score_rule([
        _f("overly_permissive", "critical"),
        _f("unprotected_allow", "high"),
        _f("missing_logging", "medium"),
        _f("missing_description", "low"),
    ])
    assert r["risk_score"] >= 90 and r["risk_tier"] == "critical"
    fb = r["factor_breakdown"]
    assert fb["exposure"] == 20 and fb["security_posture"] == 20 and fb["logging"] == 15


def test_cross_device_conflict_contributes_cross_vendor():
    r = score_rule([_f("conflict", "high"), _f("cross_device_inconsistency", "critical")])
    assert r["factor_breakdown"].get("cross_vendor") == 28
    assert r["risk_tier"] in ("medium", "high")


def test_score_is_capped_at_100():
    r = score_rule([_f("overly_permissive", "critical"), _f("any_to_sensitive", "critical"),
                    _f("unprotected_allow", "high"), _f("missing_logging", "medium"),
                    _f("cross_device_inconsistency", "critical")])
    assert r["risk_score"] == 100


def test_device_blend_keeps_critical_visible():
    # one critical rule among low rules -> device stays high (not diluted to low)
    d = score_device([96, 44, 24, 4, 0])
    assert d["risk_tier"] == "high"
    assert d["factor_breakdown"]["max_rule_risk"] == 96


def test_device_no_rules_informational():
    d = score_device([])
    assert d["risk_score"] == 0 and d["risk_tier"] == "informational"


if __name__ == "__main__":
    test_tiers()
    test_clean_rule_is_informational()
    test_governance_only_is_low()
    test_unprotected_web_allow_is_medium()
    test_broad_unprotected_unlogged_is_critical()
    test_cross_device_conflict_contributes_cross_vendor()
    test_score_is_capped_at_100()
    test_device_blend_keeps_critical_visible()
    test_device_no_rules_informational()
    print("OK: all risk tests passed")
