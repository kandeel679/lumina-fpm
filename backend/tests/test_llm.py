"""LLM SOC reporting tests (Volume 10). Pure (no DB, no external calls).

Run: `python backend/tests/test_llm.py`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.llm.prompts import (
    SYSTEM_PROMPT,
    render_executive_prompt,
    render_rule_prompt,
)
from services.llm.providers import GeminiProvider, OfflineProvider, build_provider


def test_system_prompt_guardrails():
    s = SYSTEM_PROMPT.lower()
    assert "only" in s and "evidence" in s          # use only supplied evidence
    assert "do not invent" in s                      # no hallucinated CVEs/verdicts
    assert "deterministic engine" in s and "not you" in s  # LLM is not the detector


def test_build_provider_fallback():
    assert isinstance(build_provider("gemini", "", "gemini-2.5-flash"), OfflineProvider)
    assert isinstance(build_provider("gemini", "KEY", "gemini-2.5-flash"), GeminiProvider)
    assert isinstance(build_provider("unknown", "KEY", "m"), OfflineProvider)


def test_offline_provider_is_deterministic():
    p = OfflineProvider()
    r1 = p.generate("sys", "user-evidence")
    r2 = p.generate("sys", "user-evidence")
    assert r1.status == "complete" and r1.provider == "offline"
    assert r1.output == r2.output and "user-evidence" in r1.output


def test_rule_prompt_embeds_evidence_ids():
    ctx = {
        "rule": {"rule_id": 9, "rule_name": "FGT_ALLOW_MALICIOUS", "vendor_type": "fortinet",
                 "device_id": 1, "action": "allow"},
        "risk": {"risk_id": 42, "risk_score": 76, "risk_tier": "high",
                 "factor_breakdown": {"cti": 28}},
        "findings": [{"anomaly_id": 101, "anomaly_type": "threat_exposure", "severity": "high",
                      "detection_mode": "cti", "description": "permits traffic to a malicious IP"}],
        "cti": [{"observation_id": 7, "value": "185.220.101.1", "provider": "lab_offline",
                 "threat_type": "tor_exit", "severity": "high", "confidence": 0.85,
                 "summary": "Tor exit"}],
    }
    out = render_rule_prompt(ctx)
    assert "anomaly_id=101" in out and "risk_id=42" in out and "observation_id=7" in out
    assert "185.220.101.1" in out and "lab_offline" in out


def test_executive_prompt():
    ctx = {"analysis_run_id": 15, "total_findings": 45, "tier_counts": {"critical": 4},
           "top_rules": [{"risk_id": 1, "rule_name": "FGT_ANY_DB", "vendor_type": "fortinet",
                          "risk_score": 99, "risk_tier": "critical"}]}
    out = render_executive_prompt(ctx)
    assert "risk_id=1" in out and "FGT_ANY_DB" in out


if __name__ == "__main__":
    test_system_prompt_guardrails()
    test_build_provider_fallback()
    test_offline_provider_is_deterministic()
    test_rule_prompt_embeds_evidence_ids()
    test_executive_prompt()
    print("OK: all llm tests passed")
