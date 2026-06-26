"""CTI tests (Volume 9). Pure (no DB).

Run: `python backend/tests/test_cti.py`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.cti.extract import classify, extract_indicators, is_public_ip
from services.cti.providers import LabOfflineProvider, build_providers
from services.risk.scorer import score_rule

MALICIOUS_IP = "185.220.101.1"


def test_public_vs_private():
    assert is_public_ip(MALICIOUS_IP) is True
    assert is_public_ip("10.10.10.0/24") is False
    assert is_public_ip("192.168.55.100") is False
    assert is_public_ip("172.16.5.5") is False
    assert is_public_ip("0.0.0.0/0") is False
    assert is_public_ip("not-an-ip") is None


def test_classify():
    assert classify(MALICIOUS_IP) == "ip_address"
    assert classify("8.8.8.0/24") == "cidr"
    assert classify("gmail.com") == "fqdn"
    assert classify("any") is None
    assert classify("0.0.0.0/0") is None


def test_extract_minimizes_internal():
    objs = [(1, 2, MALICIOUS_IP), (2, 2, "10.10.10.0/24"), (3, 2, "0.0.0.0/0"), (4, 2, "gmail.com")]
    # default: internal RFC1918 is NOT sent
    pub = {i.value for i in extract_indicators(objs, allow_internal=False)}
    assert MALICIOUS_IP in pub and "gmail.com" in pub
    assert "10.10.10.0/24" not in pub and "0.0.0.0/0" not in pub
    # opt-in: internal included
    allv = {i.value for i in extract_indicators(objs, allow_internal=True)}
    assert "10.10.10.0/24" in allv


def test_known_bad_loaded_from_file():
    # The known-bad list is loaded from backend/data/cti_indicators.json (not hardcoded);
    # a missing/empty file must fail loudly here rather than silently disable CTI.
    assert len(LabOfflineProvider.KNOWN_BAD) >= 1
    assert MALICIOUS_IP in LabOfflineProvider.KNOWN_BAD


def test_offline_provider_verdict():
    p = LabOfflineProvider()
    v = p.lookup_ip(MALICIOUS_IP)
    assert v is not None and v.malicious and v.provider == "lab_offline"
    assert v.confidence >= 0.5
    assert p.lookup_ip("8.8.8.8") is None  # benign -> no information


def test_build_providers():
    assert any(p.name == "lab_offline" for p in build_providers(""))
    keyed = build_providers("abuseipdb=DUMMYKEY")
    assert any(p.name == "abuseipdb" for p in keyed)


def test_threat_exposure_adds_cti_risk():
    r = score_rule([{"anomaly_type": "threat_exposure", "severity": "high"}])
    assert r["factor_breakdown"].get("cti") == 28
    assert r["risk_score"] > 0


if __name__ == "__main__":
    test_public_vs_private()
    test_classify()
    test_extract_minimizes_internal()
    test_known_bad_loaded_from_file()
    test_offline_provider_verdict()
    test_build_providers()
    test_threat_exposure_adds_cti_risk()
    print("OK: all cti tests passed")
