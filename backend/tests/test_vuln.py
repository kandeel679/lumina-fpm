"""Firmware-CVE intelligence tests (Volume 9 §6, device axis). Pure (no DB).

Covers the lifted version helpers, CVSS->severity bands, the offline lab dataset
(Cisco-free, matches the lab firmware), the pure CVE<->device predicate, and the
device firmware modifier in the risk scorer.

Run: `python backend/tests/test_vuln.py`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.cti import vuln_intel as VI
from services.cti.vuln_intel import (
    CveFinding,
    LAB_CVE_FINDINGS,
    _cvss_to_severity,
    _version_in_range,
    _version_tuple,
    cve_affects_device,
)
from services.risk.scorer import score_device


# ── version helpers ──

def test_version_tuple():
    assert _version_tuple("7.4.3") == (7, 4, 3, 0)
    assert _version_tuple("11.1.2") == (11, 1, 2, 0)
    # a vendor build suffix still parses; the leading components drive comparison,
    # and a firmware string with a build tag still falls inside the branch range.
    assert _version_in_range("v7.4.3,build2573", {"startIncl": "7.4.0", "endExcl": "7.4.5"}) is True
    assert _version_tuple("not-a-version") is None


def test_version_in_range_bounds():
    # 7.4.3 inside [7.4.0, 7.4.5)
    assert _version_in_range("7.4.3", {"startIncl": "7.4.0", "endExcl": "7.4.5"}) is True
    # 7.4.5 NOT inside [7.4.0, 7.4.5)
    assert _version_in_range("7.4.5", {"startIncl": "7.4.0", "endExcl": "7.4.5"}) is False
    # exact match
    assert _version_in_range("11.1.2", {"exact": "11.1.2"}) is True
    assert _version_in_range("11.1.3", {"exact": "11.1.2"}) is False
    # an empty range (no bounds) never matches
    assert _version_in_range("7.4.3", {}) is False
    # endIncl boundary is inclusive
    assert _version_in_range("11.0.4", {"startIncl": "11.0.0", "endIncl": "11.0.4"}) is True


def test_cvss_to_severity_bands():
    assert _cvss_to_severity(9.8, None) == "critical"
    assert _cvss_to_severity(7.5, None) == "high"
    assert _cvss_to_severity(5.0, None) == "medium"
    assert _cvss_to_severity(2.0, None) == "low"
    # explicit baseSeverity string wins
    assert _cvss_to_severity(None, "CRITICAL") == "critical"
    assert _cvss_to_severity(None, None) == "low"


# ── offline lab dataset ──

def test_lab_dataset_is_cisco_free():
    vendors = {f.vendor_type for f in LAB_CVE_FINDINGS}
    assert vendors == {"fortinet", "paloalto"}, vendors
    assert all(f.product in ("fortios", "pan_os") for f in LAB_CVE_FINDINGS)
    # provider maps onto the schema's sanctioned set
    assert all(f.provider in ("nvd", "vendor_advisory") for f in LAB_CVE_FINDINGS)


def test_lab_dataset_matches_lab_firmware():
    forti = [f for f in LAB_CVE_FINDINGS if f.vendor_type == "fortinet"]
    pan = [f for f in LAB_CVE_FINDINGS if f.vendor_type == "paloalto"]
    # FortiOS 7.4.3 is hit by at least one curated FortiOS CVE
    assert any(cve_affects_device(f, "fortinet", "7.4.3") for f in forti)
    # PAN-OS 11.1.2 and 11.0.4 are both hit
    assert any(cve_affects_device(f, "paloalto", "11.1.2") for f in pan)
    assert any(cve_affects_device(f, "paloalto", "11.0.4") for f in pan)


def test_cve_does_not_cross_vendor():
    forti_cve = next(f for f in LAB_CVE_FINDINGS if f.vendor_type == "fortinet")
    # a FortiOS CVE must never match a Palo Alto device
    assert cve_affects_device(forti_cve, "paloalto", "11.1.2") is False
    # missing firmware / vendor -> no match
    assert cve_affects_device(forti_cve, "fortinet", None) is False
    assert cve_affects_device(forti_cve, None, "7.4.3") is False


def test_offline_scoping_to_present_vendors():
    only_forti = VI._offline_cve_findings({"fortinet"})
    assert only_forti and all(f.vendor_type == "fortinet" for f in only_forti)
    assert VI._offline_cve_findings(set()) == []


# ── device firmware modifier (risk scorer) ──

def test_score_device_backward_compatible():
    # no device_factors -> identical to the pre-firmware behavior
    base = score_device([96, 44, 24, 4, 0])
    assert base["factor_breakdown"]["max_rule_risk"] == 96
    assert "firmware_modifier" not in base["factor_breakdown"]
    assert score_device([])["risk_score"] == 0


def test_firmware_modifier_raises_device_score():
    base = score_device([40, 20, 10])
    bumped = score_device([40, 20, 10], device_factors={"firmware_modifier": 40})
    assert bumped["risk_score"] == min(100, base["risk_score"] + 40)
    assert bumped["factor_breakdown"]["firmware_modifier"] == 40


def test_firmware_modifier_capped_at_100():
    d = score_device([96, 44, 24, 4, 0], device_factors={"firmware_modifier": 40})
    assert d["risk_score"] == 100  # cap over the full sum, never 136 or double-clamped


def test_clean_rules_but_vulnerable_firmware():
    # a device with no risky rules still scores from the firmware modifier alone
    d = score_device([], device_factors={"firmware_modifier": 30})
    assert d["risk_score"] == 30 and d["risk_tier"] == "low"
    assert d["factor_breakdown"]["firmware_modifier"] == 30


if __name__ == "__main__":
    test_version_tuple()
    test_version_in_range_bounds()
    test_cvss_to_severity_bands()
    test_lab_dataset_is_cisco_free()
    test_lab_dataset_matches_lab_firmware()
    test_cve_does_not_cross_vendor()
    test_offline_scoping_to_present_vendors()
    test_score_device_backward_compatible()
    test_firmware_modifier_raises_device_score()
    test_firmware_modifier_capped_at_100()
    test_clean_rules_but_vulnerable_firmware()
    print("OK: all vuln tests passed")
