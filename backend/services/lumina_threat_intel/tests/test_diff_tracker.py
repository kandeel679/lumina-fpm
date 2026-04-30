"""Tests for diff_tracker — hash computation and new/seen classification."""
import pytest
from unittest.mock import MagicMock, patch
from services.lumina_threat_intel.diff_tracker import compute_finding_hash, mark_new_findings


def _make_finding(**kwargs):
    base = {
        "category": "exploit",
        "title": "CVE-2024-3400 PoC on Exploit.in",
        "iocs": [{"type": "cve", "value": "CVE-2024-3400"}],
    }
    base.update(kwargs)
    return base


class TestComputeFindingHash:
    def test_deterministic(self):
        f = _make_finding()
        assert compute_finding_hash(f) == compute_finding_hash(f)

    def test_different_title_different_hash(self):
        a = _make_finding(title="CVE-A")
        b = _make_finding(title="CVE-B")
        assert compute_finding_hash(a) != compute_finding_hash(b)

    def test_ioc_order_insensitive(self):
        iocs_1 = [{"type": "cve", "value": "CVE-1"}, {"type": "ip", "value": "1.2.3.4"}]
        iocs_2 = [{"type": "ip", "value": "1.2.3.4"}, {"type": "cve", "value": "CVE-1"}]
        f1 = _make_finding(iocs=iocs_1)
        f2 = _make_finding(iocs=iocs_2)
        assert compute_finding_hash(f1) == compute_finding_hash(f2)

    def test_empty_iocs(self):
        f = _make_finding(iocs=[])
        h = compute_finding_hash(f)
        assert isinstance(h, str) and len(h) == 64

    def test_category_affects_hash(self):
        a = _make_finding(category="exploit")
        b = _make_finding(category="ransomware")
        assert compute_finding_hash(a) != compute_finding_hash(b)


class TestMarkNewFindings:
    def _make_db(self, existing_hashes: dict):
        """Return a mock DB whose recent-hash query returns existing_hashes."""
        db = MagicMock()
        rows = [(h, rid) for h, rid in existing_hashes.items()]
        db.query.return_value.join.return_value.filter.return_value.all.return_value = rows
        return db

    def test_all_new_when_db_empty(self):
        findings = [_make_finding(title="A"), _make_finding(title="B")]
        db = self._make_db({})
        result = mark_new_findings(db, current_report_id=1, findings=findings)
        assert all(f["is_new_since_last_scan"] for f in result)

    def test_previously_seen_finding_marked_not_new(self):
        finding = _make_finding(title="Known CVE")
        h = compute_finding_hash(finding)
        db = self._make_db({h: 99})  # hash exists in report 99
        result = mark_new_findings(db, current_report_id=1, findings=[finding])
        assert result[0]["is_new_since_last_scan"] is False
        assert result[0]["first_seen_in_scan_id"] == 99

    def test_hash_stored_on_finding(self):
        finding = _make_finding()
        db = self._make_db({})
        result = mark_new_findings(db, current_report_id=1, findings=[finding])
        assert "finding_hash" in result[0]
        assert len(result[0]["finding_hash"]) == 64

    def test_db_error_treated_as_all_new(self):
        db = MagicMock()
        db.query.side_effect = Exception("DB offline")
        findings = [_make_finding()]
        result = mark_new_findings(db, current_report_id=1, findings=findings)
        assert result[0]["is_new_since_last_scan"] is True
