"""Benchmark scorer tests (Volume 7). Pure (no DB).

Run: `python backend/tests/test_benchmark.py`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.benchmark.scorer import ExpectedCase, score


def _actual(d):
    # d: {rule: {type: severity}} -> scorer shape with synthetic anomaly_ids
    out = {}
    for rule, types in d.items():
        out[rule] = {t: {"severity": s, "anomaly_id": i}
                     for i, (t, s) in enumerate(types.items(), start=1)}
    return out


def test_perfect_match():
    expected = [
        ExpectedCase("unprotected_allow", ["R1"], "high"),
        ExpectedCase("missing_description", ["R1"], "low"),
    ]
    actual = _actual({"R1": {"unprotected_allow": "high", "missing_description": "low"}})
    s = score(expected, actual)
    assert (s.tp, s.fp, s.fn) == (2, 0, 0), (s.tp, s.fp, s.fn)
    assert s.precision == 1.0 and s.recall == 1.0 and s.f1 == 1.0
    assert s.severity_match_rate == 1.0


def test_false_negative_lowers_recall():
    expected = [
        ExpectedCase("shadowing", ["R1"], "high"),
        ExpectedCase("redundancy", ["R1"], "medium"),
    ]
    actual = _actual({"R1": {"shadowing": "high"}})  # redundancy missed
    s = score(expected, actual)
    assert (s.tp, s.fn) == (1, 1)
    assert s.recall == 0.5 and s.precision == 1.0


def test_false_positive_lowers_precision():
    expected = [ExpectedCase("shadowing", ["R1"], "high")]
    actual = _actual({"R1": {"shadowing": "high", "conflict": "high"}})  # conflict unexpected
    s = score(expected, actual)
    assert (s.tp, s.fp, s.fn) == (1, 1, 0)
    assert s.precision == 0.5 and s.recall == 1.0
    assert ("R1", "conflict") in s.false_positives


def test_cross_device_matches_either_peer():
    # engine attributes the cross-device finding to the PA side only
    expected = [ExpectedCase("cross_device_inconsistency", ["FGT_X", "PA_X"], "critical",
                             kind="cross_device")]
    actual = _actual({"PA_X": {"cross_device_inconsistency": "critical"}})
    s = score(expected, actual)
    assert s.tp == 1 and s.fp == 0 and s.fn == 0
    # the finding on PA_X is consumed by the pair, not an FP
    assert s.false_positives == []


def test_severity_mismatch_is_partial():
    expected = [ExpectedCase("cross_device_inconsistency", ["A", "B"], "critical",
                             kind="cross_device")]
    actual = _actual({"B": {"cross_device_inconsistency": "high"}})  # wrong severity
    s = score(expected, actual)
    assert s.tp == 1 and s.severity_match_rate == 0.0
    assert s.results[0].match_quality == "partial"


if __name__ == "__main__":
    test_perfect_match()
    test_false_negative_lowers_recall()
    test_false_positive_lowers_precision()
    test_cross_device_matches_either_peer()
    test_severity_mismatch_is_partial()
    print("OK: all benchmark tests passed")
