"""Benchmark scoring (Volume 7 §6) — pure functions, no DB/I/O.

Compares the deterministic engine's findings against ground-truth expected cases
and computes TP/FP/FN, precision, recall, F1, and severity-match rate.

A finding is matched at (rule, anomaly_type) granularity (presence, not count).
Cross-device cases match if the expected anomaly appears on EITHER paired rule —
the engine attributes a cross-device finding to one side of the pair.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class ExpectedCase:
    anomaly_type: str
    rules: List[str]                       # 1 rule (intra) or 2 (cross-device pair)
    expected_severity: Optional[str] = None
    case_type: str = "atomic"              # atomic | compound
    kind: str = "intra"                    # intra | cross_device
    reason: str = ""


@dataclass
class CaseResult:
    case: ExpectedCase
    detected: bool
    matched_rule: Optional[str] = None
    detected_severity: Optional[str] = None
    detected_anomaly_id: Optional[int] = None
    severity_match: bool = False
    match_quality: str = "none"            # exact | partial | none


@dataclass
class BenchmarkScore:
    results: List[CaseResult]
    false_positives: List[Tuple[str, str]]  # (rule_name, anomaly_type) not expected
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float
    severity_match_rate: float


def score(expected: List[ExpectedCase],
          actual: Dict[str, Dict[str, dict]]) -> BenchmarkScore:
    """Score engine output against ground truth.

    `actual`: rule_name -> {anomaly_type -> {"severity": str, "anomaly_id": int}}.
    """
    actual_index: Set[Tuple[str, str]] = {
        (rule, atype) for rule, types in actual.items() for atype in types
    }
    consumed: Set[Tuple[str, str]] = set()
    results: List[CaseResult] = []

    for case in expected:
        hit: Optional[Tuple[str, dict]] = None
        for rule in case.rules:
            if (rule, case.anomaly_type) in actual_index:
                hit = (rule, actual[rule][case.anomaly_type])
                break
        if hit is not None:
            rule, info = hit
            consumed.add((rule, case.anomaly_type))
            sev = info.get("severity")
            sev_match = case.expected_severity is None or sev == case.expected_severity
            results.append(CaseResult(
                case=case, detected=True, matched_rule=rule,
                detected_severity=sev, detected_anomaly_id=info.get("anomaly_id"),
                severity_match=sev_match,
                match_quality="exact" if sev_match else "partial",
            ))
        else:
            results.append(CaseResult(case=case, detected=False))

    false_positives = sorted(actual_index - consumed)
    tp = sum(1 for r in results if r.detected)
    fn = sum(1 for r in results if not r.detected)
    fp = len(false_positives)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    sev_ok = sum(1 for r in results if r.detected and r.severity_match)
    severity_match_rate = (sev_ok / tp) if tp else 1.0

    return BenchmarkScore(
        results=results, false_positives=false_positives,
        tp=tp, fp=fp, fn=fn,
        precision=round(precision, 4), recall=round(recall, 4),
        f1=round(f1, 4), severity_match_rate=round(severity_match_rate, 4),
    )
