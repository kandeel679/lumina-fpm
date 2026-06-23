"""Benchmark & evaluation subsystem (Volume 7).

Scores the deterministic anomaly engine against ground truth and computes
precision/recall/F1 — the acceptance gate and regression guard.
"""
from .scorer import BenchmarkScore, CaseResult, ExpectedCase, score

__all__ = ["BenchmarkScore", "CaseResult", "ExpectedCase", "score"]
