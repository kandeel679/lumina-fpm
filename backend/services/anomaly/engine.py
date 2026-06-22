"""Anomaly engine — runs every config-only detector over a NormalizationResult.

Deterministic: detectors run in a fixed order and each yields findings in a stable
order, so analyze() returns the same list for the same input. Reads the NORMALIZED
model ONLY (ADR-010); no DB, no network, no LLM.
"""
from __future__ import annotations

from typing import List

from services.normalization.model import NormalizationResult

from .detectors import ALL_DETECTORS
from .model import Finding


def analyze(result: NormalizationResult) -> List[Finding]:
    """Run all detectors and return the combined, deterministic finding list."""
    findings: List[Finding] = []
    for detector in ALL_DETECTORS:
        findings.extend(detector(result))
    return findings
