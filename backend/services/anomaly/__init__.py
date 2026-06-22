"""Deterministic anomaly engine (Volume 5).

Config-only core detectors over the NORMALIZED model. Every finding is explainable
with evidence; no randomness, no LLM, no raw vendor data.
"""
from .engine import analyze
from .model import Finding

__all__ = ["analyze", "Finding"]
