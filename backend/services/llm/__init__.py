"""AI/LLM SOC reporting subsystem (Volume 10).

The LLM EXPLAINS deterministic findings in SOC-friendly language — it is never the
anomaly authority and never invents evidence. Every report references DB evidence
IDs and carries provider/model metadata. If the LLM fails, the platform still
shows deterministic anomalies and risk (a built-in offline provider guarantees it).
"""
from .providers import LlmResult, build_provider

__all__ = ["LlmResult", "build_provider"]
