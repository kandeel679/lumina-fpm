"""Normalization layer (Volume 4).

Converts vendor-tagged parser models into the canonical normalized policy model and
the object/service correlation model. Deterministic and idempotent. The anomaly
engine consumes ONLY the output of this layer (ADR-010), never raw vendor data.
"""
from .engine import normalize_payloads
from .model import (
    NormalizationResult,
    NormalizedObjectRec,
    NormalizedRule,
    NormalizedServiceRec,
    ObjectMappingRec,
    ServiceMappingRec,
)

__all__ = [
    "normalize_payloads",
    "NormalizationResult",
    "NormalizedRule",
    "NormalizedObjectRec",
    "NormalizedServiceRec",
    "ObjectMappingRec",
    "ServiceMappingRec",
]
