"""Risk scoring engine (Volume 8).

Deterministic, versioned 0-100 risk scoring with a factor breakdown. Risk is
separate from detection: an anomaly says what is wrong; risk says what to fix
first. Reads the engine's findings; never touches a firewall.
"""
from .scorer import RISK_VERSION, score_device, score_rule, tier_of

__all__ = ["RISK_VERSION", "score_rule", "score_device", "tier_of"]
