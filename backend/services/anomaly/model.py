"""Finding model — the deterministic output of a single anomaly detector.

Pure, DB-independent. The anomaly task maps each Finding onto a RuleAnomaly row
(via device_id + rule_uuid -> PolicyRule.rule_id). Every Finding is explainable:
``evidence`` carries the concrete facts that produced it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class Finding:
    anomaly_type: str
    device_id: int
    rule_uuid: str                       # NormalizedRule.vendor_uuid
    severity: str                        # critical|high|medium|low
    confidence: float                    # 0..1
    description: str
    recommendation: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    related_device_id: Optional[int] = None
    related_rule_uuid: Optional[str] = None
    detection_mode: str = "config_only"
