"""Mock Anomaly Engine — simulates rule-anomaly detection.

This is a blocking mock (uses time.sleep) designed to be called from a
Celery worker.  Replace with real analysis logic in production.
"""
from __future__ import annotations

import logging
import random
import time
from datetime import datetime

logger = logging.getLogger(__name__)

# Realistic anomaly templates
_ANOMALY_TEMPLATES = [
    {
        "anomaly_type": "shadowing",
        "severity_level": "high",
        "description": (
            "Rule '{rule_name}' (order {order}) is completely shadowed by "
            "a broader rule at a higher priority. It will never match any traffic."
        ),
    },
    {
        "anomaly_type": "redundancy",
        "severity_level": "medium",
        "description": (
            "Rule '{rule_name}' (order {order}) is redundant — its match "
            "criteria are a subset of another rule with the same action."
        ),
    },
    {
        "anomaly_type": "conflict",
        "severity_level": "critical",
        "description": (
            "Rule '{rule_name}' (order {order}) conflicts with a higher-priority "
            "rule. Overlapping traffic is handled by the conflicting rule's action."
        ),
    },
    {
        "anomaly_type": "overly_permissive",
        "severity_level": "high",
        "description": (
            "Rule '{rule_name}' (order {order}) uses 'any' for both source and "
            "destination, allowing unrestricted traffic across zones."
        ),
    },
    {
        "anomaly_type": "unused_rule",
        "severity_level": "low",
        "description": (
            "Rule '{rule_name}' (order {order}) has had zero hit-count for "
            "over 90 days and may be safely removed."
        ),
    },
]


def run_anomaly_detection(device_id: int) -> list[dict]:
    """Run mock anomaly detection for a device's policy rules.

    Args:
        device_id: The firewall device to analyse.

    Returns:
        A list of dicts matching the ``rule_anomaly`` table schema::

            {
                "rule_id": int,
                "anomaly_type": str,
                "severity_level": str,
                "description": str,
            }
    """
    logger.info("Running anomaly detection for device_id=%d (mock)", device_id)

    # Simulate analysis time (blocking — runs inside Celery worker)
    time.sleep(4)

    # Generate 3-5 realistic anomalies
    count = random.randint(3, 5)
    anomalies: list[dict] = []

    for i in range(count):
        template = random.choice(_ANOMALY_TEMPLATES)
        rule_order = random.randint(1, 20)
        rule_name = f"Rule-{device_id}-{rule_order:03d}"

        anomalies.append({
            "rule_id": None,  # Caller should map to a real rule_id
            "anomaly_type": template["anomaly_type"],
            "severity_level": template["severity_level"],
            "description": template["description"].format(
                rule_name=rule_name,
                order=rule_order,
            ),
        })

    logger.info(
        "Anomaly detection complete for device_id=%d: %d anomalies found",
        device_id,
        len(anomalies),
    )
    return anomalies
