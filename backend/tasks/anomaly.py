"""Anomaly analysis tasks."""
from __future__ import annotations

import logging
import random
from typing import Any

from celery_app import celery
from models.models import get_db, PolicyRule, RuleAnomaly
from services.anomaly_engine import run_anomaly_detection

logger = logging.getLogger(__name__)

@celery.task(
    bind=True,
    name="tasks.run_anomaly_analysis",
    max_retries=0,
    acks_late=True,
    time_limit=300,
)
def run_anomaly_analysis_task(self, device_id: int) -> dict[str, Any]:
    logger.info("Anomaly analysis task started for device_id=%d", device_id)
    SessionLocal = get_db()
    session = SessionLocal()

    try:
        # Run the mock anomaly detection (this will block/sleep for 4 seconds)
        anomalies_data = run_anomaly_detection(device_id)

        # Get actual rules for this device to map anomalies to
        rules = session.query(PolicyRule).filter(PolicyRule.device_id == device_id).all()
        rule_ids = [rule.rule_id for rule in rules]

        inserted_count = 0
        for anomaly_dict in anomalies_data:
            # Map to an existing rule if possible, else skip.
            if rule_ids:
                anomaly_dict["rule_id"] = random.choice(rule_ids)
                anomaly_row = RuleAnomaly(**anomaly_dict)
                session.add(anomaly_row)
                inserted_count += 1
            else:
                logger.warning("No rules found for device_id=%d, skipping anomaly.", device_id)

        session.commit()
        logger.info("Anomaly analysis complete. Inserted %d anomalies.", inserted_count)
        return {"status": "success", "inserted_count": inserted_count}

    except Exception as exc:
        logger.exception("Anomaly analysis task failed: %s", exc)
        session.rollback()
        return {"status": "error", "message": str(exc)}
    finally:
        session.close()
