"""CTI runner (Volume 9 §4, §8, §10) — DB-backed.

Extracts public indicators from normalized objects, enriches them via the active
providers, persists cti_indicator + cti_observation, correlates malicious
indicators to rules that permit them (raising a labeled `threat_exposure`
finding), and triggers a risk recalculation so the cti_score lands.

Read-only against firewalls. Internal indicators never leave the platform.
"""
from __future__ import annotations

from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from core.config import settings
from core.logging import get_logger
from models import models

from .extract import extract_indicators
from .providers import build_providers

logger = get_logger(__name__)

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _latest_run_id(db: Session) -> Optional[int]:
    return db.query(func.max(models.RuleAnomaly.analysis_run_id)).scalar()


def _upsert_indicator(db: Session, ind) -> models.CtiIndicator:
    row = (
        db.query(models.CtiIndicator)
        .filter(models.CtiIndicator.value == ind.value,
                models.CtiIndicator.source_object_id == ind.object_id)
        .first()
    )
    if row is None:
        row = models.CtiIndicator(
            type=ind.type, value=ind.value, source_object_id=ind.object_id,
            source_device_id=ind.device_id, is_public=ind.is_public,
        )
        db.add(row)
        db.flush()
    else:
        row.last_seen = models.utcnow()
        # drop stale observations so re-runs don't accumulate
        db.query(models.CtiObservation).filter(
            models.CtiObservation.indicator_id == row.indicator_id
        ).delete()
    return row


def _correlate_threat(db: Session, ind, verdict, run_id: int) -> int:
    """Raise threat_exposure on ALLOW rules (across all devices) that reference an
    object whose value matches the malicious indicator."""
    candidates = [ind.value, f"{ind.value}/32", f"{ind.value}/128"]
    obj_ids = [
        oid for (oid,) in db.query(models.NetworkObject.object_id)
        .filter(models.NetworkObject.value.in_(candidates)).all()
    ]
    if not obj_ids:
        return 0
    rule_ids = [
        rid for (rid,) in db.query(models.RuleObjectMapping.rule_id)
        .filter(models.RuleObjectMapping.object_id.in_(obj_ids)).distinct().all()
    ]
    created = 0
    for rule_id in rule_ids:
        # Scope to the LIVE snapshot (deleted_at IS NULL): a rule retired by re-acquisition still
        # has its object mappings, so without this filter a re-provisioned-away rule (and a
        # superseded duplicate of a current rule) would each raise a stale threat_exposure.
        rule = db.query(models.PolicyRule).filter(
            models.PolicyRule.rule_id == rule_id,
            models.PolicyRule.deleted_at.is_(None),
        ).first()
        if rule is None or rule.action != "allow":
            continue
        db.add(models.RuleAnomaly(
            rule_id=rule_id,
            anomaly_type="threat_exposure",
            severity_level=verdict.severity,
            confidence=verdict.confidence,
            description=(
                f"Rule '{rule.rule_name}' permits traffic to/from a known-malicious "
                f"indicator ({verdict.summary})."
            ),
            evidence={
                "indicator": ind.value, "provider": verdict.provider,
                "confidence": verdict.confidence, "threat_type": verdict.threat_type,
                "reference": verdict.reference,
            },
            recommendation="Block or restrict access to the malicious indicator; review for compromise.",
            detection_mode="cti",
            analysis_run_id=run_id,
            status="open",
        ))
        created += 1
    return created


def run_cti(db: Session, run_id: Optional[int] = None) -> dict:
    if run_id is None:
        run_id = _latest_run_id(db)
    if run_id is None:
        return {"error": "no analysis run found"}

    providers = build_providers(settings.cti_provider_keys_raw)
    allow_internal = settings.cti_allow_internal_indicators

    objs = db.query(models.NetworkObject.object_id,
                    models.NetworkObject.device_id,
                    models.NetworkObject.value).all()
    indicators = extract_indicators(objs, allow_internal=allow_internal)

    # idempotent: clear this run's prior CTI findings before re-correlating
    db.query(models.RuleAnomaly).filter(
        models.RuleAnomaly.analysis_run_id == run_id,
        models.RuleAnomaly.anomaly_type == "threat_exposure",
    ).delete()

    enriched = malicious = threat_exposures = 0
    providers_used = set()

    for ind in indicators:
        verdicts = []
        for p in providers:
            v = (p.lookup_ip(ind.value) if ind.type in ("ip_address", "cidr")
                 else p.lookup_domain(ind.value))
            if v is not None:
                verdicts.append(v)
                providers_used.add(p.name)
        if not verdicts:
            continue
        row = _upsert_indicator(db, ind)
        enriched += 1
        for v in verdicts:
            db.add(models.CtiObservation(
                indicator_id=row.indicator_id, provider=v.provider,
                provider_reference=v.reference, severity=v.severity,
                confidence=v.confidence, threat_type=v.threat_type,
                summary=v.summary, raw_response_hash=v.raw_hash,
            ))
        worst = max(verdicts, key=lambda x: (x.malicious, _SEV_RANK.get(x.severity, 0), x.confidence))
        if worst.malicious:
            malicious += 1
            threat_exposures += _correlate_threat(db, ind, worst, run_id)

    db.commit()

    # CTI feeds risk (V9 §10): recalc so cti_score (from threat_exposure) lands.
    try:
        from services.risk.runner import run_risk
        run_risk(db, run_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Risk recalculation after CTI failed for run %s: %s", run_id, exc)

    logger.info("CTI run %s: %d indicators enriched, %d malicious, %d threat_exposure findings (%s)",
                run_id, enriched, malicious, threat_exposures, sorted(providers_used))
    return {
        "analysis_run_id": run_id,
        "providers": sorted(providers_used),
        "indicators_enriched": enriched,
        "malicious_indicators": malicious,
        "threat_exposure_findings": threat_exposures,
        "internal_indicators_sent": allow_internal,
    }
