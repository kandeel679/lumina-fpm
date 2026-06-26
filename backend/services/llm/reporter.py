"""SOC report generation (Volume 10 §8-9) — DB-backed, evidence-grounded.

Assembles the deterministic evidence (findings, risk, CTI) with their DB IDs,
asks the configured LLM provider to explain it, and stores an llm_report with the
evidence references, prompt version, and provider/model metadata. If the LLM
fails, the report is stored with status='failed' and the deterministic data
remains available unchanged (V10 §11).
"""
from __future__ import annotations

from typing import Optional, Tuple

from sqlalchemy import func
from sqlalchemy.orm import Session

from core.config import settings
from core.logging import get_logger
from models import models

from . import prompts
from .providers import build_provider

logger = get_logger(__name__)


def _latest_run_id(db: Session) -> Optional[int]:
    return db.query(func.max(models.RuleAnomaly.analysis_run_id)).scalar()


def _rule_context(db: Session, rule_id: int, run_id: int) -> Tuple[dict, dict, str]:
    rule = db.query(models.PolicyRule).filter(models.PolicyRule.rule_id == rule_id).first()
    if rule is None:
        raise ValueError(f"rule {rule_id} not found")

    findings = []
    anomaly_ids = []
    for a in (db.query(models.RuleAnomaly)
              .filter(models.RuleAnomaly.rule_id == rule_id,
                      models.RuleAnomaly.analysis_run_id == run_id).all()):
        findings.append({"anomaly_id": a.anomaly_id, "anomaly_type": a.anomaly_type,
                         "severity": a.severity_level, "detection_mode": a.detection_mode,
                         "description": a.description})
        anomaly_ids.append(a.anomaly_id)

    risk_row = (db.query(models.RiskAssessment)
                .filter(models.RiskAssessment.scope_type == "rule",
                        models.RiskAssessment.scope_id == rule_id,
                        models.RiskAssessment.analysis_run_id == run_id).first())
    risk = None
    if risk_row:
        risk = {"risk_id": risk_row.risk_id, "risk_score": risk_row.risk_score,
                "risk_tier": risk_row.risk_tier, "factor_breakdown": risk_row.factor_breakdown}

    # CTI evidence for indicators on objects this rule references
    obj_ids = [oid for (oid,) in db.query(models.RuleObjectMapping.object_id)
               .filter(models.RuleObjectMapping.rule_id == rule_id).all()]
    cti, cti_obs_ids = [], []
    if obj_ids:
        for ind in (db.query(models.CtiIndicator)
                    .filter(models.CtiIndicator.source_object_id.in_(obj_ids)).all()):
            for o in ind.observations:
                cti.append({"observation_id": o.observation_id, "value": ind.value,
                            "provider": o.provider, "threat_type": o.threat_type,
                            "severity": o.severity, "confidence": o.confidence,
                            "summary": o.summary})
                cti_obs_ids.append(o.observation_id)

    ctx = {"rule": {"rule_id": rule.rule_id, "rule_name": rule.rule_name,
                    "vendor_type": rule.vendor_type, "device_id": rule.device_id,
                    "action": rule.action},
           "risk": risk, "findings": findings, "cti": cti}
    evidence_refs = {"anomaly_ids": anomaly_ids,
                     "risk_id": risk["risk_id"] if risk else None,
                     "cti_observation_ids": cti_obs_ids}
    return ctx, evidence_refs, prompts.render_rule_prompt(ctx)


def generate_report(db: Session, scope_type: str, scope_id: Optional[int] = None) -> dict:
    run_id = _latest_run_id(db)
    if run_id is None:
        return {"error": "no analysis run found"}

    document = None
    deterministic_md = None
    if scope_type == "rule":
        if scope_id is None:
            return {"error": "scope_id (rule_id) required for a rule report"}
        _ctx, evidence_refs, user_prompt = _rule_context(db, scope_id, run_id)
    elif scope_type == "executive":
        from .report_builder import build_executive_document
        document, deterministic_md = build_executive_document(db, run_id)
        tot = document["totals"]
        prompt_ctx = {
            "analysis_run_id": run_id,
            "total_findings": tot["open_findings"],
            "tier_counts": tot["tier_counts"],
            "top_rules": [
                {"risk_id": None, "rule_name": f"{r['pol']} {r['rule_name']}",
                 "vendor_type": r["vendor_type"], "risk_score": r["risk_score"],
                 "risk_tier": r["risk_tier"]}
                for r in document["remediation"][:6]
            ],
            "firmware_cves": [
                {"device": fc["device"], "firmware": fc["firmware"],
                 "cves": [c["reference"] for c in fc["cves"]]}
                for fc in document["firmware_cves"]
            ],
        }
        user_prompt = prompts.render_executive_prompt(prompt_ctx)
        evidence_refs = {
            "analysis_run_id": run_id,
            "remediation_rule_ids": [r["rule_id"] for r in document["remediation"][:10]],
        }
    else:
        return {"error": f"unsupported scope_type '{scope_type}'"}

    provider = build_provider(settings.llm_provider, settings.llm_api_key, settings.llm_model)
    result = provider.generate(prompts.SYSTEM_PROMPT, user_prompt)

    note = ("AI analysis grounded in the referenced evidence IDs; not itself evidence."
            if provider.name != "offline" else
            "Deterministic rendering of evidence (no LLM configured).")

    # The AI authors ONLY the executive summary; the deterministic tables stand on their
    # own, so a failed/offline LLM still yields a complete report (V10 §11).
    executive_summary = None
    markdown = None
    if scope_type == "executive":
        executive_summary = result.output
        summ = (executive_summary or "").strip()
        # avoid a double heading when the LLM emits its own "## ..." header
        summ_block = summ if summ.lstrip().startswith("#") else f"## Executive Summary\n\n{summ}"
        markdown = f"# {document['title']}\n\n{summ_block}\n\n{deterministic_md}"

    report = models.LlmReport(
        scope_type=scope_type, scope_id=scope_id, provider=result.provider,
        model=result.model, prompt_version=prompts.PROMPT_VERSION,
        evidence_refs=evidence_refs, output=result.output,
        document=document, markdown=markdown, executive_summary=executive_summary,
        confidence_note=note, status=result.status,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    logger.info("LLM report %s scope=%s id=%s provider=%s status=%s",
                report.report_id, scope_type, scope_id, result.provider, result.status)
    return {
        "report_id": report.report_id, "scope_type": scope_type, "scope_id": scope_id,
        "provider": result.provider, "model": result.model, "status": result.status,
        "prompt_version": prompts.PROMPT_VERSION, "evidence_refs": evidence_refs,
        "output": result.output, "document": document, "markdown": markdown,
        "executive_summary": executive_summary, "error": result.error,
    }
