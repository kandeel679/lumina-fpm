"""Deterministic SOC report builder (Volume 10 §8) — pure DB assembly, no LLM.

Builds the structured ``document`` (sections rendered as tables in the UI and in the
downloadable Markdown) from an analysis run's evidence:
  1. Prioritized Remediation (top) — rules sorted by risk, what to fix first.
  2. Per-Finding Evidence — every finding with its anomaly_id, severity, recommendation.
  3. Risk Posture — tier distribution + device scores (incl. firmware modifier).
  4. Firmware CVEs (device axis) — each device's matched CVEs, labelled benchmark-excluded.

The LLM authors ONLY the executive summary; if it fails/offline this document is still
complete and correct (V10 §11). Read-only DB analysis; never touches a firewall.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from models import models

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _pol(rule_id: Optional[int]) -> str:
    return f"POL-{str(rule_id).zfill(3)}" if rule_id is not None else "—"


def _worst(severities: List[str]) -> str:
    return max(severities, key=lambda s: _SEV_RANK.get(s, 0)) if severities else "low"


def _md_table(headers: List[str], rows: List[List]) -> str:
    def cell(c) -> str:
        return str("" if c is None else c).replace("|", "\\|").replace("\n", " ")
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        out.append("| " + " | ".join(cell(c) for c in row) + " |")
    return "\n".join(out)


def _firmware_cves(db: Session, device_ids: Optional[List[int]],
                   device_risk: Dict[int, "models.RiskAssessment"]) -> List[dict]:
    """firmware_cves section entries (device axis). device_ids=None => all devices."""
    devs = {d.device_id: d for d in db.query(models.FirewallDevice).all()}
    q = db.query(models.CtiIndicator).filter(
        models.CtiIndicator.type == "firmware_version",
        models.CtiIndicator.source_device_id.isnot(None))
    if device_ids is not None:
        q = q.filter(models.CtiIndicator.source_device_id.in_(device_ids))
    out: List[dict] = []
    for ind in q.all():
        cves = [{
            "reference": o.provider_reference, "provider": o.provider,
            "severity": o.severity, "confidence": o.confidence, "summary": o.summary,
        } for o in ind.observations if o.threat_type == "vulnerability"]
        if not cves:
            continue
        d = devs.get(ind.source_device_id)
        dr = device_risk.get(ind.source_device_id)
        out.append({
            "device": d.hostname if d else str(ind.source_device_id),
            "vendor_type": d.vendor_type if d else None,
            "firmware": ind.value,
            "firmware_modifier": (dr.factor_breakdown or {}).get("firmware_modifier", 0) if dr else 0,
            "cves": sorted(cves, key=lambda c: _SEV_RANK.get(c["severity"], 0), reverse=True),
        })
    return out


def build_executive_document(db: Session, run_id: int) -> Tuple[dict, str]:
    """Return (document, markdown) for the executive (whole-run) SOC report."""
    devices = {d.device_id: d for d in db.query(models.FirewallDevice).all()}
    rules = {r.rule_id: r for r in db.query(models.PolicyRule).all()}

    rule_risk = {
        r.scope_id: r for r in db.query(models.RiskAssessment).filter(
            models.RiskAssessment.analysis_run_id == run_id,
            models.RiskAssessment.scope_type == "rule").all()
    }
    device_risk = {
        r.scope_id: r for r in db.query(models.RiskAssessment).filter(
            models.RiskAssessment.analysis_run_id == run_id,
            models.RiskAssessment.scope_type == "device").all()
    }

    findings_by_rule: Dict[int, List[models.RuleAnomaly]] = {}
    for a in db.query(models.RuleAnomaly).filter(
            models.RuleAnomaly.analysis_run_id == run_id).all():
        findings_by_rule.setdefault(a.rule_id, []).append(a)

    def dev_name(device_id: Optional[int]) -> str:
        d = devices.get(device_id)
        return d.hostname if d else (str(device_id) if device_id is not None else "—")

    # ── 1. Remediation (one row per rule with findings, prioritized) ──
    remediation: List[dict] = []
    for rule_id, flist in findings_by_rule.items():
        rule = rules.get(rule_id)
        sevs = [f.severity_level for f in flist]
        worst = _worst(sevs)
        # the recommendation of the worst finding (fallback to any present)
        rec = next((f.recommendation for f in sorted(
            flist, key=lambda x: _SEV_RANK.get(x.severity_level, 0), reverse=True)
            if f.recommendation), None)
        rr = rule_risk.get(rule_id)
        remediation.append({
            "rule_id": rule_id, "pol": _pol(rule_id),
            "rule_name": rule.rule_name if rule else f"rule {rule_id}",
            "vendor_type": rule.vendor_type if rule else None,
            "device": dev_name(rule.device_id) if rule else "—",
            "anomaly_types": sorted({f.anomaly_type for f in flist}),
            "max_severity": worst,
            "risk_score": rr.risk_score if rr else 0,
            "risk_tier": rr.risk_tier if rr else "informational",
            "recommendation": rec or "Review and remediate per the finding evidence.",
        })
    remediation.sort(key=lambda r: (r["risk_score"], _SEV_RANK.get(r["max_severity"], 0)), reverse=True)
    for i, r in enumerate(remediation, start=1):
        r["priority"] = i

    # ── 2. Per-finding evidence (grouped by rule, same priority order) ──
    evidence: List[dict] = []
    for r in remediation:
        flist = findings_by_rule.get(r["rule_id"], [])
        rr = rule_risk.get(r["rule_id"])
        evidence.append({
            "pol": r["pol"], "rule_name": r["rule_name"], "vendor_type": r["vendor_type"],
            "device": r["device"],
            "risk_score": r["risk_score"], "risk_tier": r["risk_tier"],
            "factor_breakdown": rr.factor_breakdown if rr else None,
            "findings": [{
                "anomaly_id": f.anomaly_id, "anomaly_type": f.anomaly_type,
                "severity": f.severity_level, "detection_mode": f.detection_mode,
                "confidence": f.confidence, "description": f.description,
                "recommendation": f.recommendation,
                "related_rule": _pol(f.related_rule_id) if f.related_rule_id else None,
            } for f in sorted(flist, key=lambda x: _SEV_RANK.get(x.severity_level, 0), reverse=True)],
        })

    # ── 3. Risk posture ──
    tier_counts: Dict[str, int] = {}
    for rr in rule_risk.values():
        tier_counts[rr.risk_tier] = tier_counts.get(rr.risk_tier, 0) + 1
    device_rows = []
    for did, dr in sorted(device_risk.items(), key=lambda kv: kv[1].risk_score, reverse=True):
        d = devices.get(did)
        device_rows.append({
            "device": dev_name(did), "vendor_type": d.vendor_type if d else None,
            "firmware": d.firmware_version if d else None,
            "risk_score": dr.risk_score, "risk_tier": dr.risk_tier,
            "factor_breakdown": dr.factor_breakdown,
        })

    # ── 4. Firmware CVEs (device axis; benchmark-excluded) ──
    firmware_cves = _firmware_cves(db, device_ids=None, device_risk=device_risk)

    total_findings = sum(len(v) for v in findings_by_rule.values())
    document = {
        "title": "LuminaFPM SOC Report — Executive",
        "scope": "executive",
        "analysis_run_id": run_id,
        "totals": {
            "open_findings": total_findings,
            "rules_with_findings": len(findings_by_rule),
            "rules_scored": len(rule_risk),
            "devices": len(device_risk),
            "tier_counts": tier_counts,
        },
        "remediation": remediation,
        "evidence": evidence,
        "risk_posture": {"tier_counts": tier_counts, "devices": device_rows},
        "firmware_cves": firmware_cves,
    }

    # ── Deterministic Markdown (tables only; the AI summary is prepended by reporter) ──
    md: List[str] = []
    t = document["totals"]
    md.append(f"_Analysis run #{run_id} · {t['open_findings']} findings across "
              f"{t['rules_with_findings']} rules · {t['devices']} devices · "
              f"risk tiers {t['tier_counts']}_\n")

    md.append("## Prioritized Remediation\n")
    md.append(_md_table(
        ["#", "Rule", "Device", "Vendor", "Anomalies", "Severity", "Risk", "Recommendation"],
        [[r["priority"], f"{r['pol']} {r['rule_name']}", r["device"], r["vendor_type"] or "—",
          ", ".join(r["anomaly_types"]), r["max_severity"], f"{r['risk_score']} ({r['risk_tier']})",
          r["recommendation"]] for r in remediation]) + "\n")

    md.append("## Risk Posture\n")
    md.append(_md_table(
        ["Device", "Vendor", "Firmware", "Risk", "Tier", "Factors"],
        [[d["device"], d["vendor_type"] or "—", d["firmware"] or "—", d["risk_score"],
          d["risk_tier"], ", ".join(f"{k} {v}" for k, v in (d["factor_breakdown"] or {}).items())]
         for d in device_rows]) + "\n")

    # Firmware before Per-Finding Evidence to match the on-screen DocumentView and the PDF order.
    if firmware_cves:
        md.append("## Firmware Vulnerabilities (device axis · excluded from the config benchmark)\n")
        for fc in firmware_cves:
            md.append(f"### {fc['device']} — {fc['vendor_type']} {fc['firmware']} "
                      f"(+{fc['firmware_modifier']} risk)\n")
            md.append(_md_table(
                ["CVE", "Severity", "Provider", "Summary"],
                [[c["reference"], c["severity"], c["provider"], c["summary"]] for c in fc["cves"]]) + "\n")

    md.append("## Per-Finding Evidence\n")
    for e in evidence:
        md.append(f"### {e['pol']} {e['rule_name']} — risk {e['risk_score']} ({e['risk_tier']})\n")
        md.append(_md_table(
            ["anomaly_id", "type", "severity", "mode", "recommendation"],
            [[f["anomaly_id"], f["anomaly_type"], f["severity"], f["detection_mode"],
              f["recommendation"] or "—"] for f in e["findings"]]) + "\n")

    return document, "\n".join(md)


def build_rule_document(db: Session, rule_id: int, run_id: int) -> Tuple[dict, str]:
    """Return (document, markdown) for a single-rule SOC report — same shape as the
    executive document (so the UI/Markdown/PDF render it identically), scoped to one rule."""
    rule = db.query(models.PolicyRule).filter(models.PolicyRule.rule_id == rule_id).first()
    if rule is None:
        raise ValueError(f"rule {rule_id} not found")
    device = db.query(models.FirewallDevice).filter(
        models.FirewallDevice.device_id == rule.device_id).first()
    dev_name = device.hostname if device else str(rule.device_id)

    flist = db.query(models.RuleAnomaly).filter(
        models.RuleAnomaly.rule_id == rule_id,
        models.RuleAnomaly.analysis_run_id == run_id).all()
    flist.sort(key=lambda x: _SEV_RANK.get(x.severity_level, 0), reverse=True)
    rr = db.query(models.RiskAssessment).filter(
        models.RiskAssessment.scope_type == "rule", models.RiskAssessment.scope_id == rule_id,
        models.RiskAssessment.analysis_run_id == run_id).first()
    dr = db.query(models.RiskAssessment).filter(
        models.RiskAssessment.scope_type == "device", models.RiskAssessment.scope_id == rule.device_id,
        models.RiskAssessment.analysis_run_id == run_id).first()

    worst = _worst([f.severity_level for f in flist])
    rec = next((f.recommendation for f in flist if f.recommendation), None)
    risk_score = rr.risk_score if rr else 0
    risk_tier = rr.risk_tier if rr else "informational"

    remediation = [{
        "priority": 1, "rule_id": rule_id, "pol": _pol(rule_id), "rule_name": rule.rule_name,
        "vendor_type": rule.vendor_type, "device": dev_name,
        "anomaly_types": sorted({f.anomaly_type for f in flist}), "max_severity": worst,
        "risk_score": risk_score, "risk_tier": risk_tier,
        "recommendation": rec or "Review per the finding evidence.",
    }] if flist else []

    evidence = [{
        "pol": _pol(rule_id), "rule_name": rule.rule_name, "vendor_type": rule.vendor_type,
        "device": dev_name, "risk_score": risk_score, "risk_tier": risk_tier,
        "factor_breakdown": rr.factor_breakdown if rr else None,
        "findings": [{
            "anomaly_id": f.anomaly_id, "anomaly_type": f.anomaly_type,
            "severity": f.severity_level, "detection_mode": f.detection_mode,
            "confidence": f.confidence, "description": f.description,
            "recommendation": f.recommendation,
            "related_rule": _pol(f.related_rule_id) if f.related_rule_id else None,
        } for f in flist],
    }]

    device_rows = [{
        "device": dev_name, "vendor_type": device.vendor_type if device else None,
        "firmware": device.firmware_version if device else None,
        "risk_score": dr.risk_score, "risk_tier": dr.risk_tier,
        "factor_breakdown": dr.factor_breakdown,
    }] if dr else []
    firmware_cves = _firmware_cves(db, device_ids=[rule.device_id],
                                   device_risk={rule.device_id: dr} if dr else {})

    document = {
        "title": f"LuminaFPM SOC Report — Rule {_pol(rule_id)} {rule.rule_name}",
        "scope": "rule", "analysis_run_id": run_id,
        "totals": {"open_findings": len(flist), "rules_with_findings": 1 if flist else 0,
                   "rules_scored": 1, "devices": 1, "tier_counts": {risk_tier: 1}},
        "remediation": remediation, "evidence": evidence,
        "risk_posture": {"tier_counts": {risk_tier: 1}, "devices": device_rows},
        "firmware_cves": firmware_cves,
    }

    md: List[str] = []
    md.append(f"_Rule {_pol(rule_id)} '{rule.rule_name}' ({rule.vendor_type}, {dev_name}, "
              f"action={rule.action}) · risk {risk_score} ({risk_tier}) · {len(flist)} findings_\n")
    if flist:
        md.append("## Findings\n")
        md.append(_md_table(
            ["anomaly_id", "type", "severity", "mode", "recommendation"],
            [[f.anomaly_id, f.anomaly_type, f.severity_level, f.detection_mode, f.recommendation or "—"]
             for f in flist]) + "\n")
    else:
        md.append("_No findings for this rule._\n")
    if rr and rr.factor_breakdown:
        md.append("## Risk Factors\n")
        md.append(_md_table(["factor", "points"],
                            [[k, v] for k, v in rr.factor_breakdown.items()]) + "\n")
    if firmware_cves:
        md.append("## Device Firmware Vulnerabilities (device axis · excluded from the config benchmark)\n")
        for fc in firmware_cves:
            md.append(_md_table(
                ["CVE", "Severity", "Provider", "Summary"],
                [[c["reference"], c["severity"], c["provider"], c["summary"]] for c in fc["cves"]]) + "\n")

    return document, "\n".join(md)
