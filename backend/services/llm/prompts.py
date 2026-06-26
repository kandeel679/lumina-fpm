"""Prompt templates + evidence rendering (Volume 10 §7, §9) — pure.

The system prompt is the guardrail: use ONLY supplied evidence, never invent CVEs/
exploits/provider results/remediations, separate evidence from interpretation. The
user prompt embeds the deterministic evidence with its DB IDs so every claim is
traceable.
"""
from __future__ import annotations

from typing import Dict

PROMPT_VERSION = "soc-report/2.0"

SYSTEM_PROMPT = (
    "You are a cybersecurity analyst assistant for LuminaFPM, a READ-ONLY firewall "
    "policy analysis platform. Use ONLY the evidence supplied in the user message. "
    "Do NOT invent CVEs, exploit claims, threat-intel verdicts, IP reputations, or "
    "remediation actions that are not supported by that evidence. Clearly SEPARATE "
    "evidence (deterministic engine findings, risk scores, and CTI provider results, "
    "each with an ID) from your INTERPRETATION. Attribute every threat-intel claim to "
    "its provider. The deterministic engine — not you — decides what is an anomaly; "
    "your job is to explain and prioritize. Write a concise, professional SOC report."
)


def _fmt_findings(findings) -> str:
    if not findings:
        return "  (none)\n"
    lines = []
    for f in findings:
        lines.append(
            f"  - [anomaly_id={f['anomaly_id']}] {f['anomaly_type']} "
            f"(severity={f['severity']}, mode={f['detection_mode']}): {f['description']}"
        )
    return "\n".join(lines) + "\n"


def _fmt_cti(cti) -> str:
    if not cti:
        return "  (none)\n"
    lines = []
    for c in cti:
        lines.append(
            f"  - [observation_id={c['observation_id']}] indicator {c['value']} — "
            f"provider={c['provider']}, threat_type={c['threat_type']}, "
            f"severity={c['severity']}, confidence={c['confidence']}: {c['summary']}"
        )
    return "\n".join(lines) + "\n"


def render_rule_prompt(ctx: Dict) -> str:
    r = ctx["rule"]
    risk = ctx.get("risk") or {}
    return (
        f"SCOPE: rule '{r['rule_name']}' ({r['vendor_type']}, device {r['device_id']}, "
        f"action={r['action']})\n\n"
        f"RISK [risk_id={risk.get('risk_id')}]: score={risk.get('risk_score')} "
        f"tier={risk.get('risk_tier')}; factors={risk.get('factor_breakdown')}\n\n"
        f"DETERMINISTIC FINDINGS (the engine's authoritative output):\n"
        f"{_fmt_findings(ctx.get('findings', []))}\n"
        f"CTI PROVIDER EVIDENCE (separate from the engine):\n"
        f"{_fmt_cti(ctx.get('cti', []))}\n"
        "TASK: Write a SOC technical report for this rule with sections: "
        "1) Summary, 2) Why it is risky (cite the anomaly_id / risk_id / observation_id "
        "evidence above), 3) Recommended remediation (grounded ONLY in the evidence). "
        "Label your prose as analysis, not new evidence."
    )


def render_executive_prompt(ctx: Dict) -> str:
    lines = [
        f"SCOPE: executive summary for analysis run {ctx.get('analysis_run_id')}",
        f"\nTOTALS: {ctx.get('total_findings')} findings; risk tiers={ctx.get('tier_counts')}",
        f"\nTOP RULES TO FIX FIRST (already prioritized by risk):",
    ]
    for t in ctx.get("top_rules", []):
        lines.append(f"  - {t['rule_name']} ({t['vendor_type']}): {t['risk_score']} {t['risk_tier']}")
    fw = ctx.get("firmware_cves", [])
    if fw:
        lines.append("\nFIRMWARE VULNERABILITIES (device axis):")
        for f in fw:
            lines.append(f"  - {f['device']} ({f['firmware']}): {', '.join(f['cves'])}")
    lines.append(
        "\nTASK: Write a concise, professional EXECUTIVE SUMMARY (3-5 short paragraphs, no "
        "jargon) of the firewall posture: the overall risk picture, the few rules that must be "
        "fixed first and why, any firmware-vulnerability exposure, and the recurring themes "
        "(e.g. unprotected allows, missing logging, overly permissive rules). Use ONLY the "
        "evidence above; do NOT invent findings, CVEs, or remediations. This summary sits ABOVE "
        "the deterministic remediation/evidence tables, so do not restate every row — synthesize."
    )
    return "\n".join(lines)
