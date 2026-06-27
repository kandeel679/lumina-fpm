"""Prompt templates + evidence rendering (Volume 10 §7, §9) — pure.

The system prompt is the guardrail: use ONLY supplied evidence, never invent CVEs/
exploits/provider results/remediations, separate evidence from interpretation. The
user prompt embeds the deterministic evidence with its DB IDs so every claim is
traceable.
"""
from __future__ import annotations

from typing import Dict

PROMPT_VERSION = "soc-report/2.1"

SYSTEM_PROMPT = (
    "You are a cybersecurity analyst assistant for LuminaFPM, a READ-ONLY firewall "
    "policy analysis platform. Use ONLY the evidence supplied in the user message. "
    "Do NOT invent CVEs, exploit claims, threat-intel verdicts, IP reputations, or "
    "remediation actions that are not supported by that evidence. Clearly SEPARATE "
    "evidence (deterministic engine findings, risk scores, and CTI provider results) "
    "from your INTERPRETATION. Attribute every threat-intel claim to its provider. "
    "The deterministic engine — not you — decides what is an anomaly; your job is to "
    "explain and prioritize. "
    "OUTPUT FORMAT: write PROSE ONLY — do NOT use markdown tables, pipe characters, or "
    "column layouts; the structured findings tables are rendered separately below your "
    "summary. Refer to each finding by its human-readable name (the anomaly type plus its "
    "policy/device, e.g. \"the unprotected allow on POL-037, FGT-LAB\"), NOT by raw numeric "
    "IDs. The bracketed IDs in the evidence are internal grounding anchors only — never print "
    "them in the report. Write a concise, professional SOC report."
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
        "TASK: Write a CONCISE analytical SUMMARY of this rule's risk (2-4 short paragraphs): "
        "what the rule allows, why it is risky, and how urgently to fix it — referring to each "
        "finding by its anomaly type and this rule's policy/device, NOT by raw IDs. The per-finding "
        "details and recommendations are TABULATED BELOW this summary, so synthesize rather than "
        "restate every row. PROSE ONLY — no markdown tables or pipes. Use ONLY the evidence above; "
        "do not invent findings/CVEs/remediations."
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
        "fixed first and why (name them by policy/device), any firmware-vulnerability exposure, "
        "and the recurring themes (e.g. unprotected allows, missing logging, overly permissive "
        "rules). PROSE ONLY — no markdown tables or pipes; refer to findings by name, not IDs. Use "
        "ONLY the evidence above; do NOT invent findings, CVEs, or remediations. This summary sits "
        "ABOVE the deterministic remediation/evidence tables, so do not restate every row — synthesize."
    )
    return "\n".join(lines)
