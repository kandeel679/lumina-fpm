"""Consolidated Findings prompt — single-call extraction + assessment.

Produces, in ONE LLM call, a firewall-scoped narrative plus structured findings
that each carry BOTH assessment axes:
  - Criticality (info|low|medium|high|critical): intrinsic danger of the threat.
  - Relevance   (score 0-100 + band): fit to THIS firewall inventory (the LLM
    reasons against the injected fingerprint; code later verifies/adjusts it).

Replaces the per-category refiners AND the generic Robin narrative (6 calls -> 1).
"""
from __future__ import annotations

from .shared import SHARED_PREAMBLE

CONSOLIDATED_FINDINGS_PROMPT = SHARED_PREAMBLE + """

TASK: From the UNTRUSTED dark-web data below, extract ALL concrete threat
findings relevant to THIS customer's firewall inventory, across these
categories: {categories}. Assess each finding on two independent axes.

CUSTOMER FIREWALL FINGERPRINT (trusted — judge relevance against this):
{firewall_context_json}

Reason about whether each finding actually pertains to the customer's vendors,
models, firmware versions, or domains above. Strongly prefer findings that
match the fingerprint; IGNORE generic dark-web chatter with no link to it.

CRITICALITY (intrinsic danger of the threat; judge WITHOUT regard to the customer):
  critical: actively-exploited RCE / auth-bypass / 0-day; verified fresh admin
            credential leak; confirmed reachable C2.
  high:     known CVE with public PoC; initial-access-broker listing; fresh
            credential dump (unverified); named ransomware victim.
  medium:   exploit chatter without PoC; old credential mention; vendor-targeted
            ransomware chatter.
  low:      vague / indirect mention; scam-pattern post.
  info:     background context only, no actionable threat.

RELEVANCE (fit to THIS inventory; score 0-100 and band it). Reason briefly:
  high   (75-100): vendor+model+firmware match, OR an org_domain match, OR an
                   IOC an exposed rule would plausibly allow.
  medium (40-74):  vendor+model OR vendor+firmware match (exposure unconfirmed).
  low    (10-39):  vendor only, or industry/geo match.
  none   (0-9):    no link to the inventory.
  Put the 1-2 deciding facts in relevance_reason
  (e.g. "FortiOS 7.4.3 matches device FG-HQ-CORE-01").

CONFIDENCE (0-100): how strongly the data supports the finding (specific IOCs,
reputable source, corroboration raise it; vague/hype/scam patterns lower it).

OUTPUT REQUIREMENTS — return JSON matching this schema:
{{
  "clean": true|false,        // true if NO finding reaches relevance band medium or high
  "coverage_note": "string",  // if clean: what was searched and ruled out (for the report)
  "narrative_summary": "string — concise (<=250 words) summary FOR A FIREWALL
     ADMINISTRATOR: what was found that affects THEIR specific devices/firmware
     and what to prioritise. Reference vendors/firmware from the fingerprint by
     name. If clean, say so plainly.",
  "findings": [
    {{
      "category": "exploit|credential|c2|ransomware|iab",
      "criticality": "info|low|medium|high|critical",
      "relevance_score": 0-100,
      "relevance_band": "none|low|medium|high",
      "relevance_reason": "string (the deciding facts)",
      "confidence": 0-100,
      "title": "string (max 512 chars)",
      "description": "string",
      "iocs": [{{"type": "ipv4|ipv6|domain|url|sha256|md5|sha1|cve|email|wallet|username|asn", "value": "string"}}],
      "source": {{
        "onion_url": "string or null",
        "search_engine": null,
        "scraped_at": null,
        "raw_excerpt": "string (max 500 chars, verbatim from data)",
        "page_title": "string or null",
        "marketplace_or_forum": "string or null"
      }},
      "recommended_actions": ["string"],
      "tags": ["string"]
    }}
  ]
}}

RULES:
- Every IOC value MUST appear literally (case-insensitive) in the data below.
  If unsure, omit it. Do NOT invent CVEs, IPs, domains, hashes, or versions.
- source.raw_excerpt MUST be <=500 chars copied verbatim from the data.
- Use the [SOURCE_URL: ...] and [PAGE_TITLE: ...] labels to fill source fields.
- recommended_actions: short, firewall-actionable imperatives
  (e.g. "Upgrade FortiOS to 7.4.7", "Block 1.2.3.4 inbound", "Rotate admin creds").
- Include `info`/`low`-relevance findings if genuinely present, but set `clean`
  to true when NONE reach medium+ relevance.
- If the data yields nothing concrete at all, return clean=true, findings=[],
  with a coverage_note explaining what was checked.

<UNTRUSTED_SCRAPED_DATA>
{scraped_text}
</UNTRUSTED_SCRAPED_DATA>
"""


def build_findings_prompt(
    firewall_context_json: str,
    requested_categories: list[str],
    scraped_text: str,
) -> str:
    """Build the consolidated Findings + assessment prompt for a single call."""
    return CONSOLIDATED_FINDINGS_PROMPT.format(
        categories=", ".join(requested_categories),
        firewall_context_json=firewall_context_json,
        scraped_text=scraped_text,
    )
