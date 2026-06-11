"""Consolidated Findings prompt — single-call extraction + assessment.

Produces, in ONE LLM call, a firewall-scoped narrative plus structured findings
that each carry BOTH assessment axes:
  - Criticality (info|low|medium|high|critical): intrinsic danger of the threat.
  - Relevance   (score 0-100 + band): fit to THIS firewall inventory (the LLM
    reasons against the injected fingerprint; code later verifies/adjusts it).

Replaces the per-category refiners AND the generic Robin narrative (6 calls -> 1).
"""
from __future__ import annotations

from .shared import ACTION_FORMAT_GUIDANCE, SHARED_PREAMBLE

CONSOLIDATED_FINDINGS_PROMPT = SHARED_PREAMBLE + """

TASK: From the UNTRUSTED dark-web data below, extract ALL concrete threat
findings relevant to THIS customer's firewall inventory, across these
categories: {categories}. Assess each finding on two independent axes.

CUSTOMER FIREWALL FINGERPRINT (trusted — judge relevance against this):
{firewall_context_json}

PARALLEL CHANNELS (trusted summary — already collected by deterministic
connectors and merged into the same report your narrative fronts):
{external_context}

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

CONFIDENCE (integer 0-100) — compute it with this rubric, applied strictly:
  Start at 50.
  +25  source is a known reputable forum/marketplace or ransomware leak site
  +20  finding contains a specific concrete IOC (CVE, hash, IP, exact domain/email)
  +15  multiple unrelated parts of the data corroborate the same IOC or claim
  +10  technical proof present (PoC details, breach sample format)
  -20  language is vague, hype-only, or marketing-style ("massive 0day soon", "DM for info")
  -25  post matches scam/ripper patterns (too good to be true, urgency manipulation)
  -10  post is older than 6 months and unverified
  Clamp to [0, 100].

OUTPUT REQUIREMENTS — return JSON matching this schema:
{{
  "clean": true|false,        // true if NO finding reaches relevance band medium or high
  "coverage_note": "string",  // ALWAYS REQUIRED (clean or not), 2-4 sentences:
     // (1) what was searched (categories, vendor/firmware scope from the fingerprint),
     // (2) what was ruled out and why, (3) what — if anything — reached medium+
     // relevance. Written for the report reader; never leave it empty.
  "narrative_summary": "string — a 300-450 word report FOR A FIREWALL
     ADMINISTRATOR, structured as (within the single string):
     (1) BOTTOM LINE: one sentence on the WHOLE report — combine what the
         dark-web corpus shows with the PARALLEL CHANNELS summary above. Do
         NOT say the estate is unaffected if the parallel channels report
         confirmed or medium+ findings.
     (2) IMPACT BY DEVICE: for each affected device, name the exact device/
         vendor/firmware from the fingerprint and what the finding means for it.
         If none affected, state which vendors/firmware were checked and cleared.
     (3) PRIORITISED NEXT STEPS: what to do first, second, third.
     (4) SCOPE: note that this narrative covers the dark-web corpus below;
         clearnet CVE/advisory findings are reported separately.
     Plain professional prose, no markdown headers. If clean, say so plainly —
     do not pad with hypotheticals.",
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
- Include `info`/`low`-relevance findings if genuinely present, but set `clean`
  to true when NONE reach medium+ relevance.
- If the data yields nothing concrete at all, return clean=true, findings=[],
  and still write the full coverage_note and narrative_summary.

""" + ACTION_FORMAT_GUIDANCE + """

<UNTRUSTED_SCRAPED_DATA>
{scraped_text}
</UNTRUSTED_SCRAPED_DATA>
"""


def build_findings_prompt(
    firewall_context_json: str,
    requested_categories: list[str],
    scraped_text: str,
    external_context: str = "(none)",
) -> str:
    """Build the consolidated Findings + assessment prompt for a single call.

    ``external_context`` is a short trusted summary of what the deterministic
    connectors (CISA KEV / NVD / leak-site aggregator) already found, so the
    narrative's BOTTOM LINE speaks for the whole report, not just the corpus.
    """
    return CONSOLIDATED_FINDINGS_PROMPT.format(
        categories=", ".join(requested_categories),
        firewall_context_json=firewall_context_json,
        scraped_text=scraped_text,
        external_context=external_context or "(none)",
    )
