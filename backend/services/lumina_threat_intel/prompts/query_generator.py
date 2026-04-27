"""Query generator prompt — converts firewall keywords into dark-web search queries."""
from __future__ import annotations

from .shared import SHARED_PREAMBLE

QUERY_GENERATOR_PROMPT = SHARED_PREAMBLE + """\

TASK: Convert the customer's firewall keywords into dark-web search queries.

INPUT FORMAT (JSON):
{{
  "firmwares": [...],          // e.g. ["PAN-OS 10.2.3", "FortiOS 7.4.1"]
  "vendors_models": [...],     // e.g. ["Palo Alto PA-3220"]
  "cves": [...],               // e.g. ["CVE-2024-3400"]
  "org_domains": [...]         // e.g. ["acme-corp.com"]
}}

RULES FOR QUERY GENERATION:
- Generate queries scoped to EXACTLY these 5 categories:
  * exploit       — exploits, 0-days, PoCs targeting the firmware/vendor
  * credential    — leaked admin credentials tied to org_domains
  * c2            — malicious infrastructure (rare for this input — only if
                    org domains hint at a known compromise; usually empty)
  * ransomware    — ransomware-group leak-site posts mentioning the org or
                    its industry-typical vendor stack
  * iab           — initial-access-broker listings selling access to firewalls
                    of the given vendor/model

- MULTIPLE queries per category are encouraged when justified by the inputs.
- Each query is <= 120 characters, plain text, no quotes, no operators.
- Do NOT invent CVE numbers, domain names, or model numbers not present in
  the input. You MAY add common synonyms (e.g., "PAN-OS" -> also try
  "Palo Alto NGFW") but only if directly derivable.
- If an input list is empty, generate no queries for the categories that
  depend on it (e.g., no org_domains -> no credential queries).

OUTPUT MUST be valid JSON matching this schema:
{{
  "queries": [
    {{"query": "string (max 120 chars)", "category": "exploit|credential|c2|ransomware|iab"}}
  ]
}}

INPUT KEYWORDS:
{keyword_bundle_json}
"""
