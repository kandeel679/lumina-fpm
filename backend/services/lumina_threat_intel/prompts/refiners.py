"""Refiner prompt base template and category-specific guidance blocks."""
from __future__ import annotations

from .shared import SHARED_PREAMBLE, CONFIDENCE_RUBRIC, SEVERITY_GUIDANCE

# ---------------------------------------------------------------------------
# Base refiner template — {CATEGORY}, {CATEGORY_GUIDANCE}, {keyword_bundle_json},
# {scraped_text}, and JSON schema are interpolated by llm_client.
# ---------------------------------------------------------------------------

REFINER_BASE_TEMPLATE = SHARED_PREAMBLE + """

TASK: Extract structured {category} findings from the scraped dark-web data
below. The customer is interested in threats matching these original
keywords (use them to filter relevance):

ORIGINAL KEYWORDS: {keyword_bundle_json}

CATEGORY-SPECIFIC EXTRACTION GUIDANCE:
{category_guidance}

""" + CONFIDENCE_RUBRIC + """

""" + SEVERITY_GUIDANCE + """

OUTPUT REQUIREMENTS:
- Return JSON matching this schema:
  {{
    "category": "{category}",
    "findings": [
      {{
        "category": "{category}",
        "severity": "critical|high|medium|low",
        "confidence": 0-100,
        "title": "string (max 512 chars)",
        "description": "string",
        "iocs": [{{"type": "ipv4|ipv6|domain|url|sha256|md5|sha1|cve|email|wallet|username|asn", "value": "string"}}],
        "source": {{
          "onion_url": "string or null",
          "search_engine": "string or null",
          "scraped_at": "ISO datetime or null",
          "raw_excerpt": "string (max 500 chars, verbatim from data)",
          "page_title": "string or null",
          "marketplace_or_forum": "string or null"
        }},
        "recommended_actions": ["string"],
        "tags": ["string"]
      }}
    ]
  }}

- Each finding's `iocs` MUST be a subset of strings literally present in the
  scraped data.
- `source.raw_excerpt` MUST be <= 500 chars and MUST be copied verbatim from
  the scraped data (this is what the post-validator checks).
- `recommended_actions` are short imperative strings, one per intended
  action (e.g., "Patch PAN-OS to 11.1.2-h3", "Block IP 1.2.3.4 inbound",
  "Rotate admin credentials for admin@acme-corp.com").
- If you cannot find any concrete {category} findings in the data, return:
  {{"category": "{category}", "findings": []}}

<UNTRUSTED_SCRAPED_DATA>
{scraped_text}
</UNTRUSTED_SCRAPED_DATA>
"""


# ---------------------------------------------------------------------------
# Category-specific guidance blocks
# ---------------------------------------------------------------------------

EXPLOIT_GUIDANCE = """\
You are extracting EXPLOITS / 0-DAYS / VULNERABILITY DISCLOSURES.
Look for:
- CVE identifiers (CVE-YYYY-NNNN format)
- Mentions of exploit kits, PoCs, weaponized vulnerabilities
- Posts on exploit-trading forums (Exploit.in, XSS, BreachForums-mirrors)
- 0-day sale listings naming the firmware vendor or version
- Patch-bypass techniques

Each finding's `title` = a one-line description like "CVE-2024-3400 PoC
circulating on Exploit.in" or "Unpatched FortiOS 7.4.1 RCE for sale".

Recommended actions: focus on patching, version upgrades, IDS signatures."""


CREDENTIAL_GUIDANCE = """\
You are extracting LEAKED CREDENTIALS relevant to the customer.
Look for:
- Email addresses on the customer's org_domains
- Admin/firewall credentials (panel logins, SSH keys, API tokens)
- Combolists, breach-dump references, paste-site mirrors
- Posts naming the customer's company, products, or domain

You MUST NOT include actual passwords or hash values in plaintext. Reference
the existence of the credential, the source, and the email/username only.
Mark severity: critical only if dump appears fresh (<=6 months) and contains
admin/privileged accounts.

Recommended actions: credential rotation, MFA enforcement, monitor SIEM for
auth attempts from leaked accounts."""


C2_GUIDANCE = """\
You are extracting COMMAND-AND-CONTROL infrastructure indicators.
Look for:
- IPs / domains tagged as malicious, C2, RAT panel, botnet node
- Threat-actor IOC dumps
- Specific malware family names + their infrastructure (e.g., "Lumma Stealer
  C2: 1.2.3.4")
- ASN-level threat reports

For every IP / domain, severity is initially `medium`; it becomes `high` if
the indicator is associated with active campaigns (mentioned in last
30 days), and `critical` only when correlation against firewall rules
shows the IOC is currently allowed by a rule (correlation step happens
AFTER your output — you cannot know it; just rank on dark-web evidence).

Recommended actions: block IP/domain on perimeter, sinkhole DNS, hunt for
beacons in NetFlow."""


RANSOMWARE_GUIDANCE = """\
You are extracting RANSOMWARE-RELATED CHATTER.
Look for:
- Customer org name on a ransomware leak site (LockBit, BlackCat, Cl0p, etc.)
- Industry-targeting posts ("we now hit healthcare in {{country}}")
- Ransomware groups discussing the customer's firewall vendor as an entry
  point
- Tor leak-site URLs, victim countdowns, sample data references

Severity: critical if the customer org appears as a named victim;
high if customer's vendor stack is named as a current target;
medium for industry-level chatter; low for generic posts.

Recommended actions: incident response activation, backup verification,
proactive threat hunt for IOCs, tabletop exercise."""


IAB_GUIDANCE = """\
You are extracting INITIAL-ACCESS-BROKER listings.
Look for:
- Forum posts selling network access to firewalls of the customer's vendor
  + model (Palo Alto, Fortinet, etc.)
- Listings mentioning specific firmware versions matching customer inventory
- Generic "VPN access" / "RDP access" / "firewall admin access" sales
  posts in customer's geography or industry

Severity: critical if the listing matches customer's exact vendor + version
+ region; high if vendor + version match; medium if vendor only; low for
generic listings.

Recommended actions: harden management plane (geo-restrict, MFA, IP allowlist),
audit recent admin auth logs, rotate admin credentials, monitor for new
admin accounts."""


# Map category enum value → guidance text
CATEGORY_GUIDANCE_MAP: dict[str, str] = {
    "exploit": EXPLOIT_GUIDANCE,
    "credential": CREDENTIAL_GUIDANCE,
    "c2": C2_GUIDANCE,
    "ransomware": RANSOMWARE_GUIDANCE,
    "iab": IAB_GUIDANCE,
}


def build_refiner_prompt(
    category: str,
    keyword_bundle_json: str,
    scraped_text: str,
) -> str:
    """Build a complete refiner prompt for the given category."""
    guidance = CATEGORY_GUIDANCE_MAP.get(category, "")
    return REFINER_BASE_TEMPLATE.format(
        category=category,
        category_guidance=guidance,
        keyword_bundle_json=keyword_bundle_json,
        scraped_text=scraped_text,
    )
