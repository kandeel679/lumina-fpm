"""LTI dark-web + clearnet source registry.

Replaces Robin's generic (and largely dead) DEFAULT_SEARCH_ENGINES list with a
curated, scope-relevant set validated for the firewall threat-intel domain
(Palo Alto PAN-OS, Fortinet FortiOS/FortiGate, Cisco ASA) across the five
categories: exploit, credential, c2, ransomware, iab.

Lives entirely in LTI — Robin is not modified. LTI's scraper uses
SEARCH_ENGINES here via Robin's per-endpoint fetcher.

Source set validated 2026-06-03. `believed_live=True` means the address is
currently published by an official/current tracker, not a live Tor probe.

SAFETY/LEGAL: read-only OSINT only. Never authenticate, post, purchase, contact
actors, or download leaked data. Group B sites are high legal/LE/honeypot risk —
metadata-only.
"""
from __future__ import annotations

# ── Group A: dark-web SEARCH ENGINES (keyword discovery; {query} placeholder) ──
# These replace Robin's DEFAULT_SEARCH_ENGINES. Used by scraper/engine.py.
SEARCH_ENGINES: list[dict] = [
    {"name": "Ahmia", "url": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}", "believed_live": True},
    {"name": "Haystak", "url": "http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/?q={query}&offset=0", "believed_live": True},
    {"name": "Torch", "url": "http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion/cgi-bin/omega/omega?P={query}", "believed_live": True},
    {"name": "OnionLand", "url": "http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={query}&page=1", "believed_live": True},
    {"name": "Not Evil", "url": "http://notevil2ebbr5xjww6nryjta7bycbriyi2vh7an3wcuovlznvobykmad.onion/index.php?q={query}", "believed_live": True},
    {"name": "Tor66", "url": "http://tor66sewebgixwhcqfnp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/search?q={query}&sorttype=rel&page=1", "believed_live": True},
    {"name": "TorDex", "url": "http://tordexv4iie7z2wcgkhrnhezrx3pz5cobq3df74rdnmdwhtxkevqbsad.onion/search?query={query}&page=1", "believed_live": True},
    {"name": "Onion Search Engine", "url": "http://37djl2wrgdzfwrgv5d7vr66swizydzt6qraecg3kpxuebgb5gsvc6eid.onion/api.php?q={query}", "believed_live": True},
]

# Backward-compatible flat list (same shape Robin exposed)
DEFAULT_SEARCH_ENGINES: list[str] = [e["url"] for e in SEARCH_ENGINES]


# ── Group B: curated direct .onion SOURCES (browsed/monitored, not searched) ──
# Tagged by category. `live` is best-effort. These are monitored for victim/
# listing metadata only.
CURATED_ONION_SOURCES: list[dict] = [
    {"name": "XSS forum", "url": "http://xssforum7mmh3n56inuf2h73hvhnzobi7h2ytb3gvklrfqm7ut3xdnyd.onion/", "categories": ["exploit", "credential", "iab", "c2"], "access": "browse", "live": "uncertain"},
    {"name": "Exploit.in", "url": "http://exploitivzcm5dawzhe6c32bbylyggbjvh5dyvsvb5lkuz5ptmunkmqd.onion/", "categories": ["exploit", "iab", "credential"], "access": "browse", "live": "uncertain"},
    {"name": "Recon market search", "url": "http://recon222tttn4ob7ujdhbn3s4gjre7netvzybuvbq2bcqwltkiqinhad.onion/search?query={query}", "categories": ["credential", "iab"], "access": "search", "live": "yes"},
    {"name": "Dread", "url": "http://dreadyj7l26jqvyk3xycgljkkagc32x2y5urlcse3qocylzn53oj2byd.onion/", "categories": ["iab", "credential", "ransomware"], "access": "browse", "live": "uncertain"},
    {"name": "Akira DLS", "url": "http://akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion/", "categories": ["ransomware", "credential", "iab"], "access": "browse", "live": "yes"},
    {"name": "Qilin DLS", "url": "http://kbsqoivihgdmwczmxkbovk7ss2dcynitwhhfu5yw725dboqo5kthfaad.onion/", "categories": ["ransomware", "credential"], "access": "browse", "live": "yes"},
    {"name": "DragonForce DLS", "url": "http://z3wqggtxft7id3ibr7srivv5gjof5fwg76slewnzwwakjuf3nlhukdid.onion/", "categories": ["ransomware", "credential"], "access": "browse", "live": "yes"},
    {"name": "Lynx DLS", "url": "http://lynxblogxstgzsarfyk2pvhdv45igghb4zmthnzmsipzeoduruz3xwqd.onion/", "categories": ["ransomware", "iab"], "access": "browse", "live": "yes"},
    {"name": "Interlock DLS", "url": "http://ebhmkoohccl45qesdbvrjqtyro2hmhkmh6vkyfyjjzfllm3ix72aqaid.onion/leaks.php", "categories": ["ransomware", "credential"], "access": "browse", "live": "yes"},
    {"name": "Everest DLS", "url": "http://ransomocmou6mnbquqz44ewosbkjk3o5qjsl3orawojexfook2j7esad.onion/", "categories": ["ransomware", "credential"], "access": "browse", "live": "yes"},
    {"name": "ShinyHunters DLS", "url": "http://shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid.onion/", "categories": ["credential", "ransomware"], "access": "browse", "live": "yes"},
]


# ── Group C: CLEARNET threat-intel feeds (no Tor; reliable, structured) ──
# HIGH VALUE: deterministic, no LLM needed for the CVE baseline, no content
# blocking, scoped to the firewall vendors. Recommended as the next integration
# (a non-LLM connector that seeds findings before any dark-web scraping).
# {vendor} keys: pan_os / fortios / cisco_asa.
CLEARNET_FEEDS: dict[str, dict] = {
    "nvd": {
        "categories": ["exploit"],
        "auth": None,
        "urls": {
            "pan_os": "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:o:paloaltonetworks:pan-os",
            "fortios": "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:o:fortinet:fortios",
            "cisco_asa": "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:o:cisco:adaptive_security_appliance_software",
        },
    },
    "cisa_kev": {
        "categories": ["exploit", "ransomware"],
        "auth": None,
        "urls": {"all": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"},
        "filter": {"vendorProject/product": ["Palo Alto Networks/PAN-OS", "Fortinet/FortiOS", "Fortinet/FortiGate", "Cisco/Adaptive Security Appliance", "Cisco/ASA"]},
    },
    "palo_alto_psirt": {"categories": ["exploit"], "auth": None, "urls": {"pan_os": "https://security.paloaltonetworks.com/json?product=PAN-OS&sort=-updated"}},
    "fortinet_psirt": {"categories": ["exploit"], "auth": None, "urls": {"fortios": "https://fortiguard.fortinet.com/psirt?product=FortiOS", "rss": "https://fortiguard.fortinet.com/rss/ir.xml"}},
    "cisco_psirt": {"categories": ["exploit"], "auth": "bearer", "urls": {"cisco_asa": "https://apix.cisco.com/security/advisories/v2/product?product=Cisco%20Secure%20Firewall%20Adaptive%20Security%20Appliance%20Software&summaryDetails=true&productNames=true", "browse": "https://sec.cloudapps.cisco.com/security/center/publicationListing.x?search=Adaptive%20Security%20Appliance%20ASA"}},
    "exploit_db": {"categories": ["exploit"], "auth": None, "urls": {"pan_os": "https://www.exploit-db.com/search?text=PAN-OS", "fortios": "https://www.exploit-db.com/search?text=FortiGate", "cisco_asa": "https://www.exploit-db.com/search?text=Cisco%20ASA"}},
    "github_poc": {"categories": ["exploit"], "auth": "optional", "urls": {
        "pan_os": "https://github.com/search?q=%28PAN-OS+OR+PANOS+OR+GlobalProtect%29+%28CVE+OR+PoC+OR+exploit%29&type=repositories&s=updated&o=desc",
        "fortios": "https://github.com/search?q=%28FortiOS+OR+FortiGate+OR+Fortinet%29+%28CVE+OR+PoC+OR+exploit%29&type=repositories&s=updated&o=desc",
        "cisco_asa": "https://github.com/search?q=%28%22Cisco+ASA%22+OR+%22Adaptive+Security+Appliance%22%29+%28CVE+OR+PoC+OR+exploit%29&type=repositories&s=updated&o=desc"}},
    "threatfox": {"categories": ["c2", "ransomware"], "auth": "api_key", "urls": {"api": "https://threatfox-api.abuse.ch/api/v1/"}, "tags": ["Fortinet", "FortiGate", "PAN-OS", "PaloAlto", "CiscoASA"]},
    "ransomware_live": {"categories": ["ransomware", "credential"], "auth": None, "urls": {
        "pan": "https://api.ransomware.live/v2/searchvictims/Palo%20Alto",
        "fortinet": "https://api.ransomware.live/v2/searchvictims/Fortinet",
        "cisco_asa": "https://api.ransomware.live/v2/searchvictims/Cisco%20ASA"}},
}


def search_engine_urls() -> list[str]:
    """Live group-A search engine URL templates (with {query})."""
    return [e["url"] for e in SEARCH_ENGINES if e.get("believed_live")]
