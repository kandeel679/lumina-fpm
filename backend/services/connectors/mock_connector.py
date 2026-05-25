"""Mock Firewall Connector — generates fake normalized rules.

Produces 20 realistic-looking policy rules that strictly follow the
``policy_rule`` table schema.  This allows the backend to save
production-shaped data to Postgres without a live Palo Alto / Fortinet
device.

Replace this class with a real vendor connector (e.g.
``PaloAltoConnector``, ``FortinetConnector``) in production.
"""
from __future__ import annotations

import logging
import random
import uuid
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Realistic sample data pools
# ---------------------------------------------------------------------------
_ZONE_PAIRS = [
    ("trust", "untrust"),
    ("dmz", "untrust"),
    ("trust", "dmz"),
    ("internal", "external"),
    ("management", "untrust"),
    ("guest", "untrust"),
    ("trust", "datacenter"),
    ("vpn", "trust"),
]

_RULE_TEMPLATES = [
    {"name": "Allow-Web-Traffic",        "action": "allow",  "type": "security", "tags": "web,production",       "desc": "Allow outbound HTTP/HTTPS traffic from trust to untrust"},
    {"name": "Block-Crypto-Mining",      "action": "deny",   "type": "security", "tags": "crypto,threat",        "desc": "Block known crypto-mining pool destinations"},
    {"name": "Allow-DNS",                "action": "allow",  "type": "security", "tags": "dns,infrastructure",   "desc": "Allow DNS queries to internal and external resolvers"},
    {"name": "Allow-VPN-Access",         "action": "allow",  "type": "security", "tags": "vpn,remote-access",    "desc": "Permit inbound VPN tunnel establishment"},
    {"name": "Deny-SSH-External",        "action": "deny",   "type": "security", "tags": "ssh,hardening",        "desc": "Block SSH access from untrusted zones"},
    {"name": "Allow-SMTP-Relay",         "action": "allow",  "type": "security", "tags": "email,production",     "desc": "Allow SMTP relay to mail gateway in DMZ"},
    {"name": "Block-TOR-Exit-Nodes",     "action": "deny",   "type": "security", "tags": "tor,threat",           "desc": "Block traffic to known Tor exit nodes"},
    {"name": "Allow-ICMP-Monitoring",    "action": "allow",  "type": "security", "tags": "monitoring,icmp",      "desc": "Allow ICMP echo for network monitoring"},
    {"name": "Allow-DB-Access",          "action": "allow",  "type": "security", "tags": "database,internal",    "desc": "Allow PostgreSQL/MySQL access from app servers"},
    {"name": "Deny-All-Default",         "action": "deny",   "type": "security", "tags": "default,cleanup",      "desc": "Implicit deny-all cleanup rule"},
    {"name": "Allow-LDAP-Auth",          "action": "allow",  "type": "security", "tags": "ldap,auth",            "desc": "Allow LDAP/AD authentication traffic"},
    {"name": "Allow-NTP-Sync",           "action": "allow",  "type": "security", "tags": "ntp,infrastructure",   "desc": "Allow NTP time synchronization"},
    {"name": "Block-P2P-Traffic",        "action": "deny",   "type": "security", "tags": "p2p,policy",           "desc": "Block peer-to-peer file sharing protocols"},
    {"name": "Allow-Backup-Replication", "action": "allow",  "type": "security", "tags": "backup,datacenter",    "desc": "Allow backup replication between datacenters"},
    {"name": "Allow-API-Gateway",        "action": "allow",  "type": "security", "tags": "api,production",       "desc": "Allow traffic to public API gateway"},
    {"name": "Deny-Telnet",             "action": "deny",   "type": "security", "tags": "telnet,hardening",     "desc": "Block Telnet — use SSH instead"},
    {"name": "Allow-SNMP-Polling",       "action": "allow",  "type": "security", "tags": "snmp,monitoring",      "desc": "Allow SNMP polling from management station"},
    {"name": "Allow-RADIUS-Auth",        "action": "allow",  "type": "security", "tags": "radius,auth",          "desc": "Allow RADIUS authentication traffic"},
    {"name": "Block-Malware-C2",         "action": "deny",   "type": "security", "tags": "malware,threat",       "desc": "Block known malware C2 callback domains"},
    {"name": "Allow-Updates",            "action": "allow",  "type": "security", "tags": "updates,maintenance",  "desc": "Allow OS/firmware update traffic"},
]

_SECURITY_PROFILES = [
    "strict-security",
    "standard-security",
    "monitoring-only",
    "threat-prevention",
    None,
]

_LOG_SETTINGS = [
    "default",
    "send-to-siem",
    "local-only",
    "high-fidelity",
]

_VENDOR_TYPES = ["paloalto", "fortinet"]


class MockFirewallConnector:
    """Mock connector that produces normalised firewall rules.

    Usage::

        connector = MockFirewallConnector()
        rules = connector.fetch_normalized_rules(device_id=1)
        # -> list of 20 dicts matching the policy_rule table schema
    """

    def fetch_normalized_rules(self, device_id: int) -> List[Dict[str, Any]]:
        """Return 20 fake normalised rules for the given device.

        Each dict is ready to be unpacked into a ``PolicyRule(**rule)``
        constructor — field names match the SQLAlchemy model exactly.
        """
        logger.info(
            "MockFirewallConnector: generating 20 normalised rules "
            "for device_id=%d",
            device_id,
        )

        vendor_type = random.choice(_VENDOR_TYPES)
        vdom_vsys = "vsys1" if vendor_type == "paloalto" else "root"

        rules: List[Dict[str, Any]] = []

        for order, template in enumerate(_RULE_TEMPLATES, start=1):
            src_zone, dst_zone = random.choice(_ZONE_PAIRS)

            rule: Dict[str, Any] = {
                "device_id": device_id,
                "vendor_rule_id": f"R-{order:03d}",
                "vendor_uuid": str(uuid.uuid4()),
                "vendor_type": vendor_type,
                "vdom_vsys": vdom_vsys,
                "rule_name": template["name"],
                "rule_order": order,
                "action": template["action"],
                "is_active": random.choices([True, False], weights=[90, 10])[0],
                "src_zone_interface": src_zone,
                "dst_zone_interface": dst_zone,
                "rule_type": template["type"],
                "tags": template["tags"],
                "src_negate": random.choices([False, True], weights=[95, 5])[0],
                "dst_negate": random.choices([False, True], weights=[95, 5])[0],
                "nat_enabled": random.choices([False, True], weights=[80, 20])[0],
                "log_setting": random.choice(_LOG_SETTINGS),
                "security_profile_group": random.choice(_SECURITY_PROFILES),
                "schedule_name": "always",
                "description": template["desc"],
            }
            rules.append(rule)

        logger.info(
            "MockFirewallConnector: generated %d rules for device_id=%d",
            len(rules),
            device_id,
        )
        return rules
