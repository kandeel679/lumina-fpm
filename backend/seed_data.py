"""
LuminaFPM — Database Seed Script
Simulates "NovaTech Solutions", a mid-size tech company with:
  - 3 firewall vendors
  - 4 administrators  
  - 5 firewall devices across HQ, branch office, and data center
  - 15 network objects (subnets, hosts, address groups)
  - 20 policy rules across devices
  - Rule-object mappings tying rules to network objects
  - 5 detected anomalies
  - 4 threat intelligence entries
  - 3 threat-rule correlations

Usage:
  Make sure the API is running (docker compose up), then:
    python seed_data.py
"""

import requests
import sys

BASE_URL = "http://localhost:8000/api/v1"


def api(method, path, json=None):
    """Helper: call the API and return the JSON response."""
    url = f"{BASE_URL}{path}"
    resp = getattr(requests, method)(url, json=json)
    if resp.status_code >= 400:
        print(f"  ✖ {method.upper()} {path} → {resp.status_code}: {resp.text}")
        sys.exit(1)
    if resp.status_code == 204:
        return None
    return resp.json()


def seed():
    print("=" * 60)
    print("  LuminaFPM — Seeding Database with NovaTech Solutions data")
    print("=" * 60)

    # ==================================================================
    # 1. VENDORS
    # ==================================================================
    print("\n🏭 Creating vendors...")
    vendors = [
        {"name": "Fortinet", "api_type": "REST", "support_contact": "support@fortinet.com"},
        {"name": "Palo Alto Networks", "api_type": "XML-API", "support_contact": "support@paloaltonetworks.com"},
        {"name": "Cisco", "api_type": "REST", "support_contact": "tac@cisco.com"},
    ]
    vendor_ids = {}
    for v in vendors:
        result = api("post", "/vendors/", v)
        vendor_ids[v["name"]] = result["vendor_id"]
        print(f"  ✔ {v['name']} (ID: {result['vendor_id']})")

    # ==================================================================
    # 2. ADMINISTRATORS
    # ==================================================================
    print("\n👤 Creating administrators...")
    admins = [
        {"first_name": "Ahmed", "last_name": "Hassan"},
        {"first_name": "Sara", "last_name": "El-Masry"},
        {"first_name": "Omar", "last_name": "Farouk"},
        {"first_name": "Nour", "last_name": "Khalil"},
    ]
    admin_ids = []
    for a in admins:
        result = api("post", "/devices/admins/", a)
        admin_ids.append(result["admin_id"])
        print(f"  ✔ {a['first_name']} {a['last_name']} (ID: {result['admin_id']})")

    # ==================================================================
    # 3. FIREWALL DEVICES
    # ==================================================================
    print("\n🔥 Creating firewall devices...")
    devices = [
        {
            "vendor_id": vendor_ids["Fortinet"],
            "hostname": "FG-HQ-EDGE-01",
            "firmware_version": "7.4.3",
            "management_ip": "10.0.1.1",
            "status": "online",
        },
        {
            "vendor_id": vendor_ids["Fortinet"],
            "hostname": "FG-HQ-CORE-01",
            "firmware_version": "7.4.3",
            "management_ip": "10.0.1.2",
            "status": "online",
        },
        {
            "vendor_id": vendor_ids["Palo Alto Networks"],
            "hostname": "PA-DC-NORTH-01",
            "firmware_version": "11.1.2",
            "management_ip": "10.10.1.1",
            "status": "online",
        },
        {
            "vendor_id": vendor_ids["Palo Alto Networks"],
            "hostname": "PA-DC-SOUTH-01",
            "firmware_version": "11.0.4",
            "management_ip": "10.10.2.1",
            "status": "degraded",
        },
        {
            "vendor_id": vendor_ids["Cisco"],
            "hostname": "ASA-BRANCH-ALEX-01",
            "firmware_version": "9.18.3",
            "management_ip": "172.16.0.1",
            "status": "online",
        },
    ]
    device_ids = {}
    for d in devices:
        result = api("post", "/devices/", d)
        device_ids[d["hostname"]] = result["device_id"]
        print(f"  ✔ {d['hostname']} ({d['management_ip']}) — {d['status']}")

    # ==================================================================
    # 4. ADMIN ↔ DEVICE ASSIGNMENTS
    # ==================================================================
    print("\n🔗 Assigning administrators to devices...")
    assignments = [
        (device_ids["FG-HQ-EDGE-01"], {"admin_id": admin_ids[0], "device_id": device_ids["FG-HQ-EDGE-01"], "role": "primary_admin"}),
        (device_ids["FG-HQ-CORE-01"], {"admin_id": admin_ids[0], "device_id": device_ids["FG-HQ-CORE-01"], "role": "primary_admin"}),
        (device_ids["PA-DC-NORTH-01"], {"admin_id": admin_ids[1], "device_id": device_ids["PA-DC-NORTH-01"], "role": "primary_admin"}),
        (device_ids["PA-DC-SOUTH-01"], {"admin_id": admin_ids[1], "device_id": device_ids["PA-DC-SOUTH-01"], "role": "primary_admin"}),
        (device_ids["ASA-BRANCH-ALEX-01"], {"admin_id": admin_ids[2], "device_id": device_ids["ASA-BRANCH-ALEX-01"], "role": "primary_admin"}),
        (device_ids["FG-HQ-EDGE-01"], {"admin_id": admin_ids[3], "device_id": device_ids["FG-HQ-EDGE-01"], "role": "backup_admin"}),
    ]
    for device_id, data in assignments:
        api("post", f"/devices/{device_id}/admins", data)
        print(f"  ✔ Admin {data['admin_id']} → Device {device_id} ({data['role']})")

    # ==================================================================
    # 5. NETWORK OBJECTS
    # ==================================================================
    print("\n🌐 Creating network objects...")
    net_objects = [
        {"name": "HQ-LAN", "type": "subnet", "value": "10.0.0.0/16"},
        {"name": "DC-SERVERS", "type": "subnet", "value": "10.10.0.0/16"},
        {"name": "BRANCH-ALEX-LAN", "type": "subnet", "value": "172.16.0.0/16"},
        {"name": "DMZ-WEB", "type": "subnet", "value": "192.168.100.0/24"},
        {"name": "DMZ-MAIL", "type": "subnet", "value": "192.168.101.0/24"},
        {"name": "DC-DB-PRIMARY", "type": "host", "value": "10.10.10.50"},
        {"name": "DC-DB-REPLICA", "type": "host", "value": "10.10.10.51"},
        {"name": "WEB-SERVER-01", "type": "host", "value": "192.168.100.10"},
        {"name": "MAIL-SERVER-01", "type": "host", "value": "192.168.101.10"},
        {"name": "AD-DC-01", "type": "host", "value": "10.0.10.5"},
        {"name": "AD-DC-02", "type": "host", "value": "10.0.10.6"},
        {"name": "CLOUDFLARE-DNS", "type": "host", "value": "1.1.1.1"},
        {"name": "GOOGLE-DNS", "type": "host", "value": "8.8.8.8"},
        {"name": "BLOCKED-C2-RANGE", "type": "subnet", "value": "185.220.100.0/24"},
        {"name": "ANY-INTERNET", "type": "wildcard", "value": "0.0.0.0/0"},
    ]
    obj_ids = {}
    for obj in net_objects:
        result = api("post", "/network-objects/", obj)
        obj_ids[obj["name"]] = result["object_id"]
        print(f"  ✔ {obj['name']} = {obj['value']} ({obj['type']})")

    # ==================================================================
    # 6. POLICY RULES
    # ==================================================================
    print("\n📋 Creating policy rules...")
    hq_edge = device_ids["FG-HQ-EDGE-01"]
    hq_core = device_ids["FG-HQ-CORE-01"]
    dc_north = device_ids["PA-DC-NORTH-01"]
    dc_south = device_ids["PA-DC-SOUTH-01"]
    branch = device_ids["ASA-BRANCH-ALEX-01"]

    rules = [
        # ---- HQ Edge Firewall (internet-facing) ----
        {"device_id": hq_edge, "vendor_type": "fortigate", "vdom_vsys": "root",
         "rule_name": "Allow-Outbound-Web", "rule_order": 1, "action": "allow",
         "src_zone_interface": "LAN", "dst_zone_interface": "WAN",
         "description": "Allow internal users to browse the internet (HTTP/HTTPS)",
         "is_active": True, "log_setting": "all-sessions"},

        {"device_id": hq_edge, "vendor_type": "fortigate", "vdom_vsys": "root",
         "rule_name": "Allow-DNS-Out", "rule_order": 2, "action": "allow",
         "src_zone_interface": "LAN", "dst_zone_interface": "WAN",
         "description": "Allow DNS queries to public resolvers",
         "is_active": True, "log_setting": "utm"},

        {"device_id": hq_edge, "vendor_type": "fortigate", "vdom_vsys": "root",
         "rule_name": "Allow-Inbound-HTTPS-DMZ", "rule_order": 3, "action": "allow",
         "src_zone_interface": "WAN", "dst_zone_interface": "DMZ",
         "description": "Allow HTTPS to public web server",
         "is_active": True, "log_setting": "all-sessions", "security_profile_group": "web-protection"},

        {"device_id": hq_edge, "vendor_type": "fortigate", "vdom_vsys": "root",
         "rule_name": "Allow-Inbound-SMTP-DMZ", "rule_order": 4, "action": "allow",
         "src_zone_interface": "WAN", "dst_zone_interface": "DMZ",
         "description": "Allow inbound email to mail server",
         "is_active": True, "log_setting": "all-sessions", "security_profile_group": "email-filter"},

        {"device_id": hq_edge, "vendor_type": "fortigate", "vdom_vsys": "root",
         "rule_name": "Block-C2-Traffic", "rule_order": 5, "action": "deny",
         "src_zone_interface": "any", "dst_zone_interface": "WAN",
         "description": "Block outbound traffic to known C2 IP ranges",
         "is_active": True, "log_setting": "all-sessions", "tags": "security,threat-response"},

        {"device_id": hq_edge, "vendor_type": "fortigate", "vdom_vsys": "root",
         "rule_name": "Default-Deny-Inbound", "rule_order": 100, "action": "deny",
         "src_zone_interface": "WAN", "dst_zone_interface": "any",
         "description": "Implicit deny all inbound traffic not matching above rules",
         "is_active": True, "log_setting": "all-sessions"},

        # ---- HQ Core (internal segmentation) ----
        {"device_id": hq_core, "vendor_type": "fortigate", "vdom_vsys": "root",
         "rule_name": "Allow-LAN-to-DC", "rule_order": 1, "action": "allow",
         "src_zone_interface": "HQ-LAN", "dst_zone_interface": "DC-ZONE",
         "description": "Allow HQ users to access data center services",
         "is_active": True, "log_setting": "utm"},

        {"device_id": hq_core, "vendor_type": "fortigate", "vdom_vsys": "root",
         "rule_name": "Allow-LAN-to-DMZ-Web", "rule_order": 2, "action": "allow",
         "src_zone_interface": "HQ-LAN", "dst_zone_interface": "DMZ",
         "description": "Allow internal access to web server for testing",
         "is_active": True, "log_setting": "utm"},

        {"device_id": hq_core, "vendor_type": "fortigate", "vdom_vsys": "root",
         "rule_name": "Block-DMZ-to-LAN", "rule_order": 3, "action": "deny",
         "src_zone_interface": "DMZ", "dst_zone_interface": "HQ-LAN",
         "description": "Prevent DMZ servers from initiating connections to internal LAN",
         "is_active": True, "log_setting": "all-sessions"},

        # ---- DC North (production servers) ----
        {"device_id": dc_north, "vendor_type": "panos", "vdom_vsys": "vsys1",
         "rule_name": "Allow-Web-to-DB", "rule_order": 1, "action": "allow",
         "src_zone_interface": "DMZ", "dst_zone_interface": "DB-ZONE",
         "description": "Allow web server to query production database",
         "is_active": True, "log_setting": "at-session-end", "security_profile_group": "strict-security"},

        {"device_id": dc_north, "vendor_type": "panos", "vdom_vsys": "vsys1",
         "rule_name": "Allow-DB-Replication", "rule_order": 2, "action": "allow",
         "src_zone_interface": "DB-ZONE", "dst_zone_interface": "DB-ZONE",
         "description": "Allow PostgreSQL replication between primary and replica",
         "is_active": True, "log_setting": "at-session-end"},

        {"device_id": dc_north, "vendor_type": "panos", "vdom_vsys": "vsys1",
         "rule_name": "Allow-Monitoring", "rule_order": 3, "action": "allow",
         "src_zone_interface": "MGMT", "dst_zone_interface": "any",
         "description": "Allow monitoring tools (Prometheus/Grafana) to reach all zones",
         "is_active": True, "log_setting": "at-session-start"},

        {"device_id": dc_north, "vendor_type": "panos", "vdom_vsys": "vsys1",
         "rule_name": "Default-Deny-DC", "rule_order": 100, "action": "deny",
         "src_zone_interface": "any", "dst_zone_interface": "any",
         "description": "Implicit deny for all unmatched DC traffic",
         "is_active": True, "log_setting": "at-session-end"},

        # ---- DC South (legacy, needs patching) ----
        {"device_id": dc_south, "vendor_type": "panos", "vdom_vsys": "vsys1",
         "rule_name": "Allow-All-Internal", "rule_order": 1, "action": "allow",
         "src_zone_interface": "trust", "dst_zone_interface": "trust",
         "description": "LEGACY: Overly permissive rule allowing all internal traffic",
         "is_active": True, "log_setting": "at-session-end", "tags": "legacy,needs-review"},

        {"device_id": dc_south, "vendor_type": "panos", "vdom_vsys": "vsys1",
         "rule_name": "Allow-SSH-Any", "rule_order": 2, "action": "allow",
         "src_zone_interface": "any", "dst_zone_interface": "trust",
         "description": "LEGACY: Allows SSH from anywhere — security risk",
         "is_active": True, "log_setting": "at-session-end", "tags": "legacy,high-risk"},

        # ---- Branch Office ----
        {"device_id": branch, "vendor_type": "asa", "vdom_vsys": None,
         "rule_name": "Allow-Branch-to-HQ-VPN", "rule_order": 1, "action": "allow",
         "src_zone_interface": "inside", "dst_zone_interface": "outside",
         "description": "Allow branch traffic to reach HQ over site-to-site VPN",
         "is_active": True, "log_setting": "enabled"},

        {"device_id": branch, "vendor_type": "asa", "vdom_vsys": None,
         "rule_name": "Allow-Branch-DNS", "rule_order": 2, "action": "allow",
         "src_zone_interface": "inside", "dst_zone_interface": "outside",
         "description": "Allow DNS from branch users to HQ DNS servers",
         "is_active": True, "log_setting": "enabled"},

        {"device_id": branch, "vendor_type": "asa", "vdom_vsys": None,
         "rule_name": "Block-Branch-Direct-Internet", "rule_order": 3, "action": "deny",
         "src_zone_interface": "inside", "dst_zone_interface": "outside",
         "description": "Force all internet traffic through HQ proxy — no direct breakout",
         "is_active": True, "log_setting": "enabled"},

        {"device_id": branch, "vendor_type": "asa", "vdom_vsys": None,
         "rule_name": "Disabled-Test-Rule", "rule_order": 99, "action": "allow",
         "src_zone_interface": "any", "dst_zone_interface": "any",
         "description": "Test rule from network audit — should be deleted",
         "is_active": False, "log_setting": "disabled", "tags": "cleanup"},
    ]

    rule_ids = {}
    for r in rules:
        result = api("post", "/rules/", r)
        rule_ids[r["rule_name"]] = result["rule_id"]
        action_icon = "✅" if r["action"] == "allow" else "🚫"
        active_tag = "" if r.get("is_active", True) else " [DISABLED]"
        print(f"  {action_icon} [{r['vendor_type'].upper()}] {r['rule_name']} (order: {r['rule_order']}){active_tag}")

    # ==================================================================
    # 7. RULE ↔ NETWORK OBJECT MAPPINGS
    # ==================================================================
    print("\n🔀 Mapping rules to network objects...")
    mappings = [
        (rule_ids["Allow-Outbound-Web"], obj_ids["HQ-LAN"], "source"),
        (rule_ids["Allow-Outbound-Web"], obj_ids["ANY-INTERNET"], "destination"),
        (rule_ids["Allow-DNS-Out"], obj_ids["HQ-LAN"], "source"),
        (rule_ids["Allow-DNS-Out"], obj_ids["CLOUDFLARE-DNS"], "destination"),
        (rule_ids["Allow-DNS-Out"], obj_ids["GOOGLE-DNS"], "destination"),
        (rule_ids["Allow-Inbound-HTTPS-DMZ"], obj_ids["ANY-INTERNET"], "source"),
        (rule_ids["Allow-Inbound-HTTPS-DMZ"], obj_ids["WEB-SERVER-01"], "destination"),
        (rule_ids["Allow-Inbound-SMTP-DMZ"], obj_ids["ANY-INTERNET"], "source"),
        (rule_ids["Allow-Inbound-SMTP-DMZ"], obj_ids["MAIL-SERVER-01"], "destination"),
        (rule_ids["Block-C2-Traffic"], obj_ids["HQ-LAN"], "source"),
        (rule_ids["Block-C2-Traffic"], obj_ids["BLOCKED-C2-RANGE"], "destination"),
        (rule_ids["Allow-Web-to-DB"], obj_ids["WEB-SERVER-01"], "source"),
        (rule_ids["Allow-Web-to-DB"], obj_ids["DC-DB-PRIMARY"], "destination"),
        (rule_ids["Allow-DB-Replication"], obj_ids["DC-DB-PRIMARY"], "source"),
        (rule_ids["Allow-DB-Replication"], obj_ids["DC-DB-REPLICA"], "destination"),
        (rule_ids["Allow-Branch-to-HQ-VPN"], obj_ids["BRANCH-ALEX-LAN"], "source"),
        (rule_ids["Allow-Branch-to-HQ-VPN"], obj_ids["HQ-LAN"], "destination"),
        (rule_ids["Allow-Branch-DNS"], obj_ids["BRANCH-ALEX-LAN"], "source"),
        (rule_ids["Allow-Branch-DNS"], obj_ids["AD-DC-01"], "destination"),
    ]
    for rule_id, object_id, direction in mappings:
        api("post", f"/rules/{rule_id}/objects", {
            "rule_id": rule_id,
            "object_id": object_id,
            "mapping_type": "address",
            "direction": direction,
        })
    print(f"  ✔ Created {len(mappings)} rule ↔ object mappings")

    # ==================================================================
    # 8. RULE ANOMALIES
    # ==================================================================
    print("\n⚠️  Creating detected anomalies...")
    anomalies = [
        {"rule_id": rule_ids["Allow-All-Internal"], "anomaly_type": "overly_permissive", "severity_level": "high",
         "description": "Rule allows all internal traffic with no service restrictions. Violates least-privilege principle."},
        {"rule_id": rule_ids["Allow-SSH-Any"], "anomaly_type": "overly_permissive", "severity_level": "critical",
         "description": "SSH access from ANY source zone. Exposes management plane to potential lateral movement."},
        {"rule_id": rule_ids["Disabled-Test-Rule"], "anomaly_type": "stale_rule", "severity_level": "low",
         "description": "Rule has been disabled since network audit. Should be removed to keep policy clean."},
        {"rule_id": rule_ids["Allow-Outbound-Web"], "anomaly_type": "shadowed_rule", "severity_level": "medium",
         "description": "Parts of this rule's traffic may be shadowed by the Block-C2-Traffic rule above it in evaluation order."},
        {"rule_id": rule_ids["Allow-Monitoring"], "anomaly_type": "overly_permissive", "severity_level": "medium",
         "description": "Monitoring rule allows access to 'any' destination zone. Should be scoped to specific monitored subnets."},
    ]
    for a in anomalies:
        rule_name = [name for name, rid in rule_ids.items() if rid == a["rule_id"]][0]
        api("post", f"/rules/{a['rule_id']}/anomalies", a)
        sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}[a["severity_level"]]
        print(f"  {sev_icon} {a['anomaly_type']} on '{rule_name}' — {a['severity_level']}")

    # ==================================================================
    # 9. THREAT INTELLIGENCE
    # ==================================================================
    print("\n🛡️  Creating threat intelligence entries...")
    threats = [
        {"device_id": dc_south, "target_version": "11.0.4",
         "intelligence_summary": "CVE-2024-3400: PAN-OS GlobalProtect RCE. Unauthenticated command injection via crafted HTTP request. CVSS 10.0. Patch to 11.0.5+ immediately.",
         "risk_score": 10.0, "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3400"},
        {"device_id": hq_edge, "target_version": "7.4.3",
         "intelligence_summary": "CVE-2024-21762: FortiOS SSL-VPN out-of-bounds write. Allows remote code execution via specially crafted HTTP requests. CVSS 9.8. Actively exploited in the wild.",
         "risk_score": 9.8, "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-21762"},
        {"device_id": branch, "target_version": "9.18.3",
         "intelligence_summary": "Cisco ASA firmware 9.18.3 has known issues with VPN session handling under high load. Not a direct vulnerability but may cause denial of service. Upgrade to 9.18.4 recommended.",
         "risk_score": 4.5, "source_url": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory"},
        {"device_id": dc_north, "target_version": "11.1.2",
         "intelligence_summary": "PAN-OS 11.1.2 is current and patched. No known critical vulnerabilities. Continue monitoring PANW security advisories.",
         "risk_score": 1.0, "source_url": "https://security.paloaltonetworks.com/"},
    ]
    threat_ids = {}
    for t in threats:
        result = api("post", "/threat-intel/", t)
        threat_ids[result["threat_id"]] = t
        hostname = [h for h, did in device_ids.items() if did == t["device_id"]][0]
        risk_bar = "█" * int(t["risk_score"]) + "░" * (10 - int(t["risk_score"]))
        print(f"  [{risk_bar}] {hostname} (v{t['target_version']}) — risk: {t['risk_score']}")

    # ==================================================================
    # 10. THREAT ↔ RULE CORRELATIONS
    # ==================================================================
    print("\n🔗 Creating threat-rule correlations...")
    dc_south_threat = [tid for tid, t in threat_ids.items() if t["device_id"] == dc_south][0]
    hq_edge_threat = [tid for tid, t in threat_ids.items() if t["device_id"] == hq_edge][0]

    correlations = [
        (dc_south_threat, rule_ids["Allow-SSH-Any"], 0.95, 0.90),
        (dc_south_threat, rule_ids["Allow-All-Internal"], 0.80, 0.85),
        (hq_edge_threat, rule_ids["Allow-Inbound-HTTPS-DMZ"], 0.70, 0.75),
    ]
    for threat_id, rule_id, strength, confidence in correlations:
        api("post", f"/threat-intel/{threat_id}/correlations", {
            "rule_id": rule_id, "threat_id": threat_id,
            "match_strength": strength, "confidence_level": confidence,
        })
        rule_name = [name for name, rid in rule_ids.items() if rid == rule_id][0]
        print(f"  ✔ Threat {threat_id} ↔ '{rule_name}' (strength: {strength}, confidence: {confidence})")

    # ==================================================================
    # SUMMARY
    # ==================================================================
    print("\n" + "=" * 60)
    print("  ✅ Seed complete! Summary:")
    print(f"     • {len(vendors)} vendors")
    print(f"     • {len(admins)} administrators")
    print(f"     • {len(devices)} firewall devices")
    print(f"     • {len(assignments)} admin-device assignments")
    print(f"     • {len(net_objects)} network objects")
    print(f"     • {len(rules)} policy rules")
    print(f"     • {len(mappings)} rule-object mappings")
    print(f"     • {len(anomalies)} detected anomalies")
    print(f"     • {len(threats)} threat intelligence entries")
    print(f"     • {len(correlations)} threat-rule correlations")
    print("=" * 60)
    print("\n  📖 View your API docs at: http://localhost:8000/docs\n")


if __name__ == "__main__":
    seed()
