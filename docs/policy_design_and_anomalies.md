# Proactive Firewall Policy Management: Policy Design & Anomaly Lab

This document serves as the **Master Design Record** for all firewall policies required to trigger the 46-point anomaly framework across FortiGate and Palo Alto lab environments.

## 1. Network Topology & Zone Mapping

| Logical Zone | Subnet | FortiGate Interface | Palo Alto Zone | Description |
|---|---|---|---|---|
| LAN | `10.10.10.0/24` | `port1` | `trust` | Internal User Network |
| DMZ | `10.10.20.0/24` | `port2` | `dmz` | Web Servers, Public Facing Services |
| DB | `10.10.30.0/24` | `port3` | `db` | **CRITICAL:** Database Subnet |
| ADMIN | `10.10.99.0/24` | `port1` | `trust` | **CRITICAL:** Management Subnet |
| WAN | `0.0.0.0/0` | `port4` | `untrust` | External Internet |

**Critical Hosts:**
- Backup Server: `10.10.50.10` (HIGH)
- Monitor Server: `10.10.60.10` (MEDIUM/HIGH)
- Malicious IP (CTI Demo): `198.51.100.5`

---

## 2. Object Creation Guide

### FortiGate Objects (CLI / API)
```json
[
  {"name": "LAN_NET", "subnet": "10.10.10.0/24"},
  {"name": "DMZ_NET", "subnet": "10.10.20.0/24"},
  {"name": "DB_NET", "subnet": "10.10.30.0/24"},
  {"name": "ADMIN_NET", "subnet": "10.10.99.0/24"},
  {"name": "BACKUP_SRV", "subnet": "10.10.50.10/32"},
  {"name": "MONITOR_SRV", "subnet": "10.10.60.10/32"},
  {"name": "MALICIOUS_IP", "subnet": "198.51.100.5/32"}
]
```

### Palo Alto Objects (CLI / API)
Use standard Address objects matching the names and IP specifications listed above.

---

## 3. End-to-End Execution Workflow

1. **Deploy Objects:** Run the automated deployers (`deploy_objects()` function) to create the address and service objects on both devices.
2. **Deploy Policies:** Run the deployers (`deploy_policies()` function) to push the ~45 policies below.
3. **Commit:** (Palo Alto only) The deployer will automatically commit the pushed configurations.
4. **Extract:** Run `fortigate_extractor.py` and `paloalto_extractor.py`. They will connect to the APIs, pull the data, apply light normalization, and output JSON/XML wrapped with metadata.
5. **Parse:** Feed the extracted output files (`output/`) into the downstream Parsing/Normalization layer to map directly to `firewall_schema_v3`.
6. **Analyze:** Run the Analysis Layer to detect the anomalies injected by these policies.

---

## 4. Full Anomaly Mapping Table

| Rule Name | Vendor | Anomaly IDs Covered | Explanation / Why It Triggers |
|---|---|---|---|
| FGT_ALLOW_ANY_TO_DB_ALL | FortiGate | 4, 7, 36 | Overly permissive (`any` source, `ALL` service) to a critical DB subnet. Exposes threats. |
| FGT_DENY_LAN_TO_DB_ALL | FortiGate | 1, 9 | Shadowed by the broader `FGT_ALLOW_ANY_TO_DB_ALL`. Placed after it (Ordering Anomaly). |
| PA_DENY_LAN_TO_DB_ALL | Palo Alto | 3, 44 | Cross-device inconsistency and Conflict. Palo Alto denies what FortiGate allows. |
| PA_ALLOW_LAN_NO_SECURITY | Palo Alto | 5, 33 | Allows outbound traffic with no Security Profile attached (Unprotected Allow, Weak Sec). |
| FGT_ALLOW_LAN_TO_DMZ_HTTP | FortiGate | 3 | Conflict pair with PA (FG allows HTTP to DMZ). |
| PA_DENY_LAN_TO_DMZ_HTTP | Palo Alto | 3 | Conflict pair with FG (PA denies HTTP to DMZ). |
| FGT_DUP_ALLOW_WEB | FortiGate | 2, 10 | Exact duplicate of another web rule. Redundancy / Duplicate rule. |
| PA_ALLOW_WIDE_PORTS | Palo Alto | 8, 23 | Allows ports 1-1024, triggering wide port range and unusual port anomalies. |
| FGT_NOLOG_ADMIN_SSH | FortiGate | 6, 32 | Logging is disabled on a rule accessing the sensitive ADMIN subnet. |
| FGT_EXPIRED_TEMP_RULE | FortiGate | 15, 29 | Temporary testing rule that has expired/schedule misconfiguration but is still active. |
| PA_UNUSED_LEGACY_RULE | Palo Alto | 13, 14, 16 | Very old rule with 0 hits over 180 days (Policy drift, unused, age issue). |
| FGT_HARDCODED_IP_TEST | FortiGate | 22 | Uses a hardcoded IP `8.8.8.8` instead of a defined network object. |
| PA_DISABLED_RISKY_RDP | Palo Alto | 20, 42 | Rule allowing RDP from untrust is disabled, but risky if enabled. |
| FGT_OVERLAPPING_BACKUP | FortiGate | 11 | Overlaps with an existing generic backup rule but specifies different objects. |
| PA_INCONSISTENT_ACT_DNS | Palo Alto | 12 | Denies DNS to one DMZ server but allows it to another identically classified server. |
| FGT_ZONE_MISMATCH | FortiGate | 27 | Tries to allow LAN to DB using the WAN interface (Zone routing mismatch). |
| PA_NEGATE_MISUSE | Palo Alto | 28 | "Allow source NOT LAN to DB". Negate logic allows the whole internet in. |
| FGT_NAT_RISK | FortiGate | 30 | NAT applied incorrectly on an internal-to-internal flow (LAN to DB). |
| PA_COMPLEX_RULE_99 | Palo Alto | 21, 24, 34 | Rule contains 50+ objects across source, destination, and service. High complexity. |
| FGT_ASYMMETRIC_ROUTE | FortiGate | 35, 46 | Allows traffic in one direction with specific NAT/routing that breaks reverse traffic. |
| PA_COMPLIANCE_FAIL | Palo Alto | 45 | Rule breaks PCI-DSS by allowing unencrypted Telnet to DB zone. |

*(Note: The full 45 policies are implemented in the deployment scripts which iterate programmatically to create variations of these core structures. 22 FG policies + 23 PA policies ensure full coverage of IDs 1-46).*

---

## 5. UI-Based Policy Creation Guide (Optional / Reference)

If manual creation is preferred over automated API deployment, follow these steps:

### FortiGate UI
1. Go to **Policy & Objects** > **Firewall Policy**.
2. Click **Create New**.
3. Set **Name** (e.g., `FGT_ALLOW_ANY_TO_DB_ALL`).
4. Set **Incoming Interface** (e.g., `any` or `port1`).
5. Set **Outgoing Interface** (e.g., `port3`).
6. Set **Source** (`all`), **Destination** (`DB_NET`), **Schedule** (`always`), **Service** (`ALL`).
7. **Action**: `Accept`
8. Toggle **Log Allowed Traffic** depending on anomaly (Disable for Anomaly #6).

### Palo Alto UI
1. Go to **Policies** > **Security**.
2. Click **Add**.
3. **General Tab**: Set Name (`PA_DENY_LAN_TO_DB_ALL`).
4. **Source Tab**: Add `trust` zone and `LAN_NET` address.
5. **Destination Tab**: Add `db` zone and `DB_NET` address.
6. **Action Tab**: Set Action to `Deny`.
7. Click **OK**, then click **Commit** at the top right.

