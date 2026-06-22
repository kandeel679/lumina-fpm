# LuminaFPM — Normalization Model

> Authoritative source: **Volume 4** (Normalization Engine) + V2 §8, V3 §11.
> Binding rule (V4 Table 1): **the anomaly engine analyzes normalized records only.** Raw FortiGate
> JSON and Palo Alto XML are acquisition/parser inputs and must never be analyzed directly.

The normalized rule model is **frozen before anomaly development** (V14 §17).

---

## 1. Pipeline position

```
FortiGate REST JSON     Palo Alto XML
        │                     │
   FortiGate Parser      PaloAlto Parser      (vendor models; NO anomaly logic)
        └─────────┬───────────┘
                  ▼
          Normalization Engine                 (Celery worker, deterministic)
                  ▼
        Normalized PostgreSQL Repository        (source of truth)
                  ▼
         Deterministic Anomaly Engine
```

## 2. Principles (V4 Table 4)
Vendor-neutral semantics · vendor traceability · **no anomaly logic in parsers** · no direct raw
analysis · configuration-first · deterministic output (same input → same output) · explainability
(every analyzed field has a source + transformation rule) · extensibility (new vendor = new parser,
not new anomaly engine).

---

## 3. Canonical normalized rule model (V4 §4, Table 6)

```json
{
  "normalized_rule_id": "string",
  "internal_rule_id": 123,
  "device_id": 1,
  "vendor": "fortinet",                 // fortinet | paloalto
  "vendor_rule_id": "15",
  "vendor_uuid": "uuid-or-derived-id",
  "vdom_vsys": "root",
  "rule_name": "FGT_ALLOW_LAN_TO_DMZ_HTTPS",
  "rule_order": 10,                      // first-match order, lower = earlier
  "enabled": true,
  "source_zone": "LAN",
  "destination_zone": "DMZ",
  "sources":      [{"name":"LAN_NET","type":"cidr","value":"10.10.10.0/24"}],
  "destinations": [{"name":"WEB_SERVER","type":"ip_address","value":"10.10.20.10"}],
  "services":     [{"name":"HTTPS","protocol":"tcp","port":"443"}],
  "action": "allow",                     // allow|deny|drop|reset|ipsec|unknown
  "logging_enabled": true,               // true|false|unknown
  "security_inspection_enabled": true,   // true|false|unknown
  "security_profile_group": "default-inspection",
  "schedule": "always",
  "nat_enabled": false,
  "description": "Allow users to access web server"
}
```
> This JSON is the **service/interchange** representation. The authoritative persistent state is
> PostgreSQL (`policy_rule` + mappings). JSON is generated from / written into relational tables.

---

## 4. Vendor → canonical field mapping (V4 Table 7)

| Canonical | FortiGate | Palo Alto | Note |
|---|---|---|---|
| vendor | `fortinet` | `paloalto` | from connector type |
| vendor_rule_id | `policyid` | sequence/name | human traceability, not sole sync key |
| vendor_uuid | `uuid` or derived hash | `uuid` or derived hash | with device_id+vdom_vsys for re-sync |
| vdom_vsys | `vdom` | `vsys`/device-group | avoid rule collisions |
| rule_name | `name`/generated | entry `name` | |
| rule_order | policy sequence | rulebase order | needed for shadowing/redundancy |
| enabled | `status=enable` | `disabled=no` | disabled rules still stored |
| source_zone | `srcintf` | `from-zone` | canonical source direction |
| destination_zone | `dstintf` | `to-zone` | canonical dest direction |
| sources | `srcaddr` | `source` | resolved via object mapping |
| destinations | `dstaddr` | `destination` | resolved via object mapping |
| services | `service` | `service`/`application` | resolved via service mapping |
| action | `accept/deny/ipsec` | `allow/deny/drop/reset` | canonical action enum |
| logging_enabled | `logtraffic` ≠ disable | `log-start/log-end`/forwarding | boolean + raw mode |
| security_inspection_enabled | UTM/profile exists | profile-group/profiles exist | unprotected-allow / weak-profile |
| schedule | `schedule` | `schedule` | null/always if unset |
| nat_enabled | `nat` enable/disable | null in v1 (separate NAT policy) | PAN-OS NAT = future |

**Derived UUID (V4 Table 8):** when vendor UUID is absent, derive a stable hash from
`device_id + vdom_vsys + vendor_rule_id + rule_name + vendor_path`, stable across polls unless the
vendor rule identity truly changes.

---

## 5. Object correlation model (V4 §7) — *correlation, not merge*

Vendor objects stay separate (ownership/traceability); a canonical `normalized_object` is created
above them and connected via `object_normalization_mapping`. Tables and matching-confidence values
are defined in [DATABASE_SCHEMA_V4.md](DATABASE_SCHEMA_V4.md) §3.

Matching logic (V4 Table 11): exact name+type+value → map (1.00); diff name same value → map +
naming-inconsistency candidate (0.90); same name diff value → **do not merge**, raise inconsistency
candidate (0.30); same group diff members → group-drift candidate (0.40); ANY → canonical ANY (1.00);
unknown → keep, exclude from strict comparison (0.20).

---

## 6. Service correlation (V4 §8, Table 12)

`normalized_service(protocol, port_start, port_end, app_id)`. Rules:
- Service groups expanded recursively, members de-duplicated.
- Port ranges as start/end.
- ANY service → canonical `ANY_SERVICE` (protocol=any).
- PAN-OS **App-ID** preserved as an application concept, **not** converted to a port unless a known
  mapping exists.
- Unknown services preserved as raw values; lower comparison confidence.

---

## 7. Group expansion & ANY handling (V4 §9, Table 13)
- Preserve original group reference **and** expanded member list (traceability + comparison).
- Recursive groups with **cycle detection** → on cycle, stop and emit `normalization_warning(group_cycle)`.
- ANY object → canonical `0.0.0.0/0` (IPv4) / `::/0` (IPv6).
- Preserve `src_negate`/`dst_negate` (changes set semantics).

## 8. Zone & direction (V4 §10, Table 14)
FortiGate uses **interfaces**, Palo Alto uses **zones**. Normalize both to `source_zone`/
`destination_zone` (+ raw values) and derive a `zone_pair` for conflict/shadowing scope.
**Zone normalization must not imply routed packet traversal** (logical graph only).

## 9. Posture abstraction (V4 §11, Table 16)
| Canonical | Values |
|---|---|
| `logging_enabled` | true / false / unknown |
| `logging_mode` | all / security-event / profile / disabled / unknown |
| `security_inspection_enabled` | true / false / unknown |
| `security_profile_group` | string / null |
| `security_profile_strength` | strong / weak / missing / unknown |
| `nat_enabled` | true / false / null |
| `schedule_name` | always / named / null |
| `schedule_scope` | always / limited / unknown |

`security_inspection_enabled=false` when an **allow** rule has no inspection profile (drives
unprotected-allow). `logging_enabled=false` only when explicitly disabled; `unknown` when not
reliably extractable.

---

## 10. Pipeline & idempotency (V4 §13)

```
1 load parsed payload → 2 validate parser schema → 3 normalize device/vendor context
4 normalize objects+groups → 5 normalize services+groups → 6 expand groups (cycle detection)
7 normalize rules → 8 attach normalized object/service refs → 9 compute normalized content hash
10 UPSERT into PostgreSQL → 11 write normalization warnings → 12 enqueue anomaly analysis
```
**Idempotency (V4 §13.2):** running normalization twice on the same input must not create duplicate
policy/object/service/mapping rows. All writes use deterministic keys or upsert by the re-sync key
`(device_id, vdom_vsys, vendor_uuid)`.

**Re-sync behavior (V4 Table 17):** stable identity across polls; rename tolerance (same UUID, new
name → update row); reorder tolerance (update + re-analyze); missing rules → soft-delete/version, no
destructive delete; keep snapshots; content hash detects meaningful change.

---

## 11. Validation gates (V4 Table 20) & service interfaces (V4 Table 22)

Gates: schema validation · required fields · object resolution · service resolution · deterministic
group expansion · ANY detection · action normalization · idempotency · traceability · anomaly-readiness.

Internal/optional API surface:
```
POST /api/normalization/run/{device_id}
GET  /api/normalization/status/{job_id}
GET  /api/normalization/warnings
GET  /api/objects/normalized
GET  /api/services/normalized
GET  /api/rules/{rule_id}/normalized
```

## 12. Acceptance criteria (V4 Table 23)
Normalized-only analysis · cross-vendor equivalence · object correlation · service correlation
(HTTP/HTTPS/SSH/DNS/MYSQL/RDP/FTP/SMTP) · full traceability · re-sync stability (no duplicates) ·
warning visibility · benchmark readiness · graph readiness · report readiness.
