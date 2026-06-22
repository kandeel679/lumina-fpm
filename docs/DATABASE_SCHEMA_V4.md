# LuminaFPM — Database Schema v4

> Authoritative source: **Volume 5** (Database & Data Model) + **Volume 4** (Normalization).
> Database: **PostgreSQL only**. Migrations: **Alembic** (no destructive auto-sync — V5 §14).
> All timestamps stored in **UTC** (timezone-aware). No secrets in plaintext.

This is the frozen data contract. Per V14 §17, **Schema v4 is frozen before backend implementation**
and the **normalized rule model is frozen before anomaly development**.

---

## 0. Conventions

- PKs are surrogate integer identities unless noted.
- FKs are explicit and indexed.
- Timestamps: `TIMESTAMP WITH TIME ZONE`, default `now()` UTC.
- "Enum-like" columns use `CHECK` constraints or SQLAlchemy `Enum`; values listed per column.
- Soft delete via `is_active=false` / `deleted_at` rather than hard delete (V4 §12, V5 §12).

---

## 1. Schema v3 baseline — keep / extend (V5 Table 3)

| Table | v1 status |
|---|---|
| `vendor` | keep |
| `firewall_device` | keep |
| `policy_rule` | keep + extend (`normalized_content_hash`, `deleted_at`) |
| `network_object` | **extend** with ownership fields |
| `rule_object_mapping` | keep |
| `rule_anomaly` | **extend** (confidence, analysis_run_id, detection_mode, status, evidence) |
| `threat_intelligence` | keep / complement with `cti_indicator` + `cti_observation` |
| `threat_correlation` | keep + extend |
| `administrator`, `admin_device_assignment` | keep (RBAC user store) |

> The existing extra tables (`external_node`, `threat_feed`, `api_token`, `audit_log`,
> `saved_search`) are retained where they map to v4 needs: `api_token` → credential/secret store
> (must be encrypted), `audit_log` → audit logging (V12), `saved_search` → Policy Explorer saved
> filters. `external_node`/`threat_feed` are legacy from the old dark-web direction and are
> candidates for repurpose/removal (see gap analysis).

---

## 2. Core operational model

### 2.1 `vendor`
`vendor_id` PK · `name` · `api_type` (`FortiOS-REST` | `PAN-OS-XML`) · `support_contact`.
Seed: Fortinet, Palo Alto Networks (V13 §7).

### 2.2 `firewall_device` (V5 Table 5, V3 Table 8)
`device_id` PK · `vendor_id` FK · `hostname` · `vendor_type` (`fortinet`|`paloalto`) ·
`management_ip` VARCHAR(45) · `firmware_version` · `location` · `status`
(`online|offline|degraded|unknown`) · `last_poll_time` · timestamps.
Status is written by the app layer, not derived in SQL.

### 2.3 `policy_rule` — core post-parsing rule table (V5 Table 7, V4 Table 6)

| Group | Fields |
|---|---|
| Identity | `rule_id` PK, `device_id` FK, `vendor_rule_id`, `vendor_uuid`, `vendor_type`, `vdom_vsys` |
| Evaluation | `rule_order`, `action`, `is_active`/`enabled` |
| Direction | `src_zone_interface`, `dst_zone_interface` |
| Posture | `log_setting`/`logging_enabled`, `security_profile_group`/`security_inspection_enabled`, `security_profile_strength`, `schedule_name`, `nat_enabled` |
| Selectors | via `rule_object_mapping` (sources/destinations/services) |
| Negation | `src_negate`, `dst_negate` |
| Canonical | `logging_mode`, `schedule_scope`, `normalized_content_hash` |
| Audit | `description`, `tags`, `created_at`, `updated_at`, `deleted_at` (nullable) |

**Canonical `action` enum:** `allow | deny | drop | reset | ipsec | unknown` (V4 Table 6).
**`logging_enabled` / `security_inspection_enabled`:** `true | false | unknown` (V4 §11).

**Sync key (V5 Table 6, V4 §12):**
```
UNIQUE (device_id, vdom_vsys, vendor_uuid)   -- where vendor_uuid IS NOT NULL
```
When the vendor exposes no UUID, the parser derives a **stable hash** from
`device_id + vdom_vsys + vendor_rule_id + rule_name + vendor_path` (V4 Table 8).

### 2.4 `rule_object_mapping` (V5)
`rule_id` FK · `object_id` FK · `mapping_type` (`source|destination|service`) · `direction`.
Composite PK `(rule_id, object_id, mapping_type)`.

---

## 3. Object & service correlation model (V4 §7–8, V5 §8)

### 3.1 `network_object` — **extended with ownership**
```
object_id        PK
device_id        FK -> firewall_device
vendor_id        FK -> vendor
vendor_object_id            -- vendor-side id when available
vendor_uuid                 -- vendor-side uuid when available
name
type             -- ip_address | cidr | fqdn | group | any | application | url_category
value            -- canonical value
raw_value        -- original extracted value
created_at, updated_at
```

### 3.2 `normalized_object` (canonical, above vendor objects)
```
normalized_object_id  PK
canonical_name
canonical_type        -- ip_address | cidr | fqdn | group | any | unknown
canonical_value
sensitivity           -- public | internal | dmz | database | admin | critical | unknown
description
created_at, updated_at
```

### 3.3 `object_normalization_mapping`
```
object_id            FK -> network_object
normalized_object_id FK -> normalized_object
match_method         -- exact_name_value | exact_value | name_similarity | manual | derived
confidence           NUMERIC(3,2)   -- 0.00–1.00
mapping_reason       text
created_at, updated_at
```

### 3.4 `normalized_service`
```
normalized_service_id PK
canonical_name        -- e.g. HTTPS, MYSQL
protocol              -- tcp | udp | icmp | application | any | unknown
port_start            int null
port_end              int null
app_id                string null   -- PAN-OS App-ID
created_at, updated_at
```

### 3.5 `service_normalization_mapping`
```
service_object_id     FK -> network_object (service-typed) / service object
normalized_service_id FK -> normalized_service
match_method          -- exact_port | exact_name_port | app_id | manual | derived
confidence            NUMERIC(3,2)
mapping_reason         text
```

**Matching confidence table (V4 Table 11):** same name+type+value → 1.00; diff name same value →
0.90 (naming-inconsistency candidate); same name diff value → 0.30 (do **not** auto-merge, raise
inconsistency candidate); same group diff members → 0.40 (group-drift candidate); ANY → canonical
ANY 1.00; unknown → 0.20.

---

## 4. Anomaly repository

### 4.1 `rule_anomaly` — extended (V5 Table 9, V6 Table 3)
```
anomaly_id        PK
rule_id           FK -> policy_rule
related_rule_id   nullable        -- pairwise (conflict/shadowing/etc.)
anomaly_type      -- taxonomy value from the 46 framework
severity_level    -- critical | high | medium | low
confidence        NUMERIC(3,2)    -- 0.00–1.00
description       text            -- technical_reason
evidence          JSONB           -- rule fields/objects that caused the finding
recommendation    text
detection_mode    -- config_only | conditional | simulated | future_enhanced
analysis_run_id   FK -> anomaly_execution_log
detected_at       timestamptz
status            -- open | resolved | suppressed | accepted_risk | false_positive
suppression_reason / suppressed_by / suppression_expires_at  (nullable)
```

### 4.2 `anomaly_execution_log` (V5 Table 4, V6 §11)
```
run_id            PK
scope_type        -- device | all | benchmark
scope_id          nullable
started_at, completed_at
status            -- running | completed | failed | partial
findings_count, error_log (text/JSONB)
engine_version
```

---

## 5. Risk repository (V8 §11)

### `risk_assessment`
```
risk_id           PK
scope_type        -- rule | device | object
scope_id
risk_score        int   -- 0–100
risk_tier         -- critical | high | medium | low | informational
factor_breakdown  JSONB -- per-factor contributions (anomaly/exposure/asset/posture/logging/cross_vendor/cti/lifecycle)
calculated_at     timestamptz
calculation_version
analysis_run_id   FK -> anomaly_execution_log (nullable)
```
Tiers: 0 informational · 1–39 low · 40–69 medium · 70–89 high · 90–100 critical.

---

## 6. CTI repository (V5 Table 10, V9 §7)

### `cti_indicator`
```
indicator_id  PK
type          -- ip_address | cidr | fqdn | url | cve | firmware_version | vendor_version_keyword
value
source_object_id / source_device_id  (nullable provenance)
is_public     bool
first_seen, last_seen
```

### `cti_observation`
```
observation_id     PK
indicator_id       FK -> cti_indicator
provider           -- abuseipdb | otx | virustotal | nvd | vendor_advisory | ...
provider_reference -- record id / url
severity
confidence         NUMERIC(3,2)
threat_type        -- malware | c2 | scanner | exploit | botnet | vulnerability | ...
summary            text
raw_response_hash
observed_at        timestamptz
```

### `threat_correlation` (kept + extended)
`rule_id` FK · `indicator_id`/`threat_id` FK · `match_strength` · `confidence` · `created_at`.

---

## 7. AI report repository (V5 Table 10, V10 §9)

### `llm_report`
```
report_id        PK
scope_type       -- rule | device | scan | executive
scope_id
provider         -- gemini | openai | ollama
model
prompt_version
evidence_refs    JSONB   -- DB evidence IDs (rule/anomaly/risk/cti)
output           text
confidence_note  text    -- confidence/limitations
status           -- complete | partial | failed
created_at       timestamptz
```

---

## 8. Benchmark repository (V5 Table 11, V7)

### `benchmark_case`
```
case_id           PK
case_type         -- atomic | compound
anomaly_type      -- expected taxonomy value
device_a_id, rule_a_id
device_b_id, rule_b_id   (nullable, pairwise/cross-device)
expected_severity -- critical | high | medium | low
expected_reason   text
detection_mode    -- config_only | conditional | simulated | future_enhanced
required_fields   JSONB
```

### `benchmark_result`
```
result_id         PK
case_id           FK -> benchmark_case
analysis_run_id   FK -> anomaly_execution_log
detected          bool
detected_anomaly_id FK -> rule_anomaly (nullable)
match_quality     -- exact | partial | none
false_positive    bool
false_negative    bool
notes             text
```
Metrics computed at report time: Precision = TP/(TP+FP), Recall = TP/(TP+FN), F1, severity-match rate.

---

## 9. Normalization support tables (V4 §14)

### `normalization_warning`
```
warning_id   PK
device_id    FK
rule_id      FK null
object_id    FK null
warning_type -- unsupported_field | ambiguous_mapping | group_cycle | unknown_service | missing_uuid
severity     -- low | medium | high
message      text
raw_reference text
created_at
```

### `rule_snapshot` (history/drift/change-frequency)
```
snapshot_id  PK
rule_id      FK -> policy_rule
device_id    FK
normalized_content_hash
snapshot     JSONB     -- full normalized rule at poll time
job_id       -- acquisition job that produced it
created_at
```

---

## 10. Acquisition tables (V3 §6–8)

### `acquisition_job`
```
job_id          PK (or string acq_YYYY_NNNNNN)
device_id       FK
vendor_type
requested_by    (admin_id / 'scheduler')
status          -- queued | running | success | partial_success | failed | timeout
                -- authentication_failed | authorization_failed | connection_failed
                -- rate_limited | parsing_queued | parsing_failed
started_at, completed_at, duration_ms
connector_version
error_code, error_message    -- safe summary, NO secrets
created_at
```

### `raw_artifact`
```
artifact_id  PK
job_id       FK -> acquisition_job
device_id    FK
type         -- policies | address_objects | address_groups | service_objects | service_groups | device_metadata | manifest
path         -- storage reference under /raw_acquisition/{vendor}/{device}/{job}/
sha256
created_at
```

### `device_credential` (encrypted) (V3 §6.2, V12 §6)
```
credential_id   PK
device_id       FK
auth_type       -- fortigate_api_token | panos_api_key | panos_userpass
secret_encrypted BYTEA / text  -- encrypted with ENCRYPTION_KEY; NEVER plaintext, NEVER to frontend
created_at, rotated_at, last_used_at
```
> Supersedes the current `api_token` model's role for *firewall* secrets. Audit credential
> usage without logging values.

---

## 11. Indexes & constraints (V5 Table 12)

```
UNIQUE (policy_rule.device_id, vdom_vsys, vendor_uuid)        -- re-sync / dedupe (partial: vendor_uuid IS NOT NULL)
INDEX  (policy_rule.device_id, vdom_vsys, rule_order)         -- ordered anomaly analysis
INDEX  (rule_anomaly.rule_id)
INDEX  (rule_anomaly.analysis_run_id)
INDEX  (network_object.device_id, type, value)
INDEX  (object_normalization_mapping.normalized_object_id)
INDEX  (risk_assessment.scope_type, scope_id, calculated_at)
INDEX  (cti_indicator.type, value)                            -- dedupe
INDEX  (acquisition_job.device_id, status)
```

---

## 12. Migration & data-quality rules (V5 §14)

1. All schema changes via **Alembic**; migration history version-controlled.
2. Every table has clear PKs/FKs; all timestamps UTC.
3. No API secrets in plaintext.
4. Imported vendor records preserve source identifiers when available.
5. Validation failures logged and attached to ingestion job records (`normalization_warning`,
   `acquisition_job.error_*`).
6. Run migrations **before** API startup; never destructive auto-sync (drop `Base.metadata.create_all`
   from the production path; keep only for ephemeral test DBs).
7. Seed Fortinet + Palo Alto vendors on first migration.

---

## 13. ERD (V5 §5)

```
vendor 1─N firewall_device 1─N policy_rule 1─N rule_anomaly
                                  │              │
                                  │              └─N rule_object_mapping N─1 network_object
                                  │                                         │
                                  │                                         └─N object_normalization_mapping N─1 normalized_object
                                  ├─N risk_assessment
                                  ├─N acquisition_job 1─N raw_artifact
                                  └─N threat_correlation N─1 cti_indicator 1─N cti_observation
policy_rule N─N benchmark_case   (via benchmark_result)
policy_rule 1─N llm_report (scope=rule)   ·   anomaly_execution_log 1─N rule_anomaly
```
