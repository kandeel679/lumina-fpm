# LuminaFPM — API Contract (v1 target)

> Sources: V2 Table 13, V3 Table 27, V4 Table 22, V8 §13, V9 §13, V11 §12.
> All endpoints require authentication; RBAC scopes per [SECURITY_MODEL.md](SECURITY_MODEL.md) §4.
> Read-only against firewalls — **no endpoint pushes/commits config.** Base prefix: `/api/v1`.

This is the *target* contract the implementation converges on. Existing routes are mapped to it in
[CODEBASE_GAP_ANALYSIS.md](CODEBASE_GAP_ANALYSIS.md).

---

## 1. Devices & acquisition (V3 Table 27)
| Method | Path | Purpose | Min role |
|---|---|---|---|
| GET | `/devices` | List firewall devices | Viewer |
| POST | `/devices` | Register a device | Admin |
| GET | `/devices/{id}` | Device detail | Viewer |
| POST | `/devices/{id}/credentials` | Create/update **encrypted** creds (returns status only) | Admin |
| POST | `/devices/{id}/test-connection` | Validate API connectivity (status only, no secret) | Firewall Eng |
| POST | `/devices/{id}/poll` | Trigger async acquisition job | Firewall Eng |
| GET | `/jobs/{job_id}` | Acquisition job status | Firewall Eng |
| GET | `/jobs?device_id={id}` | List jobs for a device | Firewall Eng |
| GET | `/jobs/{job_id}/artifacts` | List raw artifacts (authorized) | Firewall Eng |
| POST | `/jobs/{job_id}/replay-parser` | Re-run parser from stored raw artifacts | Firewall Eng |

## 2. Policies, objects, services
| Method | Path | Purpose |
|---|---|---|
| GET | `/policies` | Policy Explorer: filter by vendor/device/vdom/zone/src/dst/service/action/severity/anomaly/risk |
| GET | `/policies/{rule_id}` | Normalized rule + vendor traceability |
| GET | `/rules/{rule_id}/normalized` | Normalized representation of a rule |
| GET | `/objects` · `/objects/normalized` | Vendor objects / canonical normalized objects |
| GET | `/services/normalized` | Canonical normalized services |
| POST | `/normalization/run/{device_id}` | Trigger normalization for latest parsed payload |
| GET | `/normalization/warnings` | Normalization warnings for review |

## 3. Anomalies (V6)
| Method | Path | Purpose |
|---|---|---|
| GET | `/anomalies` | List/filter findings (type/severity/device/status) |
| GET | `/anomalies/{id}` | Finding detail + evidence + related rule |
| POST | `/anomalies/run` | Trigger anomaly analysis (scope: device/all) → `analysis_run_id` |
| PATCH | `/anomalies/{id}` | Set status (`resolved/suppressed/false_positive/accepted_risk`) + reason |
| GET | `/rules/{rule_id}/anomalies` | Anomalies for a rule |

## 4. Risk (V8 §13)
| Method | Path | Purpose |
|---|---|---|
| GET | `/risks` | Risk-ranked rules/devices (sort by score) |
| GET | `/risks/{scope_type}/{scope_id}` | Risk score + **factor breakdown** + history |
| POST | `/risks/recalculate` | Trigger recalculation (scope) |

## 5. CTI (V9 §13)
| Method | Path | Purpose |
|---|---|---|
| GET | `/cti/indicators` | Extracted indicators |
| GET | `/cti/observations` | Provider observations (provider, confidence, affected rules) |
| POST | `/cti/run` | Trigger CTI enrichment (provider-abstracted, API-based) |
| GET | `/rules/{rule_id}/cti` | CTI correlated to a rule |

## 6. Reports / AI (V10)
| Method | Path | Purpose |
|---|---|---|
| GET | `/reports` | List `llm_report` entries |
| GET | `/reports/{id}` | Report (output + evidence refs + provider/model/prompt-version + confidence) |
| POST | `/reports/generate` | Generate SOC/executive report from deterministic evidence |

## 7. Benchmark (V7)
| Method | Path | Purpose |
|---|---|---|
| GET | `/benchmarks/cases` | Ground-truth cases |
| POST | `/benchmarks/cases/import` · GET `/benchmarks/cases/export` | Import/export matrix |
| POST | `/benchmarks/run` | Run evaluation → results |
| GET | `/benchmarks/results` | Detected vs expected + precision/recall/F1/FP/FN |

## 8. Graph (V11 §12)
`GET /api/graph/policy-relationships` →
```json
{
  "nodes": [
    {"id":"vendor:fortinet","type":"vendor","label":"Fortinet"},
    {"id":"device:fgt1","type":"device","parent":"vendor:fortinet"},
    {"id":"object:web_server","type":"object","label":"WEB_SERVER"}
  ],
  "edges": [
    {"id":"rule:1","source":"object:lan_net","target":"object:web_server","type":"allow"},
    {"id":"anom:44","source":"rule:fgt1:10","target":"rule:pa1:12","type":"inconsistent_with"}
  ]
}
```
Node types: vendor/device/vdom_vsys/zone/interface/object/service/rule (+ risk/anomaly badges).
Edge types: allows/denies/uses_object/uses_service/shadows/conflicts/duplicates/inconsistent_with/
has_risk/correlates_with_threat. **Logical relationships only — never live traffic.**

## 9. Settings / auth
`/auth/login`, `/auth/logout`, `/auth/me`; `/settings/providers` (CTI/LLM config, secrets write-only),
`/settings/schedules` (polling). All admin-gated; secrets never returned.

## 10. Conventions
- Errors: structured `{detail}`; 400/401/403/404/409/422/429; **no stack traces or secrets**.
- Pagination: `page`, `page_size` (capped); list responses `{items,total,page,page_size,total_pages}`.
- Timestamps: ISO-8601 UTC. Async actions return a job/run id; clients poll status (SSE optional later).
