# LuminaFPM — Deterministic Anomaly Engine Specification

> Authoritative source: **Volume 6** (Anomaly Detection Engine) + V2 §10.
> Binding rule (V6 Table 1): the engine is **deterministic** and analyzes **normalized policies
> only**. AI may *explain* findings but is **never** the authoritative detector.

> ⚠️ The current `backend/services/anomaly_engine.py` is a **mock** (random anomalies on random
> rules). It directly violates this volume and is replaced by the engine specified here.

---

## 1. Engine architecture (V6 §2)

```
PostgreSQL normalized repo
        │
   Object & service expansion
        │
   Rule comparator / policy analyzer
        ├─ single-rule checks
        ├─ pairwise (same-device) checks
        ├─ cross-device checks
        └─ historical / conditional checks
        │
   rule_anomaly + anomaly_execution_log + (trigger) risk_assessment
```

## 2. Inputs (V6 Table 2) / Outputs (V2 §10.3)
**Reads:** `policy_rule`, `rule_object_mapping`, `network_object`, `normalized_object`,
`object_normalization_mapping`, `normalized_service`, `service_normalization_mapping`; optionally
`rule_snapshot` (history), log/telemetry metadata (conditional), `benchmark_case` (simulated).
**Writes:** `rule_anomaly`, `anomaly_execution_log`, `benchmark_result`, and triggers `risk_assessment`.

## 3. Output contract — every finding (V6 Table 3, V2 §10.4)
`anomaly_type` (taxonomy) · `rule_id` · `related_rule_id` (pairwise) · `severity_level`
(critical|high|medium|low) · `confidence` (0.00–1.00) · `description` (technical reason) · `evidence`
(JSONB of rule fields/objects) · `recommendation` · `detection_mode`
(config_only|conditional|simulated|future_enhanced) · `analysis_run_id` · `detected_at` · `status`.
**No vague findings** — each must link to the exact affected rule with evidence.

## 4. Classification (V6 Table 4)
| Class | Meaning |
|---|---|
| `config_only` (fully implemented) | from configuration only — ship first |
| `conditional` | needs logs/hit-counts/history if available |
| `benchmark_simulated` | simulated via lab metadata for validation; must be labeled |
| `future_enhanced` | needs enterprise telemetry/integrations |

Runtime findings must be labeled telemetry-supported or benchmark-simulated; **no finding may claim
live-traffic evidence unless live telemetry was actually ingested** (V6 §9).

---

## 5. The 46-anomaly taxonomy (V6 Table 5)

| # | Anomaly | Category | Data mode | v1 target |
|---|---|---|---|---|
| 1 | Shadowing | Logic | Config | **config_only** |
| 2 | Redundancy | Logic | Config | **config_only** |
| 3 | Rule conflict | Logic | Config | **config_only** |
| 4 | Over-permissive | Security | Config | **config_only** |
| 5 | Unprotected allow (no profile) | Security | Config | **config_only** |
| 6 | Logging disabled | Security | Config | **config_only** |
| 7 | Any-to-sensitive destination | Security | Config | **config_only** |
| 8 | Wide port range | Security | Config | **config_only** |
| 9 | Ordering anomaly | Logic | Config | **config_only** |
| 10 | Duplicate rules | Logic | Config | **config_only** |
| 11 | Overlapping rules | Logic | Config | **config_only** |
| 12 | Inconsistent actions | Logic | Config | **config_only** |
| 13 | Unused rules | Lifecycle | Conditional/Sim | conditional |
| 14 | Policy drift | Lifecycle | History/Sim | conditional |
| 15 | Temporary rules active | Lifecycle | Config | **config_only** |
| 16 | Rule age issue | Governance | History | conditional |
| 17 | Rule explosion | Governance | History | conditional |
| 18 | Missing description | Governance | Config | **config_only** |
| 19 | Poor naming | Governance | Config | **config_only** |
| 20 | Disabled rules review | Governance | Config | **config_only** |
| 21 | Complex rule | Design | Config | **config_only** |
| 22 | Hardcoded IP | Design | Config | **config_only** |
| 23 | Unusual port usage | Design | Config | config_only |
| 24 | Rule complexity score | Design | Config | config_only |
| 25 | Rule risk score | Risk | Risk engine | risk engine |
| 26 | Auto recommendation | Smart | Engine output | engine output |
| 27 | Zone mismatch | Firewall | Config | **config_only** |
| 28 | Negate misuse | Firewall | Config | **config_only** |
| 29 | Schedule misconfiguration | Firewall | Config | **config_only** |
| 30 | NAT risk | Firewall | Config | config_only (where extractable) |
| 31 | Cross-VDOM conflict | Firewall | Config | config_only |
| 32 | Missing logging on critical rules | Firewall | Config | **config_only** |
| 33 | Weak security profile | Firewall | Config | **config_only** |
| 34 | Object sprawl | Firewall | Config | **config_only** |
| 35 | Direction issue | Firewall | Config | config_only |
| 36 | Threat exposure | Risk | CTI | cti |
| 37 | Hit-distribution anomaly | Advanced | Conditional/Sim | conditional |
| 38 | Time-of-day usage | Advanced | Conditional/Sim | conditional |
| 39 | Geo-based violation | Advanced | Future/CTI | future_enhanced |
| 40 | Policy simulation gap | Advanced | Benchmark | benchmark_simulated |
| 41 | Rule change frequency | Advanced | History/Sim | conditional |
| 42 | Inactive but risky rule | Advanced | Config | **config_only** |
| 43 | Rule dependency risk | Advanced | Config | config_only |
| 44 | **Cross-device inconsistency** | Advanced | Config | **config_only** |
| 45 | Compliance violation | Advanced | Policy/Config | config_only (rule-driven) |
| 46 | Asymmetric rule | Advanced | Config/Sim | config_only |

### v1 "ship-first" config-only core (mandate P4 + V1 §12)
1 Shadowing · 2 Redundancy · 3 Conflict · 4 Over-permissive · 5 Unprotected allow · 6 Logging
disabled · 7 Any-to-sensitive · 8 Wide port range · 10 Duplicate · 15 Temporary-without-schedule ·
18 Missing description · 20 Disabled-rule review · 27 Zone mismatch · 32 Missing logging on critical ·
33 Weak profile · 34 Object sprawl (+ service sprawl) · 44 Cross-device inconsistency (policy conflict
+ security-posture difference).

---

## 6. Core detection algorithms (V6 §7)

**Shadowing (§7.1):**
```
for lower_rule in ordered_rules:
  for higher_rule before lower_rule:
    if same_direction(higher, lower)
       and higher.match_set ⊇ lower.match_set
       and higher.action prevents lower from being evaluated:
         create_anomaly(lower, 'shadowed', related_rule=higher)
```

**Conflict (§7.2):**
```
if a.direction == b.direction
   and overlap(a.sources,b.sources) and overlap(a.destinations,b.destinations)
   and overlap(a.services,b.services) and a.action != b.action:
     create_anomaly('conflicting', a, related_rule=b)
```

**Redundancy (§7.3):**
```
if a.match_conditions == b.match_conditions
   and a.action == b.action and a.security_posture == b.security_posture:
     create_anomaly('redundant', a, related_rule=b)
```

Match-set comparison uses **expanded** object/service sets (post group-expansion), canonical ANY =
`0.0.0.0/0`/`::/0` and `ANY_SERVICE`. Superset/overlap operate on expanded CIDR/port ranges.

## 7. Cross-device inconsistency (V6 §8, Table 6) — mandatory v1
- **Policy conflict:** equivalent canonical (source,destination,service) → different actions across
  vendors → `cross_device_inconsistency`. Evidence includes **both** rules.
- **Security-posture difference:** equivalent allow on both, but one lacks logging/inspection →
  `cross_device_security_posture_inconsistency`.
Equivalence is established through the normalized object/service correlation, not raw names.

## 8. Severity & confidence (V6 Table 7)
- **Critical:** direct exposure, conflicting access decision, unprotected broad allow, CTI-confirmed exposure.
- **High:** shadowed critical rule, missing logging on important rule, weak posture difference.
- **Medium:** redundancy, schedule issue, moderate governance.
- **Low:** cleanup, unused/disabled-rule review.
Confidence reflects match certainty (e.g. expanded-set exactness, derived-UUID vs real UUID,
unknown-service penalty).

## 9. Execution lifecycle (V6 §11)
1 create `anomaly_execution_log` row · 2 load normalized policies for scope · 3 expand objects/services ·
4 single-rule checks · 5 pairwise same-device · 6 cross-device · 7 write `rule_anomaly` · 8 trigger
risk recalculation · 9 finalize log with counts + status.

## 10. False-positive handling (V6 §12)
Analysts may set `accepted_risk | suppressed | false_positive | resolved`. Suppression requires
reason+user+timestamp(+optional expiry), is never hard-deleted, and **benchmark mode must not allow
suppression to hide evaluation errors**.

## 11. Testing (V6 §13, V14 §9)
Unit-test **every** detector; atomic benchmark = one-anomaly validation; compound = realistic overlap;
compute precision/recall/FP after each run; regression-test shadowing+conflict after any normalization
change. Detectors implemented as independent classes/functions accepting **normalized models only**,
each producing an evidence payload.
