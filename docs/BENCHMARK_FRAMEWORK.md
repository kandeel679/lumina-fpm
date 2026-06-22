# LuminaFPM — Benchmark & Evaluation Framework

> Authoritative source: **Volume 7** (Benchmark & Evaluation) + V1 §13, V5 §11, V6 §13.
> Purpose: **prove the anomaly engine works** against ground truth, not visual inspection.

## 1. Philosophy (V7 §2)
Every anomaly has an explicit expected trigger. The engine is evaluated against a ground-truth
matrix. **Atomic** cases validate detector correctness; **compound** cases validate realistic
rulebase behavior. Runtime anomalies are conditional/simulated and must be labeled.

## 2. Phase-1 dataset scope (V7 Table 2)
| Element | Decision |
|---|---|
| FortiGate rules | ~22 |
| Palo Alto rules | ~23 |
| Total phase-1 | ~45 |
| Taxonomy coverage | 46 categories |
| Role | Phase-1 benchmark, not final maximum |
| Lab model | Hybrid Parallel Shared-Network |

Shared object baseline on **both** vendors (V7 §7): `LAN_NET, DMZ_NET, DB_NET, WEB_SERVER, DB_SERVER,
ADMIN_PC, MALICIOUS_IP`. Rule names encode vendor+action+source+dest+service. Ordering intentionally
creates shadowing/redundancy. Descriptions/tags simulate temporary/test/old/high-change rules.

## 3. Data model — see DATABASE_SCHEMA_V4 §8
`benchmark_case(case_id, case_type, anomaly_type, device_a_id, rule_a_id, device_b_id, rule_b_id,
expected_severity, expected_reason, detection_mode, required_fields)` and
`benchmark_result(case_id, analysis_run_id, detected, detected_anomaly_id, match_quality,
false_positive, false_negative, notes)`.

## 4. Ground-truth matrix columns (V7 Table 3)
`case_id · case_type(atomic|compound) · device_a · rule_a · device_b · rule_b · expected_anomaly ·
expected_reason · expected_severity · detection_mode · required_fields`.

## 5. Example cases
**Atomic (V7 Table 4):** shadowing-only; redundancy-only; missing-logging-only; unprotected-allow-only;
poor-naming-only.

**Compound (V7 Table 5):**
| Rule | Expected findings |
|---|---|
| ANY→DB allow, no profile, logging off | overly_permissive, any_to_sensitive, unprotected_allow, logging_disabled, high risk |
| Temp vendor rule, no schedule, broad service | temporary_rule, schedule_misconfiguration, wide_port_range, missing_description |
| FGT allow vs PA deny same canonical traffic | cross_device_inconsistency, inconsistent_actions |
| Disabled rule that would expose DB to ANY | disabled_rule, inactive_but_risky_rule, any_to_sensitive |

**Cross-device row (V7 §8):**
```
case_id: BENCH-044-A   type: compound
A: FortiGate / FGT_ALLOW_LAN_TO_DMZ_HTTPS
B: Palo Alto / PA_DENY_LAN_TO_DMZ_HTTPS
expected: cross_device_inconsistency   mode: config_only   severity: critical
reason: same canonical source/destination/service, different actions across vendors
```

## 6. Metrics (V7 Table 6)
TP = expected detected · FP = reported but not expected · FN = expected not detected ·
**Precision = TP/(TP+FP)** · **Recall = TP/(TP+FN)** · **F1** = harmonic mean · severity-match rate ·
explanation-match quality (reviewer score).

## 7. Execution workflow (V7 §10)
1 generate/import benchmark rules → 2 acquisition → 3 parse+normalize → 4 run anomaly engine →
5 compare `rule_anomaly` vs `benchmark_case` → 6 write `benchmark_result` → 7 compute
precision/recall/F1/FP/FN → 8 generate benchmark report.

## 8. Acceptance (V7 Table 7)
All core config-only anomalies detected in atomic cases · cross-device policy conflict **and**
security-posture difference detected · compound major findings appear · simulated cases clearly
labeled · every finding shows affected rule (+ related rule) + reason.

## 9. Reporting (V7 §12, V11 §10)
Benchmark Center shows total expected / detected / missed / extra; per-category pass/fail; FN
prioritized for developer review; FP shows rule + detection reason; export DOCX/PDF (future).

## 10. Developer checklist (V7 §13)
Create benchmark tables · build import/export format · generate phase-1 policies for both vendors ·
automate benchmark runs after every engine change · surface results in Benchmark Center · preserve
the dataset as **regression-test evidence**. Fix false negatives **before** UI polish (V14 §10).
