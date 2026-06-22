# lab/ — benchmark provisioning (LAB-ONLY, write tooling)

> ⚠️ **Not part of the LuminaFPM platform.** The platform is strictly read-only against firewalls.
> This directory holds operator tooling that *writes* the phase-1 benchmark policy set to the
> controlled lab firewalls so the deterministic anomaly engine has data to analyze (Volume 7 §13).
> Use a **separate write-capable credential** — never the read-only token LuminaFPM stores.

## Files
- `benchmark_dataset.py` — logical rule specs for FortiGate + Palo Alto + design ground truth
  (intended anomalies per rule; list order = rule evaluation order).
- `provision_benchmark.py` — translates specs to vendor API payloads and pushes them
  (FortiGate REST POST; Palo Alto XML `set` + `commit`). Default is **dry-run**.

## Preview (no network) + write the ground-truth file
```bash
python lab/provision_benchmark.py --dry-run --out lab/benchmark_ground_truth.json
```

## Push to the lab firewalls (writes config — requires --apply AND --confirm)
```bash
python lab/provision_benchmark.py --apply --confirm \
  --fgt-host 192.168.55.10 --fgt-token <FGT_WRITE_TOKEN> \
  --pan-host 192.168.55.20 --pan-key <PAN_API_KEY>
```
Then, in LuminaFPM: poll each device → `POST /api/v1/anomalies/run` (all-scope) → review findings.

## Notes
- Logical zones map to vendors in `provision_benchmark.py` (`FGT_INTF`, `PAN_ZONE`); adjust if your
  lab zone/interface names differ (e.g. the Palo Alto `db` zone).
- Inspection rules reference an FGT `default` AV profile and a PAN `default` profile group; create
  those (or edit the builders) if absent.
- All referenced address/service objects already exist in the lab baseline.
- The design ground truth here is validated by the Phase-6 benchmark runner (precision/recall/F1).
