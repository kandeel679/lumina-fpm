"""Benchmark API (Volume 7).

Scores the deterministic anomaly engine against the ground-truth matrix and
exposes precision/recall/F1 — the acceptance gate and regression guard. Pure DB
analysis; never touches a firewall.
"""
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import get_db_session
from models import models
from services.benchmark.runner import run_benchmark

router = APIRouter(prefix="/api/v1/benchmark", tags=["Benchmark"])


class RunRequest(BaseModel):
    analysis_run_id: Optional[int] = None  # omit = score the latest analysis run


@router.post("/run")
def run(req: RunRequest, db: Session = Depends(get_db_session)):
    """Score an analysis run against ground truth; persists benchmark_case/result."""
    return run_benchmark(db, req.analysis_run_id)


@router.get("/report")
def report(db: Session = Depends(get_db_session)):
    """Read the persisted benchmark results (latest run scored)."""
    rows = (
        db.query(models.BenchmarkResult, models.BenchmarkCase)
        .join(models.BenchmarkCase, models.BenchmarkResult.case_id == models.BenchmarkCase.case_id)
        .all()
    )
    if not rows:
        return {"cases": 0, "detail": "no benchmark has been run yet"}
    total = len(rows)
    detected = sum(1 for r, _ in rows if r.detected)
    sev_ok = sum(1 for r, _ in rows if r.match_quality == "exact")
    run_id = rows[0][0].analysis_run_id
    return {
        "analysis_run_id": run_id,
        "expected_cases": total,
        "detected": detected,
        "missed": total - detected,
        "recall": round(detected / total, 4) if total else 1.0,
        "severity_match_rate": round(sev_ok / detected, 4) if detected else 1.0,
        "cases": [
            {
                "anomaly_type": case.anomaly_type,
                "case_type": case.case_type,
                "expected_severity": case.expected_severity,
                "detected": res.detected,
                "match_quality": res.match_quality,
                "rule_a_id": case.rule_a_id,
                "rule_b_id": case.rule_b_id,
            }
            for res, case in rows
        ],
    }
