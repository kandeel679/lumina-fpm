"""Celery application configuration for Lumina FPM.

Uses Redis as the message broker and PostgreSQL (via SQLAlchemy) as the
result backend for durable task-result persistence.

Settings are tuned for reliability:
  - task_acks_late: tasks ACK only after completion (crash-safe)
  - worker_prefetch_multiplier = 1: no greedy prefetch
"""
from __future__ import annotations

import os

from celery import Celery

# ---------------------------------------------------------------------------
# Connection URLs
# ---------------------------------------------------------------------------
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

# Build the SQLAlchemy result-backend URL from DATABASE_URL.
# Celery expects the prefix "db+" for its SQLAlchemy result backend.
_raw_db_url = os.getenv("DATABASE_URL", "")
if _raw_db_url.startswith("postgresql://"):
    RESULT_BACKEND = f"db+{_raw_db_url}"
elif _raw_db_url.startswith("db+"):
    RESULT_BACKEND = _raw_db_url
else:
    # Fallback: store results in Redis if DATABASE_URL is misconfigured
    RESULT_BACKEND = REDIS_URL

# ---------------------------------------------------------------------------
# Celery instance
# ---------------------------------------------------------------------------
celery = Celery(
    "lumina_fpm",
    broker=REDIS_URL,
    backend=RESULT_BACKEND,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
celery.conf.update(
    # Reliability
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_track_started=True,

    # Serialization
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],

    # Timezone
    timezone="UTC",
    enable_utc=True,

    # Result expiry (24 hours)
    result_expires=86400,

    # Per-job-type queue routing (V2 §14.3, V3 Table 28, V13 Table 5) so slow
    # firewall polling never blocks analysis/CTI/reporting workloads.
    task_routes={
        "acquisition.*": {"queue": "acquisition"},
        "normalization.*": {"queue": "normalization"},
        "analysis.*": {"queue": "analysis"},
        "cti.*": {"queue": "cti"},
        "reporting.*": {"queue": "reporting"},
    },
)

# Explicitly register task modules
# (autodiscover_tasks expects a 'tasks.py' file inside each package,
#  but our modules are named per-domain)
celery.conf.include = [
    "tasks.acquisition",
    "tasks.normalization",
    "tasks.threat_intel",
    "tasks.anomaly",
]
