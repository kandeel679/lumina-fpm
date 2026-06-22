"""Structured, secret-safe logging setup for LuminaFPM.

Volume 12 §8/§9 require that secrets are redacted from logs and that
security-relevant actions are auditable. This module provides a single
``configure_logging`` entry point used by the API and Celery workers, plus a
``SecretRedactingFilter`` that masks obvious credential material from log lines.
"""
from __future__ import annotations

import logging
import re
import sys

from core.config import settings

# Patterns for values that must never appear in logs (V12 §6).
_REDACT_PATTERNS = [
    re.compile(r"(api[_-]?key\"?\s*[:=]\s*\"?)([^\s\"',]+)", re.IGNORECASE),
    re.compile(r"(token\"?\s*[:=]\s*\"?)([^\s\"',]+)", re.IGNORECASE),
    re.compile(r"(password\"?\s*[:=]\s*\"?)([^\s\"',]+)", re.IGNORECASE),
    re.compile(r"(Authorization:\s*Bearer\s+)(\S+)", re.IGNORECASE),
]


class SecretRedactingFilter(logging.Filter):
    """Masks credential-looking substrings in log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            return True
        redacted = msg
        for pat in _REDACT_PATTERNS:
            redacted = pat.sub(r"\1***REDACTED***", redacted)
        if redacted != msg:
            record.msg = redacted
            record.args = ()
        return True


def configure_logging(level: str | None = None) -> None:
    """Configure root logging once, idempotently."""
    log_level = (level or settings.log_level or "INFO").upper()
    root = logging.getLogger()
    if getattr(root, "_lumina_configured", False):
        root.setLevel(log_level)
        return

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    handler.addFilter(SecretRedactingFilter())

    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(log_level)
    root._lumina_configured = True  # type: ignore[attr-defined]

    # Tame noisy third-party loggers.
    for noisy in ("urllib3", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
