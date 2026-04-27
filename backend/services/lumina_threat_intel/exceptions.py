"""Module-specific exceptions for Lumina Threat Intel."""
from __future__ import annotations


class ThreatIntelError(Exception):
    """Base exception for the threat-intel module."""


class ScanAlreadyRunningError(ThreatIntelError):
    """Raised when a scan is triggered while one is already in progress."""


class ScanTimeoutError(ThreatIntelError):
    """Raised when a scan exceeds the total allowed wall-clock time."""


class LLMValidationError(ThreatIntelError):
    """Raised when the LLM returns output that fails Pydantic validation
    after all retry attempts have been exhausted."""


class LLMProviderError(ThreatIntelError):
    """Raised on unrecoverable LLM provider errors (auth, quota, etc.)."""


class ScraperError(ThreatIntelError):
    """Raised on scraper-level failures (Tor unreachable, etc.)."""


class RateLimitExceededError(ThreatIntelError):
    """Raised when user/tenant rate limits are exceeded."""
