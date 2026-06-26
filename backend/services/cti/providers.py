"""CTI provider abstraction (Volume 9 §6).

Pluggable threat-intel providers behind one interface. Each returns a normalized
`CtiVerdict` (or None for "no information"), so the runner is provider-agnostic.

- `AbuseIPDBProvider` — real REST lookups, activated only when an API key is set.
- `LabOfflineProvider` — deterministic, no network; knows a small all-list of
  well-known-bad lab indicators (e.g. the Tor exit 185.220.101.1) so CTI is
  demonstrable/testable offline. Every observation records its provider, so lab
  verdicts are clearly distinguishable from live provider evidence (V9 §13).
"""
from __future__ import annotations

import abc
import hashlib
import json
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from core.logging import get_logger

logger = get_logger(__name__)

# Offline known-bad indicator list lives in a versioned data file (not hardcoded),
# mirroring backend/data/cve_reference.json. Override with CTI_INDICATORS_PATH.
_CTI_INDICATORS_PATH = os.getenv(
    "CTI_INDICATORS_PATH",
    str(Path(__file__).resolve().parents[2] / "data" / "cti_indicators.json"),
)


@lru_cache(maxsize=1)
def _load_known_bad() -> dict:
    """Load the offline known-bad list -> {value: (threat_type, severity, confidence, summary)}.
    Returns {} on any read/parse error (runtime resilience); the test suite asserts the file
    is present and non-empty so a missing file fails loudly in CI."""
    try:
        with open(_CTI_INDICATORS_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        return {
            i["value"]: (i.get("threat_type"), i.get("severity", "high"),
                         float(i.get("confidence", 0.85)), i.get("summary", ""))
            for i in data.get("indicators", []) if i.get("value")
        }
    except Exception as exc:  # noqa: BLE001 — never hard-fail import; tests gate completeness
        logger.warning("CTI indicator list load failed from %s (non-fatal): %s",
                       _CTI_INDICATORS_PATH, str(exc)[:150])
        return {}


@dataclass
class CtiVerdict:
    provider: str
    malicious: bool
    severity: str                 # critical | high | medium | low | info
    confidence: float             # 0.0 - 1.0
    threat_type: Optional[str] = None   # malware | c2 | scanner | botnet | tor_exit | ...
    summary: Optional[str] = None
    reference: Optional[str] = None
    raw_hash: Optional[str] = None


class CtiProvider(abc.ABC):
    name: str = "unknown"

    @abc.abstractmethod
    def lookup_ip(self, value: str) -> Optional[CtiVerdict]:
        ...

    def lookup_domain(self, value: str) -> Optional[CtiVerdict]:  # optional override
        return None


class LabOfflineProvider(CtiProvider):
    """Deterministic, network-free provider for offline validation (lab indicators)."""

    name = "lab_offline"
    # Loaded from backend/data/cti_indicators.json (not hardcoded). Real, documented bad
    # IPs (e.g. 185.220.101.1 — a long-standing Tor exit / abuse source).
    KNOWN_BAD = _load_known_bad()

    def lookup_ip(self, value: str) -> Optional[CtiVerdict]:
        hit = self.KNOWN_BAD.get(value)
        if not hit:
            return None
        threat_type, severity, confidence, summary = hit
        return CtiVerdict(
            provider=self.name, malicious=True, severity=severity, confidence=confidence,
            threat_type=threat_type, summary=summary, reference="lab:static-known-bad",
            raw_hash=hashlib.sha256(f"{self.name}:{value}".encode()).hexdigest(),
        )


class AbuseIPDBProvider(CtiProvider):
    """Real AbuseIPDB lookups (https://www.abuseipdb.com/) — used only when keyed."""

    name = "abuseipdb"
    _ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str, malicious_threshold: int = 25, timeout: int = 15):
        self.api_key = api_key
        self.threshold = malicious_threshold
        self.timeout = timeout

    def lookup_ip(self, value: str) -> Optional[CtiVerdict]:
        import requests  # lazy
        try:
            resp = requests.get(
                self._ENDPOINT,
                params={"ipAddress": value, "maxAgeInDays": 90},
                headers={"Key": self.api_key, "Accept": "application/json"},
                timeout=self.timeout,
            )
        except Exception as exc:  # noqa: BLE001 - provider outage must not break enrichment
            logger.warning("AbuseIPDB lookup failed for %s: %s", value, exc)
            return None
        if resp.status_code != 200:
            logger.warning("AbuseIPDB %s -> HTTP %s", value, resp.status_code)
            return None
        data = (resp.json() or {}).get("data", {})
        score = int(data.get("abuseConfidenceScore", 0) or 0)
        malicious = score >= self.threshold
        severity = ("critical" if score >= 90 else "high" if score >= 50
                    else "medium" if score >= self.threshold else "low")
        return CtiVerdict(
            provider=self.name, malicious=malicious, severity=severity,
            confidence=round(score / 100.0, 2),
            threat_type="abuse" if malicious else None,
            summary=(f"AbuseIPDB confidence {score}%, reports={data.get('totalReports', 0)}, "
                     f"country={data.get('countryCode')}"),
            reference=f"https://www.abuseipdb.com/check/{value}",
            raw_hash=hashlib.sha256(resp.text.encode()).hexdigest(),
        )


def _parse_provider_keys(raw: str) -> dict:
    """'abuseipdb=KEY,otx=KEY' -> {'abuseipdb': 'KEY', ...}."""
    out = {}
    for part in (raw or "").split(","):
        part = part.strip()
        if "=" in part:
            name, _, key = part.partition("=")
            if name.strip() and key.strip():
                out[name.strip().lower()] = key.strip()
    return out


def build_providers(provider_keys_raw: str) -> List[CtiProvider]:
    """Construct the active providers. The offline lab provider is always present
    (deterministic baseline); real providers are added when their key is configured."""
    providers: List[CtiProvider] = [LabOfflineProvider()]
    keys = _parse_provider_keys(provider_keys_raw)
    if "abuseipdb" in keys:
        providers.append(AbuseIPDBProvider(keys["abuseipdb"]))
    # OTX / VirusTotal adapters plug in here when keyed (same interface).
    return providers
