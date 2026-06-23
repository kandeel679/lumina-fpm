"""API-based CTI enrichment subsystem (Volume 9).

Correlates the public IPs/domains referenced by firewall policy against external
threat-intel providers. CTI is NOT an anomaly by default — it contributes to risk
and can raise a labeled `threat_exposure` finding. API-based only (dark-web is
future). Internal/RFC1918 indicators are never sent to external providers.
"""
from .providers import CtiVerdict, build_providers

__all__ = ["CtiVerdict", "build_providers"]
