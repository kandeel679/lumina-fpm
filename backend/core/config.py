"""Centralized, environment-based configuration for LuminaFPM.

Volume 13 §6 defines the canonical environment variables. Volume 12 requires that
secrets come from the environment / a secret manager and never from source code.

This module is the single source of truth for runtime configuration. Import the
shared ``settings`` instance rather than calling ``os.getenv`` directly, so that
defaults, validation, and documentation stay in one place.

    from core.config import settings
    engine = create_engine(settings.database_url)

Falls back to plain ``os.getenv`` semantics if ``pydantic-settings`` is not yet
installed, so importing this module never hard-fails a partially-built image.
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import List

try:  # Preferred: typed, validated settings
    from pydantic import Field
    from pydantic_settings import BaseSettings, SettingsConfigDict

    _HAVE_PYDANTIC_SETTINGS = True
except Exception:  # pragma: no cover - fallback when dep not yet installed
    _HAVE_PYDANTIC_SETTINGS = False


def _split_csv(value: str | None) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


if _HAVE_PYDANTIC_SETTINGS:

    class Settings(BaseSettings):
        """Typed application settings loaded from the environment / .env."""

        model_config = SettingsConfigDict(
            env_file=".env", env_file_encoding="utf-8", extra="ignore"
        )

        # ── Identity ──
        app_name: str = "LuminaFPM"
        app_version: str = "1.0.0-dev"
        environment: str = Field(default="development")  # development|lab|staging|production
        log_level: str = Field(default="INFO")

        # ── Database / broker (V13 §6) ──
        database_url: str = Field(
            default="postgresql://lumina:lumina@db:5432/lumina_fpm"
        )
        redis_url: str = Field(default="redis://redis:6379/0")

        # ── Security (V12) ──
        secret_key: str = Field(default="change-me-in-production")
        encryption_key: str = Field(default="")  # Fernet key for credential encryption
        cors_allowed_origins_raw: str = Field(
            default="http://localhost:5173", alias="CORS_ALLOWED_ORIGINS"
        )
        access_token_expire_minutes: int = 30

        # ── Firewall acquisition (V3) ──
        # Lab mode may allow insecure TLS for self-signed firewall certs (V3 Table 25).
        firewall_tls_verify: bool = Field(default=True)
        acquisition_raw_dir: str = Field(default="/app/raw_acquisition")
        acquisition_timeout_seconds: int = 60
        acquisition_max_retries: int = 3

        # ── LLM / CTI (V9, V10) ──
        llm_provider: str = Field(default="gemini")  # gemini|openai|ollama
        llm_model: str = Field(default="gemini-2.5-flash")
        llm_api_key: str = Field(default="")
        ollama_base_url: str = Field(default="http://ollama:11434")
        cti_provider_keys_raw: str = Field(default="", alias="CTI_PROVIDER_KEYS")
        # Data minimization (V9 §4 / V12 §10): never send internal indicators out by default.
        cti_allow_internal_indicators: bool = Field(default=False)

        # ── Feature flags ──
        # Dark-web / Tor / Robin is future/optional only (ADR LFPM-IMPL-005); off by default.
        enable_darkweb_intel: bool = Field(default=False)

        @property
        def cors_allowed_origins(self) -> List[str]:
            return _split_csv(self.cors_allowed_origins_raw)

        @property
        def is_production(self) -> bool:
            return self.environment.lower() == "production"

else:  # pragma: no cover - lightweight fallback

    class Settings:  # type: ignore[no-redef]
        def __init__(self) -> None:
            g = os.getenv
            self.app_name = g("APP_NAME", "LuminaFPM")
            self.app_version = g("APP_VERSION", "1.0.0-dev")
            self.environment = g("ENVIRONMENT", "development")
            self.log_level = g("LOG_LEVEL", "INFO")
            self.database_url = g(
                "DATABASE_URL", "postgresql://lumina:lumina@db:5432/lumina_fpm"
            )
            self.redis_url = g("REDIS_URL", "redis://redis:6379/0")
            self.secret_key = g("SECRET_KEY", "change-me-in-production")
            self.encryption_key = g("ENCRYPTION_KEY", "")
            self.cors_allowed_origins_raw = g(
                "CORS_ALLOWED_ORIGINS", "http://localhost:5173"
            )
            self.access_token_expire_minutes = int(g("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
            self.firewall_tls_verify = g("FIREWALL_TLS_VERIFY", "true").lower() == "true"
            self.acquisition_raw_dir = g("ACQUISITION_RAW_DIR", "/app/raw_acquisition")
            self.acquisition_timeout_seconds = int(g("ACQUISITION_TIMEOUT_SECONDS", "60"))
            self.acquisition_max_retries = int(g("ACQUISITION_MAX_RETRIES", "3"))
            self.llm_provider = g("LLM_PROVIDER", "gemini")
            self.llm_model = g("LLM_MODEL", "gemini-2.5-flash")
            self.llm_api_key = g("LLM_API_KEY", "")
            self.ollama_base_url = g("OLLAMA_BASE_URL", "http://ollama:11434")
            self.cti_provider_keys_raw = g("CTI_PROVIDER_KEYS", "")
            self.cti_allow_internal_indicators = (
                g("CTI_ALLOW_INTERNAL_INDICATORS", "false").lower() == "true"
            )
            self.enable_darkweb_intel = (
                g("ENABLE_DARKWEB_INTEL", "false").lower() == "true"
            )

        @property
        def cors_allowed_origins(self) -> List[str]:
            return _split_csv(self.cors_allowed_origins_raw)

        @property
        def is_production(self) -> bool:
            return self.environment.lower() == "production"


@lru_cache
def get_settings() -> "Settings":
    return Settings()


settings = get_settings()
