"""LLM provider abstraction (Volume 10 §4) — pluggable, evidence-grounded.

`GeminiProvider` calls the real Gemini API (key-gated). `OfflineProvider` is a
deterministic, network-free fallback that renders the supplied evidence into a
plain report — so if the LLM is unavailable the platform still produces output
(V10 §11). All providers receive a low temperature to keep output grounded.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Optional

from core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class LlmResult:
    output: str
    provider: str
    model: str
    status: str                 # complete | partial | failed
    error: Optional[str] = None


class LLMProvider(abc.ABC):
    name: str = "unknown"
    model: str = ""

    @abc.abstractmethod
    def generate(self, system: str, user: str) -> LlmResult:
        ...


class OfflineProvider(LLMProvider):
    """Deterministic fallback: renders the evidence prompt verbatim, no network.

    Clearly labelled as a non-AI rendering so it is never mistaken for an LLM
    analysis. Guarantees the platform still reports when no LLM key is configured."""

    name = "offline"
    model = "deterministic-render/1.0"

    def generate(self, system: str, user: str) -> LlmResult:
        body = (
            "## SOC Report (deterministic rendering — no LLM configured)\n\n"
            "_The text below is the structured evidence itself, not an AI analysis._\n\n"
            f"{user}\n"
        )
        return LlmResult(output=body, provider=self.name, model=self.model, status="complete")


class GeminiProvider(LLMProvider):
    """Google Gemini (generativelanguage API), used only when a key is configured."""

    name = "gemini"
    _BASE = "https://generativelanguage.googleapis.com/v1beta/models"

    def __init__(self, api_key: str, model: str = "gemini-2.5-flash", timeout: int = 60):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def generate(self, system: str, user: str) -> LlmResult:
        import requests  # lazy
        url = f"{self._BASE}/{self.model}:generateContent?key={self.api_key}"
        payload = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 2048},
        }
        try:
            resp = requests.post(url, json=payload, timeout=self.timeout)
        except Exception as exc:  # noqa: BLE001 - LLM failure must not break the platform
            logger.warning("Gemini request failed: %s", exc)
            return LlmResult(output="", provider=self.name, model=self.model,
                             status="failed", error=str(exc))
        if resp.status_code != 200:
            logger.warning("Gemini HTTP %s: %s", resp.status_code, resp.text[:200])
            return LlmResult(output="", provider=self.name, model=self.model,
                             status="failed", error=f"http {resp.status_code}")
        try:
            data = resp.json()
            text = data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as exc:  # noqa: BLE001
            return LlmResult(output="", provider=self.name, model=self.model,
                             status="failed", error=f"malformed response: {exc}")
        return LlmResult(output=text, provider=self.name, model=self.model, status="complete")


def build_provider(provider_name: str, api_key: str, model: str) -> LLMProvider:
    """Select the provider from config; fall back to offline when unkeyed (V10 §11)."""
    name = (provider_name or "gemini").lower()
    if name == "gemini" and api_key:
        return GeminiProvider(api_key, model or "gemini-2.5-flash")
    # OpenAI / Ollama adapters plug in here (same interface) when configured.
    return OfflineProvider()
