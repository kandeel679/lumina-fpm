"""Unified LLM client for Lumina Threat Intel.

Powered by Robin's proven LangChain-based LLM engine. Supports all providers
configured in Robin's llm_utils (OpenAI, Anthropic, Google Gemini, Ollama,
OpenRouter, llama.cpp).

The public interface (call_llm_structured, call_llm_text) is unchanged so
all existing callers (orchestrator, prompts) work without modification.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from typing import Optional, Type

from pydantic import BaseModel, ValidationError

from .exceptions import LLMProviderError, LLMValidationError
from .prompts.shared import LLM_RETRY_INSTRUCTION

logger = logging.getLogger(__name__)

# ── Robin import path setup ──
# Robin lives at services/robin — make sure Python can import it.
_robin_dir = os.path.join(
    os.path.dirname(__file__), os.pardir, "robin",
)
_robin_dir = os.path.normpath(_robin_dir)
if _robin_dir not in sys.path:
    sys.path.insert(0, _robin_dir)

# Now import Robin's LLM machinery
from llm import get_llm as _robin_get_llm          # noqa: E402
from llm_utils import get_model_choices             # noqa: E402

# ── Configuration ──
# Use ROBIN_MODEL env var, fall back to the Lumina-specific vars for compat
ROBIN_MODEL = os.getenv(
    "ROBIN_MODEL",
    os.getenv("LTI_LLM_MODEL", "gemini-2.5-flash"),
)
LTI_LLM_MAX_RETRIES = int(os.getenv("LTI_LLM_MAX_RETRIES", "3"))

# Cache the LLM instance so we don't re-create it on every call
_llm_instance = None


def _get_llm():
    """Lazy-initialize and cache the Robin LLM instance."""
    global _llm_instance
    if _llm_instance is None:
        logger.info("Initializing Robin LLM with model: %s", ROBIN_MODEL)
        try:
            _llm_instance = _robin_get_llm(ROBIN_MODEL)
        except Exception as e:
            raise LLMProviderError(
                f"Failed to initialize Robin LLM (model={ROBIN_MODEL}): {e}"
            ) from e
    return _llm_instance


def _call_llm_raw(prompt: str, tier: str = "strong") -> str:
    """Invoke the LTI Model Router (tiered, budget-aware) and return raw text.

    `tier` selects the model class: "fast" (cheap, simple steps), "strong"
    (Findings reasoning), or "premium" (max quality). The router downgrades to
    the cheapest model when the soft budget cap is reached.
    """
    try:
        from .model_router import invoke_with_fallback
        text, _model_used = invoke_with_fallback(prompt, tier=tier)
        return text or ""
    except Exception as e:
        raise LLMProviderError(f"LLM call failed: {e}") from e


def _extract_json(text: str) -> str:
    """Strip markdown fences and whitespace from LLM output to isolate JSON."""
    text = text.strip()
    # Strip ```json ... ``` fences
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first line (```json) and last line (```)
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines).strip()
    return text


def call_llm_structured(
    prompt: str,
    output_schema: Type[BaseModel],
    max_retries: Optional[int] = None,
    tier: str = "strong",
) -> BaseModel:
    """Call the LLM and validate the output against a Pydantic schema.

    Retries up to max_retries times if the output fails validation,
    appending the validation error to the prompt on each retry.

    Returns:
        A validated Pydantic model instance.

    Raises:
        LLMValidationError: After all retries exhausted.
        LLMProviderError: On unrecoverable provider errors.
    """
    if max_retries is None:
        max_retries = LTI_LLM_MAX_RETRIES

    current_prompt = prompt
    last_error: Optional[str] = None

    for attempt in range(1, max_retries + 1):
        try:
            raw_text = _call_llm_raw(current_prompt, tier=tier)
            logger.info(
                "LLM call attempt %d/%d — got %d chars",
                attempt, max_retries, len(raw_text),
            )

            json_text = _extract_json(raw_text)
            parsed = json.loads(json_text)
            result = output_schema.model_validate(parsed)
            return result

        except (json.JSONDecodeError, ValidationError) as e:
            last_error = str(e)
            logger.warning(
                "LLM output validation failed (attempt %d/%d): %s",
                attempt, max_retries, last_error[:200],
            )
            # Append validation error as retry instruction
            retry_note = LLM_RETRY_INSTRUCTION.format(error=last_error[:500])
            current_prompt = prompt + "\n\n" + retry_note

        except LLMProviderError:
            raise

        except Exception as e:
            logger.error("LLM provider error: %s", str(e))
            raise LLMProviderError(str(e)) from e

    raise LLMValidationError(
        f"LLM output failed validation after {max_retries} attempts. "
        f"Last error: {last_error}"
    )


def call_llm_text(prompt: str) -> str:
    """Call the LLM and return the raw text (no schema validation).
    Used for narrative summary generation.
    """
    try:
        return _call_llm_raw(prompt)
    except LLMProviderError:
        raise
    except Exception as e:
        logger.error("LLM text call failed: %s", str(e))
        raise LLMProviderError(str(e)) from e


def get_robin_model_name() -> str:
    """Return the configured Robin model name for report metadata."""
    return ROBIN_MODEL
