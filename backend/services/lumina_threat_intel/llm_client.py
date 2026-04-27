"""Unified LLM client for Lumina Threat Intel.

Supports Gemini (default), OpenAI, Anthropic, and Ollama via environment
variables. Uses structured JSON output mode when available.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Optional, Type

from pydantic import BaseModel, ValidationError

from .exceptions import LLMProviderError, LLMValidationError
from .prompts.shared import LLM_RETRY_INSTRUCTION

logger = logging.getLogger(__name__)

# Environment config
LTI_LLM_PROVIDER = os.getenv("LTI_LLM_PROVIDER", "gemini").lower()
LTI_LLM_MODEL = os.getenv("LTI_LLM_MODEL", "gemini-2.5-flash")
LTI_LLM_API_KEY = os.getenv("LTI_LLM_API_KEY", "")
LTI_LLM_TIMEOUT = int(os.getenv("LTI_LLM_TIMEOUT_SECONDS", "120"))
LTI_LLM_MAX_RETRIES = int(os.getenv("LTI_LLM_MAX_RETRIES", "3"))


def _call_gemini(prompt: str, model: str, api_key: str, timeout: int) -> str:
    """Call Google Gemini API and return raw text response."""
    try:
        import google.generativeai as genai
    except ImportError:
        raise LLMProviderError(
            "google-generativeai is not installed. "
            "Run: pip install google-generativeai"
        )

    genai.configure(api_key=api_key)
    gen_model = genai.GenerativeModel(model)
    response = gen_model.generate_content(
        prompt,
        generation_config=genai.GenerationConfig(
            temperature=0,
            response_mime_type="application/json",
        ),
        request_options={"timeout": timeout},
    )
    return response.text


def _call_openai(prompt: str, model: str, api_key: str, timeout: int) -> str:
    """Call OpenAI-compatible API and return raw text response."""
    try:
        from openai import OpenAI
    except ImportError:
        raise LLMProviderError(
            "openai is not installed. Run: pip install openai"
        )

    client = OpenAI(api_key=api_key, timeout=timeout)
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0,
        response_format={"type": "json_object"},
    )
    return response.choices[0].message.content or ""


def _call_anthropic(prompt: str, model: str, api_key: str, timeout: int) -> str:
    """Call Anthropic API and return raw text response."""
    try:
        import anthropic
    except ImportError:
        raise LLMProviderError(
            "anthropic is not installed. Run: pip install anthropic"
        )

    client = anthropic.Anthropic(api_key=api_key, timeout=timeout)
    response = client.messages.create(
        model=model,
        max_tokens=8192,
        temperature=0,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text


def _call_ollama(prompt: str, model: str, timeout: int) -> str:
    """Call local Ollama instance and return raw text response."""
    import requests

    base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    resp = requests.post(
        f"{base_url.rstrip('/')}/api/generate",
        json={
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0},
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json().get("response", "")


def _call_llm_raw(prompt: str) -> str:
    """Route to the configured LLM provider and return the raw text."""
    provider = LTI_LLM_PROVIDER
    model = LTI_LLM_MODEL
    api_key = LTI_LLM_API_KEY
    timeout = LTI_LLM_TIMEOUT

    if provider == "gemini":
        return _call_gemini(prompt, model, api_key, timeout)
    elif provider == "openai":
        return _call_openai(prompt, model, api_key, timeout)
    elif provider == "anthropic":
        return _call_anthropic(prompt, model, api_key, timeout)
    elif provider == "ollama":
        return _call_ollama(prompt, model, timeout)
    else:
        raise LLMProviderError(f"Unknown LLM provider: {provider}")


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
            raw_text = _call_llm_raw(current_prompt)
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
    except Exception as e:
        logger.error("LLM text call failed: %s", str(e))
        raise LLMProviderError(str(e)) from e
