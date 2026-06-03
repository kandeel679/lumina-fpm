"""LTI Model Router — multi-provider model creation with relaxed safety and
ordered fallback. Lives entirely in LTI (does NOT modify Robin).

Two problems this solves:
  1. Gemini's consumer safety filters BLOCK dark-web threat content, returning
     EMPTY responses (observed: "Findings extraction failed" on real scrapes).
     Here we build the Gemini client with all safety thresholds = BLOCK_NONE so
     threat-intel content is analysed, not refused.
  2. Free Gemini caps at 20 requests/day. This router routes to OpenCode Zen
     open models (and others) and falls back across a chain on error/empty/429.

Config via env (all optional; sensible defaults):
  LTI_MODEL_CHAIN        comma-separated model ids, tried in order. e.g.
                         "opencode/big-pickle,opencode/deepseek-v3.2,gemini-2.5-flash-lite"
  OPENCODE_ZEN_API_KEY   key from https://opencode.ai/auth (needed for opencode/* ids)
  OPENCODE_ZEN_BASE_URL  default https://opencode.ai/zen/v1
  GOOGLE_API_KEY / LTI_LLM_API_KEY   for gemini-* ids
  ROBIN_MODEL / LTI_LLM_MODEL        single-model fallback (back-compat)
"""
from __future__ import annotations

import logging
import os
import sys

logger = logging.getLogger(__name__)

OPENCODE_ZEN_BASE_URL = os.getenv("OPENCODE_ZEN_BASE_URL", "https://opencode.ai/zen/v1")


def _gemini_safety_off():
    """All Gemini harm categories -> BLOCK_NONE (analyse threat content)."""
    try:
        from langchain_google_genai import HarmBlockThreshold, HarmCategory
        return {
            HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
        }
    except Exception as e:  # pragma: no cover
        logger.warning("Could not load Gemini safety enums: %s", e)
        return None


def create_llm(model_id: str):
    """Create a LangChain chat model for a model id, entirely within LTI."""
    mid = (model_id or "").strip()

    # --- OpenCode Zen (OpenAI-compatible gateway, open models) ---
    if mid.startswith("opencode/"):
        from langchain_openai import ChatOpenAI
        key = os.getenv("OPENCODE_ZEN_API_KEY") or os.getenv("OPENCODE_API_KEY")
        if not key:
            raise RuntimeError(f"OPENCODE_ZEN_API_KEY not set (required for '{mid}')")
        return ChatOpenAI(
            model=mid,
            base_url=OPENCODE_ZEN_BASE_URL,
            api_key=key,
            temperature=0,
            max_retries=2,
            timeout=120,
        )

    # --- Gemini with safety relaxed (so dark-web content isn't blocked) ---
    if mid.startswith("gemini"):
        from langchain_google_genai import ChatGoogleGenerativeAI
        key = os.getenv("GOOGLE_API_KEY") or os.getenv("LTI_LLM_API_KEY")
        kwargs = dict(model=mid, google_api_key=key, temperature=0)
        safety = _gemini_safety_off()
        if safety:
            kwargs["safety_settings"] = safety
        return ChatGoogleGenerativeAI(**kwargs)

    # --- Anything else: defer to Robin's resolver (openai/anthropic/ollama) ---
    robin_dir = os.path.normpath(
        os.path.join(os.path.dirname(__file__), os.pardir, "robin")
    )
    if robin_dir not in sys.path:
        sys.path.insert(0, robin_dir)
    from llm import get_llm as robin_get_llm  # noqa: E402
    return robin_get_llm(mid)


def get_model_chain() -> list[str]:
    """Ordered list of model ids to try. LTI_MODEL_CHAIN wins; else single model."""
    chain = os.getenv("LTI_MODEL_CHAIN", "")
    ids = [m.strip() for m in chain.split(",") if m.strip()]
    if not ids:
        ids = [os.getenv("ROBIN_MODEL") or os.getenv("LTI_LLM_MODEL") or "gemini-2.5-flash"]
    return ids


def invoke_with_fallback(prompt: str) -> tuple[str, str]:
    """Try each model in the chain until one returns non-empty text.

    Treats an EMPTY response as a failure (Gemini returns empty when it blocks),
    so the chain advances to the next model instead of silently producing nothing.

    Returns (text, model_id_used). Raises RuntimeError if every model fails.
    """
    last_err = "no models configured"
    for mid in get_model_chain():
        try:
            llm = create_llm(mid)
            resp = llm.invoke(prompt)
            text = getattr(resp, "content", str(resp)) or ""
            if text.strip():
                return text, mid
            last_err = f"empty response from '{mid}' (possibly safety-blocked)"
            logger.warning(last_err)
        except Exception as e:
            last_err = f"{mid}: {e}"
            logger.warning("Model '%s' failed, trying next: %s", mid, str(e)[:160])
    raise RuntimeError(f"All models in chain failed. Last error: {last_err}")
