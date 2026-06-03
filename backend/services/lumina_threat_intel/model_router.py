"""LTI Model Router — tiered, budget-aware, multi-provider model selection.

Lumina picks the model PER REQUEST based on the task's need (fast vs big-brain)
and the remaining budget, with fallback. Lives entirely in LTI (no Robin edits).

Tiers (task -> tier):
  fast    : query generation, simple steps         -> deepseek-v4-flash
  strong  : the Findings reasoning + assessment     -> deepseek-v4-pro -> claude-haiku (fallback)
  premium : explicit "max quality" only             -> claude-opus-4-6

Budget (soft cap, default $20): estimated spend is tracked in a state file; once
spend crosses the cap threshold, ALL tiers downgrade to the cheapest model and a
warning is logged (never a hard stop — clearnet KEV findings are free anyway).

Providers:
  agentrouter/<model>  -> AgentRouter OpenAI-compatible endpoint (DeepSeek/GLM/Claude)
  gemini*              -> Gemini with safety BLOCK_NONE (legacy/fallback)
  opencode/<model>     -> OpenCode Zen (OpenAI-compatible)
  anything else        -> Robin's resolver (back-compat)

Config (env, all optional):
  AGENTROUTER_TOKEN, AGENTROUTER_BASE_URL (default https://agentrouter.org)
  LTI_CHAIN_FAST / LTI_CHAIN_STRONG / LTI_CHAIN_PREMIUM  (comma-separated overrides)
  LTI_BUDGET_USD (default 20), LTI_BUDGET_STATE_FILE (default /app/.lti_budget_state.json)
"""
from __future__ import annotations

import json
import logging
import os
import sys

logger = logging.getLogger(__name__)

AGENTROUTER_BASE_URL = os.getenv("AGENTROUTER_BASE_URL", "https://agentrouter.org")
OPENCODE_ZEN_BASE_URL = os.getenv("OPENCODE_ZEN_BASE_URL", "https://opencode.ai/zen/v1")
BUDGET_USD = float(os.getenv("LTI_BUDGET_USD", "20"))
BUDGET_STATE_FILE = os.getenv("LTI_BUDGET_STATE_FILE", "/app/.lti_budget_state.json")
# Downgrade everything to the cheapest model once spend crosses this fraction.
BUDGET_DOWNGRADE_AT = float(os.getenv("LTI_BUDGET_DOWNGRADE_AT", "0.9"))

# Per-1M-token prices (USD). DeepSeek-Pro/Haiku/Opus confirmed; flash & GLM est.
MODEL_CATALOG: dict[str, dict] = {
    "agentrouter/deepseek-v4-flash": {"tier": "fast", "in": 0.10, "out": 0.40},
    "agentrouter/deepseek-v4-pro": {"tier": "strong", "in": 0.44, "out": 0.87},
    "agentrouter/glm-5.1": {"tier": "strong", "in": 0.50, "out": 2.00},
    "agentrouter/claude-haiku-4-5-20251001": {"tier": "strong", "in": 1.00, "out": 5.00},
    "agentrouter/claude-opus-4-6": {"tier": "premium", "in": 5.00, "out": 25.00},
}

_CHEAPEST = "agentrouter/deepseek-v4-flash"

_DEFAULT_CHAINS = {
    "fast": ["agentrouter/deepseek-v4-flash"],
    "strong": ["agentrouter/deepseek-v4-pro", "agentrouter/claude-haiku-4-5-20251001"],
    "premium": ["agentrouter/claude-opus-4-6", "agentrouter/claude-haiku-4-5-20251001"],
}


# ── Budget state (estimated spend) ──────────────────────────────────────────
def _read_spend() -> float:
    try:
        with open(BUDGET_STATE_FILE) as f:
            return float(json.load(f).get("spend_usd", 0.0))
    except Exception:
        return 0.0


def _add_spend(amount: float) -> float:
    total = _read_spend() + max(0.0, amount)
    try:
        with open(BUDGET_STATE_FILE, "w") as f:
            json.dump({"spend_usd": round(total, 6)}, f)
    except Exception as e:  # pragma: no cover
        logger.warning("Could not persist budget state: %s", e)
    return total


def _estimate_cost(model_id: str, prompt: str, output: str) -> float:
    meta = MODEL_CATALOG.get(model_id)
    if not meta:
        return 0.0
    in_tok = len(prompt) / 4.0          # ~4 chars/token heuristic
    out_tok = len(output) / 4.0
    return (in_tok / 1e6) * meta["in"] + (out_tok / 1e6) * meta["out"]


def budget_status() -> dict:
    spent = _read_spend()
    return {"spent_usd": round(spent, 4), "cap_usd": BUDGET_USD,
            "remaining_usd": round(BUDGET_USD - spent, 4),
            "downgraded": spent >= BUDGET_USD * BUDGET_DOWNGRADE_AT}


# ── Provider creation ────────────────────────────────────────────────────────
def _gemini_safety_off():
    try:
        from langchain_google_genai import HarmBlockThreshold, HarmCategory
        return {
            HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
        }
    except Exception:
        return None


def create_llm(model_id: str):
    """Create a LangChain chat model for a model id, entirely within LTI."""
    mid = (model_id or "").strip()

    # AgentRouter — Anthropic-style endpoint (mimics the Claude Code client that
    # AgentRouter authorizes). The OpenAI /v1 client was rejected as
    # "unauthorized client". ChatAnthropic posts to {base_url}/v1/messages.
    # (Set LTI_AGENTROUTER_MODE=openai to use the OpenAI-compatible /v1 path.)
    if mid.startswith("agentrouter/"):
        model = mid.split("/", 1)[1]
        key = os.getenv("AGENTROUTER_TOKEN") or os.getenv("ANTHROPIC_AUTH_TOKEN")
        if not key:
            raise RuntimeError(f"AGENTROUTER_TOKEN not set (required for '{mid}')")
        if os.getenv("LTI_AGENTROUTER_MODE", "anthropic").lower() == "openai":
            from langchain_openai import ChatOpenAI
            base = AGENTROUTER_BASE_URL.rstrip("/")
            if not base.endswith("/v1"):
                base = base + "/v1"
            return ChatOpenAI(model=model, base_url=base, api_key=key,
                              temperature=0, max_retries=2, timeout=120)
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(model=model, base_url=AGENTROUTER_BASE_URL.rstrip("/"),
                             api_key=key, temperature=0, max_retries=2,
                             timeout=120, max_tokens=4096)

    if mid.startswith("opencode/"):
        from langchain_openai import ChatOpenAI
        key = os.getenv("OPENCODE_ZEN_API_KEY") or os.getenv("OPENCODE_API_KEY")
        if not key:
            raise RuntimeError(f"OPENCODE_ZEN_API_KEY not set (required for '{mid}')")
        return ChatOpenAI(model=mid, base_url=OPENCODE_ZEN_BASE_URL, api_key=key,
                          temperature=0, max_retries=2, timeout=120)

    # OpenRouter — standard pay-as-you-go gateway; accepts API clients (no
    # Claude-Code-only restriction). ids: "openrouter/deepseek/deepseek-chat", etc.
    if mid.startswith("openrouter/"):
        from langchain_openai import ChatOpenAI
        model = mid.split("/", 1)[1]
        key = os.getenv("OPENROUTER_API_KEY")
        if not key:
            raise RuntimeError(f"OPENROUTER_API_KEY not set (required for '{mid}')")
        base = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
        return ChatOpenAI(model=model, base_url=base, api_key=key,
                          temperature=0, max_retries=2, timeout=120)

    # DeepSeek direct API — permissive proper backend API (the Robin-style path).
    # ids: "deepseek/deepseek-chat" (V3, cheap) or "deepseek/deepseek-reasoner".
    if mid.startswith("deepseek/"):
        from langchain_openai import ChatOpenAI
        model = mid.split("/", 1)[1]
        key = os.getenv("DEEPSEEK_API_KEY")
        if not key:
            raise RuntimeError(f"DEEPSEEK_API_KEY not set (required for '{mid}')")
        base = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
        return ChatOpenAI(model=model, base_url=base, api_key=key,
                          temperature=0, max_retries=2, timeout=120)

    if mid.startswith("gemini"):
        from langchain_google_genai import ChatGoogleGenerativeAI
        key = os.getenv("GOOGLE_API_KEY") or os.getenv("LTI_LLM_API_KEY")
        kwargs = dict(model=mid, google_api_key=key, temperature=0)
        safety = _gemini_safety_off()
        if safety:
            kwargs["safety_settings"] = safety
        return ChatGoogleGenerativeAI(**kwargs)

    robin_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), os.pardir, "robin"))
    if robin_dir not in sys.path:
        sys.path.insert(0, robin_dir)
    from llm import get_llm as robin_get_llm  # noqa: E402
    return robin_get_llm(mid)


# ── Tiered selection + budget-aware downgrade ────────────────────────────────
def _chain_for(tier: str) -> list[str]:
    env = os.getenv(f"LTI_CHAIN_{tier.upper()}", "")
    ids = [m.strip() for m in env.split(",") if m.strip()]
    return ids or _DEFAULT_CHAINS.get(tier, _DEFAULT_CHAINS["strong"])


def select_chain(tier: str) -> list[str]:
    """Return the model chain for a tier, downgraded to cheapest if over budget."""
    chain = list(_chain_for(tier))
    spent = _read_spend()
    if spent >= BUDGET_USD * BUDGET_DOWNGRADE_AT:
        logger.warning(
            "Budget soft-cap: $%.4f/$%.2f spent (>=%.0f%%) -> downgrading '%s' tier to cheapest (%s)",
            spent, BUDGET_USD, BUDGET_DOWNGRADE_AT * 100, tier, _CHEAPEST,
        )
        return [_CHEAPEST]
    # Always keep the cheapest as a final fallback
    if _CHEAPEST not in chain:
        chain.append(_CHEAPEST)
    return chain


def invoke_with_fallback(prompt: str, tier: str = "strong") -> tuple[str, str]:
    """Invoke the chosen tier's model chain until one returns non-empty text.

    Records estimated spend on success. Empty output (e.g. a content block) is
    treated as failure so the chain advances. Returns (text, model_id_used).
    """
    last_err = "no models configured"
    for mid in select_chain(tier):
        try:
            llm = create_llm(mid)
            resp = llm.invoke(prompt)
            text = getattr(resp, "content", str(resp)) or ""
            if text.strip():
                cost = _estimate_cost(mid, prompt, text)
                total = _add_spend(cost)
                logger.info(
                    "LLM tier=%s model=%s ~$%.5f (cumulative ~$%.4f/$%.2f)",
                    tier, mid, cost, total, BUDGET_USD,
                )
                return text, mid
            last_err = f"empty response from '{mid}'"
            logger.warning(last_err)
        except Exception as e:
            last_err = f"{mid}: {e}"
            logger.warning("Model '%s' failed, trying next: %s", mid, str(e)[:160])
    raise RuntimeError(f"All models in '{tier}' chain failed. Last error: {last_err}")
