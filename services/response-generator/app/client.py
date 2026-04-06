"""
Isolated LLM HTTP Client

Responsibilities:
  - Call external LLM (Ollama) via async HTTP POST
  - Configurable timeout via LLM_TIMEOUT env var (default: 30s)
  - Return plain text response
  - Raise LLMClientError on any failure (never crash)

Environment Variables:
  LLM_API_URL  — LLM endpoint (falls back to LLM_URL for backward compat)
  MODEL_NAME   — Ollama model name (default: qwen2.5:3b)
  LLM_TIMEOUT  — Request timeout in seconds (default: 30)
"""

import logging
import os

import httpx

logger = logging.getLogger("response_generator")

# ---------------------------------------------------------------------------
# Configuration — all from environment, easily changeable
# ---------------------------------------------------------------------------
LLM_API_URL: str = os.environ.get(
    "LLM_API_URL",
    os.environ.get("LLM_URL", "http://host.docker.internal:11434/api/generate"),
)

MODEL_NAME: str = os.environ.get("MODEL_NAME", "qwen2.5:3b")

LLM_TIMEOUT: float = float(os.environ.get("LLM_TIMEOUT", "30"))


class LLMClientError(Exception):
    """Raised when the LLM call fails for any reason."""
    pass


async def call_llm(prompt: str) -> str:
    """
    Send a prompt to the LLM and return the generated text.

    Raises LLMClientError if the call fails, times out, or returns
    an unparseable response.
    """
    try:
        async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as client:
            resp = await client.post(
                LLM_API_URL,
                json={
                    "model": MODEL_NAME,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.5,
                        "num_predict": 800,
                    },
                },
            )
            resp.raise_for_status()
            data = resp.json()
            text = data.get("response", "").strip()
            if not text:
                raise LLMClientError("LLM returned empty response body")
            return text

    except httpx.TimeoutException as exc:
        logger.error(f"LLM timeout after {LLM_TIMEOUT}s: {exc}")
        raise LLMClientError(f"LLM request timed out ({LLM_TIMEOUT}s)") from exc

    except httpx.HTTPStatusError as exc:
        logger.error(f"LLM HTTP error {exc.response.status_code}: {exc}")
        raise LLMClientError(f"LLM returned HTTP {exc.response.status_code}") from exc

    except LLMClientError:
        raise  # re-raise our own errors as-is

    except Exception as exc:
        logger.error(f"LLM client unexpected error: {exc}")
        raise LLMClientError(f"LLM call failed: {exc}") from exc
