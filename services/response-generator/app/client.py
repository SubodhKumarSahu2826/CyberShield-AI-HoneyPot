"""
Isolated LLM HTTP Client — OpenAI-Compatible Format

Responsibilities:
  - Call LLM via async HTTP POST using OpenAI chat completions format
  - Works with: Groq, OpenAI, Ollama (/v1/chat/completions), llama.cpp
  - Configurable timeout via LLM_TIMEOUT env var (default: 30s)
  - Return plain text response
  - Raise LLMClientError on any failure (never crash)

Environment Variables:
  LLM_URL      — Base URL (e.g., https://api.groq.com or http://localhost:11434)
  LLM_API_KEY  — API key for auth (required for Groq/OpenAI, optional for local Ollama)
  MODEL_NAME   — Model name (default: llama-3.1-8b-instant)
  LLM_TIMEOUT  — Request timeout in seconds (default: 30)
"""

import logging
import os

import httpx

logger = logging.getLogger("response_generator")

# ---------------------------------------------------------------------------
# Configuration — all from environment, easily changeable
# ---------------------------------------------------------------------------
LLM_BASE_URL: str = os.environ.get(
    "LLM_URL",
    "https://api.groq.com",
).rstrip("/")

LLM_API_KEY: str = os.environ.get("LLM_API_KEY", "")

MODEL_NAME: str = os.environ.get("MODEL_NAME", "llama-3.1-8b-instant")

LLM_TIMEOUT: float = float(os.environ.get("LLM_TIMEOUT", "30"))


class LLMClientError(Exception):
    """Raised when the LLM call fails for any reason."""
    pass


async def call_llm(prompt: str) -> str:
    """
    Send a prompt to the LLM and return the generated text.

    Uses OpenAI-compatible /v1/chat/completions format, which works with
    Groq, OpenAI, Ollama, llama.cpp, and most LLM providers.

    Raises LLMClientError if the call fails, times out, or returns
    an unparseable response.
    """
    headers = {"Content-Type": "application/json"}
    if LLM_API_KEY:
        headers["Authorization"] = f"Bearer {LLM_API_KEY}"

    payload = {
        "model": MODEL_NAME,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a real production server. Output ONLY raw server "
                    "responses. Never use markdown, code blocks, or mention AI."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.25,
        "max_tokens": 2048,
        "top_p": 0.9,
        "stream": False,
    }

    try:
        async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as client:
            resp = await client.post(
                f"{LLM_BASE_URL}/openai/v1/chat/completions",
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()

            # Parse OpenAI-compatible response format
            choices = data.get("choices", [])
            if not choices:
                raise LLMClientError("LLM returned no choices")

            text = choices[0].get("message", {}).get("content", "").strip()
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
