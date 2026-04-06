"""
Response Generator — Core Orchestrator

Flow:
  1. Build prompt via prompt_builder
  2. Call LLM via client
  3. Validate response (empty, too short, AI-revealing → reject)
  4. Return (response_text, response_type)

On any failure → graceful fallback.
"""

import logging
import re

from app.prompt_builder import build_prompt
from app.client import call_llm, LLMClientError

logger = logging.getLogger("response_generator")

# ---------------------------------------------------------------------------
# Fallback response — used when LLM fails or returns invalid output
# ---------------------------------------------------------------------------
FALLBACK_RESPONSE = "Operation completed successfully"
FALLBACK_TYPE = "fallback"

# ---------------------------------------------------------------------------
# AI-revealing patterns to reject (case-insensitive)
# ---------------------------------------------------------------------------
_AI_PATTERNS = re.compile(
    r"\b(as an ai|i am an ai|language model|i cannot|i can't|"
    r"i'm an ai|artificial intelligence|openai|chatgpt|"
    r"large language model|i apologize|as a language|"
    r"i'm not able to|i am not able to)\b",
    re.IGNORECASE,
)


def _classify_response_type(attack_type: str) -> str:
    """Map attack_type to a clean response_type value."""
    upper = attack_type.upper()
    if "SQL" in upper:
        return "sql"
    if any(kw in upper for kw in ("FILE", "TRAVERSAL", "DIRECTORY", "PATH")):
        return "file"
    if "AUTH" in upper or "BRUTE" in upper:
        return "auth"
    if "COMMAND" in upper:
        return "file"  # terminal output is file-like
    if "XSS" in upper or "CROSS" in upper:
        return "generic"
    return "generic"


def _validate_response(text: str) -> bool:
    """
    Validate the LLM response.
    Returns True if the response is usable, False if it should be rejected.
    """
    # Empty or whitespace-only
    if not text or not text.strip():
        logger.warning("Validation FAIL: empty response")
        return False

    # Too short (fewer than 10 characters)
    if len(text.strip()) < 10:
        logger.warning(f"Validation FAIL: too short ({len(text.strip())} chars)")
        return False

    # Contains AI-revealing language
    if _AI_PATTERNS.search(text):
        logger.warning("Validation FAIL: response contains AI-revealing patterns")
        return False

    return True


async def generate_llm_response(
    payload: str,
    endpoint: str,
    method: str,
    attack_type: str,
    **kwargs,
) -> tuple[str, str]:
    """
    Generate a fake response for the given attack payload.

    Returns:
        (response_text, response_type)

    Never raises — always returns a valid tuple.
    """
    res_type = _classify_response_type(attack_type)

    try:
        # Build prompt using strict templates
        prompt = build_prompt(payload, attack_type)

        # Call LLM via isolated client
        llm_text = await call_llm(prompt)

        # Validate the response
        if _validate_response(llm_text):
            logger.info(
                f"LLM response generated successfully for {attack_type} "
                f"({len(llm_text)} chars)",
                extra={"event": "llm_success"},
            )
            return llm_text, res_type
        else:
            logger.warning(
                f"LLM response failed validation for {attack_type}, using fallback",
                extra={"event": "llm_validation_fail"},
            )
            return FALLBACK_RESPONSE, FALLBACK_TYPE

    except LLMClientError as exc:
        logger.error(
            f"LLM client error for {attack_type}: {exc}",
            extra={"event": "llm_error"},
        )
        return FALLBACK_RESPONSE, FALLBACK_TYPE

    except Exception as exc:
        logger.error(
            f"Unexpected error generating response for {attack_type}: {exc}",
            extra={"event": "generator_error"},
        )
        return FALLBACK_RESPONSE, FALLBACK_TYPE
