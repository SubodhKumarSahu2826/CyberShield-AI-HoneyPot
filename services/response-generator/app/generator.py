"""
Response Generator — Core Orchestrator

Flow:
  1. Build prompt via prompt_builder
  2. Call LLM via client
  3. Validate response (empty, too short, AI-revealing → reject)
  4. Return (response_text, response_type)

On any failure → attack-specific static fallback (never generic).
"""

import logging
import re

from app.prompt_builder import build_prompt
from app.client import call_llm, LLMClientError

logger = logging.getLogger("response_generator")

# ---------------------------------------------------------------------------
# Attack-specific fallback responses — used when LLM fails or returns
# invalid output. Each one looks like a real server response so even
# fallback mode doesn't expose the honeypot.
# ---------------------------------------------------------------------------
_FALLBACK_RESPONSES: dict[str, tuple[str, str]] = {
    "sql": (
        "id | username | email | password_hash | role | last_login\n"
        "---|----------|-------|---------------|------|----------\n"
        "1 | svc_admin | admin@internal.corp | $2a$12$LJ3m5R8Gk.VYn9F2e1u8/.XhB7K2V3Q9R1pN5dO0wZ4yA6bC8eF0G | admin | 2026-04-28 09:14:33\n"
        "2 | j.martinez | j.martinez@internal.corp | $2a$12$Np7q3R9Tk.WZm0H3f2v9A.YiC8L3W4R0S2qO6eP1xA5zB7cD9gH1I | user | 2026-04-29 14:22:01\n"
        "3 | deploy_svc | deploy@internal.corp | $2a$12$Oq8r4S0Ul.XAn1I4g3w0B.ZjD9M4X5S1T3rP7fQ2yB6aC8dE0hI2J | service | 2026-04-30 02:00:00\n"
        "4 | k.patel | k.patel@internal.corp | $2a$12$Pr9s5T1Vm.YBo2J5h4x1C.AkE0N5Y6T2U4sQ8gR3zC7bD9eF1iJ3K | analyst | 2026-04-27 11:45:19\n"
        "5 | backup_agent | backup@internal.corp | $2a$12$Qs0t6U2Wn.ZCp3K6i5y2D.BlF1O6Z7U3V5tR9hS4AD8cE0fG2jK4L | service | 2026-04-30 03:30:00\n"
        "6 | r.chen | r.chen@internal.corp | $2a$12$Rt1u7V3Xo.ADq4L7j6z3E.CmG2P7A8V4W6uS0iT5BE9dF1gH3kL5M | manager | 2026-04-29 16:33:47\n"
        "\n(6 rows returned)",
        "sql",
    ),
    "file": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n"
        "postgres:x:110:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\n"
        "deploy_svc:x:1001:1001:Deployment Service:/home/deploy_svc:/bin/bash\n"
        "app_runner:x:1002:1002:Application Runner:/opt/app:/usr/sbin/nologin\n"
        "monitoring:x:1003:1003:Monitoring Agent:/opt/monitoring:/usr/sbin/nologin\n"
        "backup_agent:x:1004:1004:Backup Service:/var/backups:/usr/sbin/nologin\n"
        "redis:x:111:118::/var/lib/redis:/usr/sbin/nologin\n"
        "node_app:x:1005:1005:Node.js App:/opt/node-app:/usr/sbin/nologin",
        "file",
    ),
    "html": (
        '<!DOCTYPE html><html><head><title>Search Results - Internal Portal</title></head>'
        '<body><h1>Search Results</h1><p>Your search returned 0 results.</p>'
        '<div class="search-input">Query: <span id="reflected"></span></div>'
        '<footer>&copy; 2026 Internal Systems v3.2.1</footer></body></html>',
        "html",
    ),
    "json": (
        '{"status":"error","code":500,"message":"Internal Server Error",'
        '"details":{"database_host":"10.0.4.22","service":"api-gateway",'
        '"trace":"at com.corp.api.UserController.getUsers(UserController.java:142)"},'
        '"timestamp":"2026-04-30T14:22:33Z"}',
        "json",
    ),
    "xml": (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<response><status>error</status>'
        '<file-content>root:x:0:0:root:/root:/bin/bash\n'
        'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n'
        'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin</file-content>'
        '<server>prod-web-01.corp.internal</server></response>',
        "xml",
    ),
    "auth": (
        '{"access_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.'
        'eyJzdWIiOiJ1c2VyXzEwMjMiLCJlbWFpbCI6ImFkbWluQGludGVybmFsLmNvcnAiLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3MTQ0ODAwMDAsImV4cCI6MTcxNDQ4MzYwMH0.'
        'kV8xR2mN3pQ5sT7uW9yA1bC3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9d",'
        '"token_type":"Bearer","expires_in":3600}',
        "auth",
    ),
}

FALLBACK_TYPE = "fallback"

# ---------------------------------------------------------------------------
# AI-revealing patterns to reject (case-insensitive)
# ---------------------------------------------------------------------------
_AI_PATTERNS = re.compile(
    r"\b(as an ai|i am an ai|language model|i cannot|i can't|"
    r"i'm an ai|artificial intelligence|openai|chatgpt|"
    r"large language model|i apologize|as a language|"
    r"i'm not able to|i am not able to|"
    r"as a helpful|here is a|here's a|sure,? here|"
    r"gemma|llama|mistral|qwen|deepseek|"
    r"note:|disclaimer:)\b",
    re.IGNORECASE,
)


def _classify_response_type(attack_type: str) -> str:
    """Map attack_type to a clean response_type value."""
    upper = attack_type.upper()
    if "SQL" in upper and "NOSQL" not in upper:
        return "sql"
    if "NOSQL" in upper or "MONGO" in upper:
        return "json"
    if any(kw in upper for kw in ("FILE", "TRAVERSAL", "DIRECTORY", "PATH")):
        return "file"
    if "AUTH" in upper or "BRUTE" in upper or "CREDENTIAL" in upper:
        return "auth"
    if "COMMAND" in upper:
        return "file"  # terminal output is file-like
    if "XSS" in upper or "CROSS" in upper:
        return "html"
    if "SSRF" in upper or "SERVER-SIDE" in upper:
        return "json"
    if "XML" in upper or "XXE" in upper or "ENTITY" in upper:
        return "xml"
    if "JNDI" in upper or "LOG4" in upper or "DESERIALIZATION" in upper:
        return "json"
    if "ACCESS" in upper or "BROKEN" in upper or "IDOR" in upper:
        return "json"
    if "ENUM" in upper:
        return "file"
    return "generic"


def _get_fallback(res_type: str) -> tuple[str, str]:
    """Return an attack-type-specific fallback response."""
    if res_type in _FALLBACK_RESPONSES:
        return _FALLBACK_RESPONSES[res_type]
    # Generic fallback for unknown types
    return _FALLBACK_RESPONSES["json"][0], FALLBACK_TYPE


def _sanitize_response(text: str) -> str:
    """
    Remove markdown code block formatting (like ```bash / ```html).
    A real server does not return markdown formatting.
    """
    # Remove starting markdown blocks
    text = re.sub(r"```[a-zA-Z]*\n", "", text)
    # Remove ending markdown blocks
    text = re.sub(r"\n?```\n?", "\n", text)
    # Remove bold/italic markdown
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = re.sub(r"\*(.+?)\*", r"\1", text)
    # Remove markdown headers
    text = re.sub(r"^#{1,6}\s+", "", text, flags=re.MULTILINE)
    # Remove "Here is..." preamble lines
    text = re.sub(r"^(Here is|Here's|Below is|Sure)[^\n]*\n", "", text, flags=re.IGNORECASE)
    return text.strip()


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
    strategy: str = "",
    attacker_type: str = "unknown",
    attack_pattern: str = "none",
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
        # Build prompt using strict templates with attacker context
        prompt = build_prompt(
            payload,
            attack_type,
            endpoint,
            strategy=strategy,
            attacker_type=attacker_type,
            attack_pattern=attack_pattern,
        )

        # Call LLM via isolated client
        llm_text = await call_llm(prompt)

        # Sanitize LLM text (strip markdown blocks)
        llm_text = _sanitize_response(llm_text)

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
            return _get_fallback(res_type)

    except LLMClientError as exc:
        logger.error(
            f"LLM client error for {attack_type}: {exc}",
            extra={"event": "llm_error"},
        )
        return _get_fallback(res_type)

    except Exception as exc:
        logger.error(
            f"Unexpected error generating response for {attack_type}: {exc}",
            extra={"event": "generator_error"},
        )
        return _get_fallback(res_type)
