"""
Phi-3.5 Mini Client — Classifier Service
services/classifier/app/classifier_client.py

Sends HTTP requests to the remote Phi-3.5 model exposed via ngrok.
Supports OpenAI-compatible API format (used by Ollama, llama.cpp, LM Studio).

Environment variables:
  PHI_MODEL_URL   — Local Ollama endpoint or OpenAI-compatible endpoint (default: http://host.docker.internal:11434)
  PHI_MODEL_NAME  — model name string (default: phi3:mini or phi3.5)
  CLASSIFIER_TIMEOUT — seconds before failing safe (default: 12)
"""

from __future__ import annotations

import json
import logging
import os
import re

import httpx

logger = logging.getLogger("classifier")

# ---------------------------------------------------------------------------
# Configuration — all values come from env vars, never hard-coded
# ---------------------------------------------------------------------------
PHI_MODEL_URL: str = os.environ.get("PHI_MODEL_URL", "http://host.docker.internal:11434").rstrip("/")
PHI_MODEL_NAME: str = os.environ.get("PHI_MODEL_NAME", "phi3")
TIMEOUT: float = float(os.environ.get("CLASSIFIER_TIMEOUT", "12"))

# Attack categories the model is asked to choose from
ATTACK_CATEGORIES = [
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Command Injection",
    "Path Traversal",
    "Local File Inclusion (LFI)",
    "Remote File Inclusion (RFI)",
    "Brute Force / Credential Stuffing",
    "Directory Enumeration",
    "Server-Side Request Forgery (SSRF)",
    "XML Injection",
    "Broken Access Control",
    "Broken Access Control",
    "Port Scanning / Reconnaissance",
    "None / Benign"
]


def _build_prompt(
    *,
    method: str,
    endpoint: str,
    headers: dict,
    payload: str,
) -> str:
    """
    Construct a structured cybersecurity analysis prompt for Phi-3.5.
    The model is instructed to return ONLY a JSON object.
    """
    # Trim headers and payload to stay within token budget
    safe_headers = {
        k: v for k, v in headers.items()
        if k.lower() not in {"cookie", "authorization", "x-api-key"}
    }
    header_str = json.dumps(safe_headers, indent=2)[:800]
    payload_str = payload[:1000] if payload else "(empty)"

    categories = "\n".join(f"  - {c}" for c in ATTACK_CATEGORIES)

    return f"""You are a cybersecurity threat analysis model specialized in web attack detection.

Analyze the following HTTP request and classify the most likely attack type.

=== HTTP REQUEST ===
Method:   {method}
Endpoint: {endpoint}
Headers:
{header_str}
Payload:
{payload_str}

=== TASK ===
1. Determine if this request is 'benign' (normal traffic) or 'malicious' (an attack).
2. If malicious, choose the single best-matching attack category from this list:
{categories}

Return ONLY a valid JSON object in exactly this format — no markdown, no explanation:
{{
  "classification": "benign" or "malicious",
  "attack_type": "<category from the list above, or 'None / Benign'>",
  "probability_score": <float between 0.0 and 1.0>
}}"""


def _parse_response(raw: str) -> dict:
    """
    Extract JSON from the model's response.
    Handles cases where the model wraps output in markdown code fences.
    """
    # Strip markdown code fences if present
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw)

    # Try to find a JSON object anywhere in the response
    match = re.search(r'\{[^{}]*"attack_type"[^{}]*\}', raw, re.DOTALL)
    if match:
        raw = match.group(0)

    try:
        data = json.loads(raw)
        classification = str(data.get("classification", "benign")).strip().lower()
        if classification not in ("benign", "malicious"):
            classification = "benign"
            
        attack_type = str(data.get("attack_type", "Unknown Anomaly")).strip()
        score_raw = data.get("probability_score", 0.5)
        score = max(0.0, min(1.0, float(score_raw)))
        return {
            "classification": classification,
            "attack_type": attack_type, 
            "probability_score": round(score, 4)
        }
    except (json.JSONDecodeError, ValueError, TypeError):
        logger.warning(f"Could not parse model response: {raw[:200]}")
        return {"classification": "benign", "attack_type": "Unknown Anomaly", "probability_score": 0.3}


async def classify_request(
    *,
    method: str,
    endpoint: str,
    headers: dict,
    payload: str,
) -> dict:
    """
    Send a request to the remote Phi-3.5 model via ngrok.
    Returns: {"classification": str, "attack_type": str, "probability_score": float}

    Falls back to {"classification": "benign", "attack_type": "model_unavailable", "probability_score": 0.0}
    if the model is unreachable or returns an error.
    """
    if not PHI_MODEL_URL:
        logger.warning("PHI_MODEL_URL not configured — AI classification disabled")
        return {"classification": "benign", "attack_type": "model_unavailable", "probability_score": 0.0}

    prompt = _build_prompt(
        method=method,
        endpoint=endpoint,
        headers=headers,
        payload=payload,
    )

    # OpenAI-compatible chat completions format (works with Ollama, llama.cpp)
    payload_body = {
        "model": PHI_MODEL_NAME,
        "messages": [
            {
                "role": "system",
                "content": "You are a cybersecurity threat analysis model. Always respond with valid JSON only.",
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,      # Low temperature for deterministic classification
        "max_tokens": 120,       # JSON response is small
        "stream": False,
    }

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.post(
                f"{PHI_MODEL_URL}/v1/chat/completions",
                json=payload_body,
                headers={
                    "Content-Type": "application/json",
                    "ngrok-skip-browser-warning": "true",  # skip ngrok browser page
                },
            )
            resp.raise_for_status()
            data = resp.json()

            # Extract content from OpenAI-format response
            content = (
                data.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
            )
            result = _parse_response(content)
            logger.info(
                f"AI classified [{method}] {endpoint} → "
                f"{result['classification'].upper()} | {result['attack_type']} ({result['probability_score']:.2f})"
            )
            return result

    except httpx.TimeoutException:
        logger.warning(f"AI classifier timeout after {TIMEOUT}s for [{method}] {endpoint}")
        return {"classification": "benign", "attack_type": "model_unavailable", "probability_score": 0.0}
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"AI classifier error: {exc}")
        return {"classification": "benign", "attack_type": "model_unavailable", "probability_score": 0.0}
