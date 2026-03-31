"""
Honeypot → Classifier HTTP Client  (Day 4)
services/honeypot/app/classifier_client.py

Sends suspicious requests to the internal classifier container for
AI-powered attack classification using the remote Phi-3.5 model.

Design decisions:
- Async httpx so the honeypot never blocks on I/O
- Short timeout (10s default) — honeypot must stay responsive
- Falls back gracefully: ai_attack_type='model_unavailable', score=0.0
- Classifier host/port configured via environment variables
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass

import httpx

logger = logging.getLogger("honeypot")

CLASSIFIER_HOST: str = os.environ.get("CLASSIFIER_HOST", "classifier")
CLASSIFIER_PORT: str = os.environ.get("CLASSIFIER_PORT", "5001")
CLASSIFIER_URL:  str = f"http://{CLASSIFIER_HOST}:{CLASSIFIER_PORT}"
TIMEOUT: float = float(os.environ.get("CLASSIFIER_CLIENT_TIMEOUT", "10"))

_FALLBACK = {"ai_classification_status": "benign", "ai_attack_type": "model_unavailable", "ai_confidence_score": 0.0}


@dataclass
class AIClassification:
    ai_classification_status: str
    ai_attack_type:       str
    ai_confidence_score:  float


async def ai_classify(
    *,
    method:   str,
    endpoint: str,
    headers:  dict,
    payload:  str,
) -> AIClassification:
    """
    Call the classifier service for AI prediction.

    Returns AIClassification with `model_unavailable` + 0.0 score on any
    error, so the honeypot pipeline always continues uninterrupted.
    """
    body = {
        "method":   method,
        "endpoint": endpoint,
        "headers":  headers,
        "payload":  payload,
    }
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.post(
                f"{CLASSIFIER_URL}/classify",
                json=body,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            return AIClassification(
                ai_classification_status=str(data.get("classification", "benign")),
                ai_attack_type=str(data.get("attack_type", "Unknown Anomaly")),
                ai_confidence_score=float(data.get("probability_score", 0.0)),
            )
    except httpx.TimeoutException:
        logger.debug(f"Classifier timeout ({TIMEOUT}s) for [{method}] {endpoint}")
        return AIClassification(**_FALLBACK)
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"Classifier unavailable: {exc}")
        return AIClassification(**_FALLBACK)
