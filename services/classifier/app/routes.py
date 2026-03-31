"""
Classifier Service — Route Handlers
services/classifier/app/routes.py

POST /classify — primary inference endpoint
GET  /_health  — Docker health check
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.classifier_client import classify_request

logger = logging.getLogger("classifier")
router = APIRouter()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ClassifyRequest(BaseModel):
    method:   str         = Field(default="GET", description="HTTP method")
    endpoint: str         = Field(..., description="Request path/endpoint")
    headers:  dict[str, Any] = Field(default_factory=dict)
    payload:  str         = Field(default="", description="Request body as string")


class ClassifyResponse(BaseModel):
    classification:     str
    attack_type:        str
    probability_score:  float


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/_health")
async def health() -> JSONResponse:
    from app.classifier_client import PHI_MODEL_URL
    return JSONResponse({
        "status":  "healthy",
        "service": "classifier",
        "model_configured": bool(PHI_MODEL_URL),
    })


@router.post("/classify", response_model=ClassifyResponse)
async def classify(req: ClassifyRequest) -> JSONResponse:
    """
    Classify a suspicious HTTP request using the remote Phi-3.5 model.

    Returns:
        attack_type        — predicted attack category
        probability_score  — confidence [0.0, 1.0]
    """
    result = await classify_request(
        method=req.method,
        endpoint=req.endpoint,
        headers=req.headers,
        payload=req.payload,
    )
    logger.info(
        f"[/classify] {req.method} {req.endpoint} → "
        f"{result.get('classification', 'benign').upper()} | {result.get('attack_type', 'none')} ({result.get('probability_score', 0):.2f})"
    )
    return JSONResponse(result)
