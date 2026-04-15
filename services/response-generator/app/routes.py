"""
Routes for Response Generator

Implements the /generate-response endpoint with the exact flow:
  1. Check in-memory cache
  2. Cache hit → return cached response
  3. Cache miss → build prompt → call LLM → validate → cache → return
"""

import logging
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

from app.cache import get_cached_response, set_cached_response, cache_size
from app.generator import generate_llm_response

router = APIRouter()
logger = logging.getLogger("response_generator")


class DeceptionRequest(BaseModel):
    payload: str
    endpoint: str
    method: str
    attack_type: str
    session_id: str
    # Optional fields for backward compatibility with honeypot integration
    strategy: str = ""
    attacker_type: str = "unknown"
    attack_pattern: str = "none"


class DeceptionResponse(BaseModel):
    response: str
    response_type: str


@router.post("/generate-response", response_model=DeceptionResponse)
async def generate_response(req: DeceptionRequest):
    """
    Generate a fake LLM-powered deception response.

    Flow:
      1. Check cache (instant if hit)
      2. Build prompt + call LLM + validate (if miss)
      3. Store in cache
      4. Return response
    """

    # 1. Check cache first — ALWAYS before LLM
    cached = get_cached_response(req.payload, req.endpoint, req.attack_type)
    if cached:
        logger.info(
            f"Cache hit for {req.attack_type} (cache size: {cache_size()})",
            extra={
                "event": "cache_hit",
                "attack_type": req.attack_type,
                "session_id": req.session_id,
            },
        )
        return DeceptionResponse(
            response=cached["response"],
            response_type=cached["response_type"],
        )

    # 2. Cache miss — generate new response from LLM
    logger.info(
        f"Cache miss for {req.attack_type}. Generating via LLM...",
        extra={
            "event": "cache_miss",
            "attack_type": req.attack_type,
            "session_id": req.session_id,
        },
    )

    res_text, res_type = await generate_llm_response(
        payload=req.payload,
        endpoint=req.endpoint,
        method=req.method,
        attack_type=req.attack_type,
    )

    # 3. Cache successful responses only — never cache fallbacks so retries work
    if res_type != "fallback":
        set_cached_response(req.payload, req.endpoint, req.attack_type, res_text, res_type)

    logger.info(
        f"Response generated for {req.attack_type} (type: {res_type})",
        extra={
            "event": "response_generated",
            "attack_type": req.attack_type,
            "session_id": req.session_id,
            "response_type": res_type,
        },
    )

    return DeceptionResponse(response=res_text, response_type=res_type)
