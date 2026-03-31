"""
Routes for Response Generator
"""

import logging
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

from app.cache_manager import get_cached_response, set_cached_response
from app.generator import generate_llm_response

router = APIRouter()
logger = logging.getLogger("response_generator")

class DeceptionRequest(BaseModel):
    payload: str
    endpoint: str
    method: str
    attack_type: str
    session_id: str
    strategy: str = ""
    attacker_type: str = "unknown"
    attack_pattern: str = "none"

class DeceptionResponse(BaseModel):
    response: str
    response_type: str

@router.post("/generate-response", response_model=DeceptionResponse)
async def generate_response(req: DeceptionRequest):
    # 1. Check cache to save LLM round-trips
    cached = await get_cached_response(req.payload, req.attack_type)
    if cached:
        logger.info(f"Cache hit for attack {req.attack_type}", extra={
             "event": "cache_hit", "attack_type": req.attack_type, "session_id": req.session_id})
        return DeceptionResponse(response=cached["response"], response_type=cached["response_type"])
    
    # 2. Generate new response from LLM
    logger.info(f"Cache miss. Generating new response for {req.attack_type}", extra={
             "event": "response_generating", "attack_type": req.attack_type, "session_id": req.session_id})
    res_text, res_type = await generate_llm_response(
        req.payload, req.endpoint, req.method, req.attack_type, req.strategy, req.attacker_type, req.attack_pattern
    )

    # 3. Cache the new response
    await set_cached_response(req.payload, req.attack_type, res_text, res_type)

    logger.info(f"Response generated for {req.attack_type}", extra={
         "event": "response_generated", "attack_type": req.attack_type, "session_id": req.session_id})

    return DeceptionResponse(response=res_text, response_type=res_type)
