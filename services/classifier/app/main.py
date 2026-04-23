"""
Classifier Service — Application Entry Point
services/classifier/app/main.py

Lightweight FastAPI proxy between the honeypot and the remote Phi-3.5 model.
Runs on port 5001, internal Docker network only (no public port).
"""

import logging
import os
import sys
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes import router

logging.basicConfig(
    stream=sys.stdout,
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format='{"timestamp": "%(asctime)s", "service": "classifier", '
           '"level": "%(levelname)s", "message": "%(message)s"}',
)
logger = logging.getLogger("classifier")


async def _warmup_model():
    """
    Send a tiny request to Ollama on startup to pre-load the model into GPU/RAM.
    This prevents the first real classification from timing out due to cold start.
    """
    from app.classifier_client import PHI_MODEL_URL, PHI_MODEL_NAME
    logger.info(f"Warming up model '{PHI_MODEL_NAME}' at {PHI_MODEL_URL}...")
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{PHI_MODEL_URL}/v1/chat/completions",
                json={
                    "model": PHI_MODEL_NAME,
                    "messages": [{"role": "user", "content": "Say OK"}],
                    "max_tokens": 5,
                    "stream": False,
                },
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            logger.info(f"Model warm-up complete — '{PHI_MODEL_NAME}' is loaded and ready")
    except Exception as exc:
        logger.warning(f"Model warm-up failed (will retry on first request): {exc}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await _warmup_model()
    yield


app = FastAPI(
    title="AI Attack Classifier",
    description="Phi-3.5 Mini inference proxy for honeypot traffic classification",
    version="1.0.0",
    docs_url=None,   # Hide from public
    redoc_url=None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

logger.info(
    "AI Classifier service started",
    extra={"model_url": os.environ.get("PHI_MODEL_URL", "NOT SET")},
)

