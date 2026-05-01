"""
Response Generator Microservice — Main App
services/response-generator/app/main.py

Endpoints:
  POST /generate-response  — generate a deception response
  GET  /_health             — health check
  GET  /_cache_stats        — cache statistics
"""

import logging
import sys
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import router

# Setup structured logging
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='{"timestamp": "%(asctime)s", "service": "response_generator", "level": "%(levelname)s", "message": "%(message)s"}',
)
logger = logging.getLogger("response_generator")


async def _warmup_model():
    """
    Send a tiny request to the LLM API on startup to verify connectivity.
    Works with Groq, OpenAI, or any OpenAI-compatible endpoint.
    """
    from app.client import LLM_BASE_URL, MODEL_NAME, LLM_API_KEY
    import httpx
    logger.info(f"Warming up LLM model '{MODEL_NAME}' at {LLM_BASE_URL}...")
    try:
        headers = {"Content-Type": "application/json"}
        if LLM_API_KEY:
            headers["Authorization"] = f"Bearer {LLM_API_KEY}"

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{LLM_BASE_URL}/openai/v1/chat/completions",
                json={
                    "model": MODEL_NAME,
                    "messages": [{"role": "user", "content": "Say OK"}],
                    "max_tokens": 5,
                    "stream": False,
                },
                headers=headers,
            )
            resp.raise_for_status()
            logger.info(f"Model warm-up complete — '{MODEL_NAME}' is loaded and ready")
    except Exception as exc:
        logger.warning(f"Model warm-up failed (will retry on first request): {exc}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await _warmup_model()
    yield


app = FastAPI(
    title="CyberShield Deception Response Generator",
    description="LLM-based context-aware fake response generator for CyberShield honeypot",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/_health", tags=["Health"])
async def health_check():
    return {"status": "healthy", "service": "response-generator", "version": "2.0.0"}


@app.get("/_cache_stats", tags=["Health"])
async def cache_stats():
    from app.cache import cache_size
    return {"cache_entries": cache_size(), "max_cache_size": 1024}

