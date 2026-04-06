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

app = FastAPI(
    title="CyberShield Deception Response Generator",
    description="LLM-based context-aware fake response generator for CyberShield honeypot",
    version="2.0.0",
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
