"""
Classifier Service — Application Entry Point
services/classifier/app/main.py

Lightweight FastAPI proxy between the honeypot and the remote Phi-3.5 model.
Runs on port 5001, internal Docker network only (no public port).
"""

import logging
import os
import sys

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

app = FastAPI(
    title="AI Attack Classifier",
    description="Phi-3.5 Mini inference proxy for honeypot traffic classification",
    version="1.0.0",
    docs_url=None,   # Hide from public
    redoc_url=None,
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
