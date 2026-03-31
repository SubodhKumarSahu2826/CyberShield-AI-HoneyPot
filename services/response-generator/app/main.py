"""
Response Generator Microservice Main App
services/response-generator/app/main.py
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
    format='{"timestamp": "%(asctime)s", "service": "response_generator", "level": "%(levelname)s", "message": "%(message)s"}'
)
logger = logging.getLogger("response_generator")

app = FastAPI(
    title="SentinAI Deception Response Generator",
    description="LLM-based context-aware fake response generator for SentinAI honeypot",
    version="1.0.0"
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
    return {"status": "healthy", "service": "response-generator"}
