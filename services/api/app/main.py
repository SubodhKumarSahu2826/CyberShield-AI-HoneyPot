"""
API Service - Application Entry Point
"""

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import close_db_pool, get_db_pool
from app.routes import router

# Configure logging
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='{"timestamp": "%(asctime)s", "service": "api", "level": "%(levelname)s", "message": "%(message)s"}',
)
logger = logging.getLogger("api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("API service starting up")
    await get_db_pool()
    logger.info("API service ready")
    yield
    await close_db_pool()
    logger.info("API service shut down cleanly")


app = FastAPI(
    title="Honeypot API",
    description="Query interface for captured honeypot traffic",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

app.include_router(router)
