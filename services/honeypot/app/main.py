import asyncio
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import close_db_pool, get_db_pool
from app.logging.structured_logger import get_structured_logger
from app.routes import router
from app.session.session_manager import session_manager
from app.async_pipeline.classification_worker import start_worker_pool

logger = get_structured_logger(__name__)

# Evict stale sessions from memory every 15 minutes
_EVICTION_INTERVAL: int = int(os.environ.get("SESSION_EVICTION_INTERVAL", "900"))


async def _session_eviction_loop() -> None:
    """Background task: periodically clean stale sessions from memory."""
    while True:
        await asyncio.sleep(_EVICTION_INTERVAL)
        try:
            evicted = session_manager.evict_stale()
            if evicted:
                logger.info(
                    f"Background eviction: removed {evicted} stale sessions",
                    extra={"event_type": "session_eviction", "count": evicted},
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"Session eviction error: {exc}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage startup and shutdown lifecycle."""
    logger.info("Honeypot service starting up", extra={"event_type": "startup"})
    # Pre-warm the DB pool so first request is not delayed
    await get_db_pool()
    # Start background session eviction task
    eviction_task = asyncio.create_task(_session_eviction_loop())
    
    # Start AI Classification Worker pool (Day 5)
    workers = await start_worker_pool(num_workers=3)
    
    logger.info(
        "Honeypot service ready — capturing all traffic",
        extra={"event_type": "ready"},
    )
    yield
    # Graceful shutdown
    eviction_task.cancel()
    for w in workers:
        w.cancel()
    
    try:
        await eviction_task
    except asyncio.CancelledError:
        pass
    await close_db_pool()
    logger.info("Honeypot service shut down cleanly", extra={"event_type": "shutdown"})


app = FastAPI(
    title="AI-Adaptive Honeypot",
    description="Captures and stores attacker HTTP traffic for analysis",
    version="1.0.0",
    docs_url=None,   # Hide API docs — don't expose to attackers
    redoc_url=None,
    lifespan=lifespan,
)

# Allow the internal API/Dashboard to query honeypot metadata if needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
