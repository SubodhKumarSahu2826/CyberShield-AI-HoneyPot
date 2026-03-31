"""
Cache Manager
Implements persistent PostgreSQL caching for generated LLM responses to avoid repeated generations.
"""

import asyncio
import os
import logging
from typing import Optional, Dict
import asyncpg

logger = logging.getLogger("response_generator")

_pool: asyncpg.Pool | None = None

async def get_db_pool() -> asyncpg.Pool:
    global _pool
    if _pool is not None:
        return _pool

    dsn = (
        f"postgresql://{os.environ.get('POSTGRES_USER', 'honeypot')}"
        f":{os.environ.get('POSTGRES_PASSWORD', 'changeme_in_production')}"
        f"@{os.environ.get('POSTGRES_HOST', 'postgres')}"
        f":{os.environ.get('POSTGRES_PORT', '5432')}"
        f"/{os.environ.get('POSTGRES_DB', 'honeypot')}"
    )

    for attempt in range(1, 11):
        try:
            _pool = await asyncpg.create_pool(dsn=dsn, min_size=1, max_size=5)
            logger.info(f"PostgreSQL cache pool established (attempt {attempt})")
            return _pool
        except Exception as exc:
            logger.warning(f"DB connection attempt {attempt}/10 failed: {exc}")
            await asyncio.sleep(2)

    raise RuntimeError("Unable to connect to PostgreSQL for caching")

async def get_cached_response(payload: str, attack_type: str) -> Optional[dict]:
    """
    Search the requests table for an identical previous attack.
    If we've ever generated a response for this exact payload + attack_type, return it.
    """
    try:
        pool = await get_db_pool()
        row = await pool.fetchrow(
            """
            SELECT response, response_type 
            FROM requests 
            WHERE attack_type = $1 
              AND payload = $2 
              AND response_generated = TRUE 
              AND response != '' 
            ORDER BY timestamp DESC 
            LIMIT 1
            """,
            attack_type,
            payload
        )
        if row:
            return {"response": row["response"], "response_type": row["response_type"]}
    except Exception as exc:
        logger.error(f"Cache get error: {exc}")
    return None

async def set_cached_response(payload: str, attack_type: str, response: str, response_type: str) -> None:
    """
    We don't actually need to explicitly 'set' the cache here, because the `honeypot-capture`
    service will update the `requests` table with this response immediately after we return it.
    However, for immediate availability before the honeypot DB update finishes, we could keep 
    a small LRU in memory here too. For simplicity, we strictly rely on the DB.
    """
    pass
