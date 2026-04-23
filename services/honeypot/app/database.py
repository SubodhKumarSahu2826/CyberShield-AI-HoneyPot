"""
Honeypot Service - Async PostgreSQL Database Layer

Uses asyncpg connection pool.
All queries are fully parameterized — no string interpolation.
"""

import asyncio
import os

import asyncpg
from app.logger import get_logger

logger = get_logger()

_pool: asyncpg.Pool | None = None


async def get_db_pool() -> asyncpg.Pool:
    """Return the singleton connection pool, creating it if necessary."""
    global _pool
    if _pool is not None:
        return _pool

    dsn = (
        f"postgresql://{os.environ['POSTGRES_USER']}"
        f":{os.environ['POSTGRES_PASSWORD']}"
        f"@{os.environ.get('POSTGRES_HOST', 'postgres')}"
        f":{os.environ.get('POSTGRES_PORT', '5432')}"
        f"/{os.environ['POSTGRES_DB']}"
    )

    # Retry loop — waits for postgres to be ready
    for attempt in range(1, 11):
        try:
            _pool = await asyncpg.create_pool(
                dsn=dsn,
                min_size=2,
                max_size=10,
                command_timeout=30,
            )
            logger.info(
                "PostgreSQL connection pool established",
                extra={"event_type": "db_connected", "attempt": attempt},
            )
            return _pool
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                f"DB connection attempt {attempt}/10 failed: {exc}",
                extra={"event_type": "db_retry"},
            )
            await asyncio.sleep(3)

    raise RuntimeError("Unable to connect to PostgreSQL after 10 attempts")


async def close_db_pool() -> None:
    global _pool
    if _pool:
        await _pool.close()
        _pool = None
        logger.info("PostgreSQL connection pool closed", extra={"event_type": "db_closed"})


async def insert_request(
    *,
    source_ip: str,
    method: str,
    endpoint: str,
    headers: dict,
    payload: str,
    timestamp: str,
    # Detection result fields (Day 2)
    detection_status: str = "suspicious",
    attack_type: str = "unknown",
    detection_score: float = 0.2,
    # Session tracking fields (Day 3)
    session_id: str = "",
    response_generated: bool = False,
    # AI classifier fields (Day 4)
    ai_attack_type: str = "",
    ai_confidence_score: float = 0.0,
    # Threat Intelligence fields (Day 4)
    country: str = "",
    city: str = "",
    asn: str = "",
    reputation_score: int = 0,
    reputation_tags: list = None,
    # Milestone 2B Behaviour Profiling
    attacker_score: float = 0.0,
    attacker_type: str = "",
    attack_pattern: str = "",
) -> int:
    """Insert one captured request (with detection + session + AI data) and return row id."""
    pool = await get_db_pool()

    import json as _json
    from datetime import datetime

    # Parse ISO timestamp to offset-naive datetime for asyncpg TIMESTAMP column
    from datetime import timezone
    try:
        dt_timestamp = datetime.fromisoformat(timestamp)
        if dt_timestamp.tzinfo is not None:
            dt_timestamp = dt_timestamp.astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        dt_timestamp = datetime.now()  # already naive

    # Sanitize text fields — strip null bytes
    source_ip          = source_ip.replace("\x00", "")[:64]
    method             = method.replace("\x00", "")[:16]
    endpoint           = endpoint.replace("\x00", "")[:2048]
    payload            = payload.replace("\x00", "")[:65536]
    detection_status   = detection_status.replace("\x00", "")[:32]
    attack_type        = attack_type.replace("\x00", "")[:64]
    session_id         = session_id.replace("\x00", "")[:64]
    ai_attack_type     = ai_attack_type.replace("\x00", "")[:128]
    country            = country.replace("\x00", "")[:64]
    city               = city.replace("\x00", "")[:64]
    asn                = asn.replace("\x00", "")[:128]
    reputation_tags_list = reputation_tags or []
    attacker_type      = attacker_type.replace("\x00", "")[:64]
    attack_pattern     = attack_pattern.replace("\x00", "")[:64]

    row = await pool.fetchrow(
        """
        INSERT INTO requests (
            source_ip, method, endpoint, headers, payload, timestamp,
            detection_status, attack_type, detection_score,
            session_id, response_generated,
            ai_attack_type, ai_confidence_score,
            country, city, asn, reputation_score, reputation_tags,
            attacker_score, attacker_type, attack_pattern
        )
        VALUES ($1, $2, $3, $4::jsonb, $5, $6::timestamp, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18::jsonb, $19, $20, $21)
        RETURNING id
        """,
        source_ip,
        method,
        endpoint,
        _json.dumps(headers),
        payload,
        dt_timestamp,
        detection_status,
        attack_type,
        detection_score,
        session_id,
        response_generated,
        ai_attack_type,
        ai_confidence_score,
        country,
        city,
        asn,
        reputation_score,
        _json.dumps(reputation_tags_list),
        attacker_score,
        attacker_type,
        attack_pattern,
    )
    return row["id"]


async def update_request_classification(
    *,
    request_id: int,
    detection_status: str,
    ai_attack_type: str,
    ai_confidence_score: float,
) -> None:
    """Async updater for the background AI inference pipeline (Day 5).
    
    Also updates the `attack_type` column when the AI detects an evasion
    attack that the rule engine missed (i.e. when the current attack_type
    is 'none' or 'unknown' but the AI identified a real attack).
    """
    pool = await get_db_pool()
    await pool.execute(
        """
        UPDATE requests 
        SET detection_status   = $2, 
            ai_attack_type     = $3, 
            ai_confidence_score = $4,
            attack_type = CASE
                WHEN attack_type IN ('none', 'unknown', '') AND $3 != '' AND $3 != 'model_unavailable' AND $3 != 'None / Benign'
                THEN $3
                ELSE attack_type
            END
        WHERE id = $1
        """,
        request_id,
        detection_status,
        ai_attack_type,
        ai_confidence_score,
    )
    logger.debug(f"DB updated AI classification for request {request_id} -> {detection_status} (ai_type={ai_attack_type})")


async def update_request_response(
    *,
    request_id: int,
    response: str,
    response_type: str,
) -> None:
    """Async updater to persist the payload response served to the attacker (Milestone 2A)."""
    pool = await get_db_pool()
    await pool.execute(
        """
        UPDATE requests 
        SET response = $2, 
            response_type = $3,
            response_generated = TRUE
        WHERE id = $1
        """,
        request_id,
        response,
        response_type,
    )

async def insert_alert(
    *,
    source_ip: str,
    session_id: str,
    attack_type: str,
    severity: str,
    message: str,
) -> None:
    """Async insert helper for Alert Manager events (Milestone 3)."""
    pool = await get_db_pool()
    await pool.execute(
        """
        INSERT INTO alerts (source_ip, session_id, attack_type, severity, message)
        VALUES ($1, $2, $3, $4, $5)
        """,
        source_ip.replace("\x00", "")[:64],
        session_id.replace("\x00", "")[:64],
        attack_type.replace("\x00", "")[:64],
        severity.replace("\x00", "")[:32],
        message.replace("\x00", "")[:2048],
    )
