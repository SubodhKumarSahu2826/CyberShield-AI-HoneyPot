"""
API Service - Async PostgreSQL Database Layer
Read-only queries from the requests table.
All queries fully parameterized — SQL injection protected.
"""

import asyncio
import os

import asyncpg
import logging

logger = logging.getLogger("api")


_pool: asyncpg.Pool | None = None


async def get_db_pool() -> asyncpg.Pool:
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

    for attempt in range(1, 11):
        try:
            _pool = await asyncpg.create_pool(
                dsn=dsn,
                min_size=1,
                max_size=5,
                command_timeout=30,
            )
            logger.info(f"PostgreSQL pool ready (attempt {attempt})")
            return _pool
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"DB connect attempt {attempt}/10 failed: {exc}")
            await asyncio.sleep(3)

    raise RuntimeError("Unable to connect to PostgreSQL after 10 attempts")


async def close_db_pool() -> None:
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


async def fetch_recent_requests(limit: int = 50, offset: int = 0) -> list[dict]:
    pool = await get_db_pool()
    rows = await pool.fetch(
        """
        SELECT id, source_ip, method, endpoint, headers, payload, timestamp,
               detection_status, attack_type, detection_score,
               session_id, response_generated,
               ai_attack_type, ai_confidence_score,
               country, city, asn, reputation_score, reputation_tags,
               response, response_type,
               attacker_score, attacker_type, attack_pattern
        FROM requests
        ORDER BY timestamp DESC
        LIMIT $1 OFFSET $2
        """,
        limit,
        offset,
    )
    return [_row_to_dict(r) for r in rows]


async def fetch_latest_requests(limit: int = 20) -> list[dict]:
    pool = await get_db_pool()
    rows = await pool.fetch(
        """
        SELECT id, source_ip, method, endpoint, headers, payload, timestamp,
               detection_status, attack_type, detection_score,
               session_id, response_generated,
               ai_attack_type, ai_confidence_score,
               country, city, asn, reputation_score, reputation_tags,
               response, response_type,
               attacker_score, attacker_type, attack_pattern
        FROM requests
        ORDER BY timestamp DESC
        LIMIT $1
        """,
        limit,
    )
    return [_row_to_dict(r) for r in rows]


async def fetch_stats() -> dict:
    pool = await get_db_pool()
    totals = await pool.fetchrow(
        """
        SELECT
            COUNT(*)                        AS total,
            COUNT(DISTINCT source_ip)       AS unique_ips,
            COUNT(*) FILTER (WHERE detection_status = 'malicious') AS malicious_count
        FROM requests
        """
    )
    endpoints = await pool.fetch(
        """
        SELECT endpoint, COUNT(*) AS hit_count
        FROM requests
        GROUP BY endpoint
        ORDER BY hit_count DESC
        LIMIT 10
        """
    )
    attack_types = await pool.fetch(
        """
        SELECT attack_type, COUNT(*) AS count
        FROM requests
        WHERE detection_status = 'malicious'
        GROUP BY attack_type
        ORDER BY count DESC
        LIMIT 10
        """
    )
    attacker_types = await pool.fetch(
        """
        SELECT attacker_type, COUNT(DISTINCT session_id) AS count
        FROM requests
        WHERE attacker_type != '' AND attacker_type != 'unknown'
        GROUP BY attacker_type
        """
    )
    return {
        "total_requests":  totals["total"],
        "unique_ips":      totals["unique_ips"],
        "malicious_count": totals["malicious_count"],
        "top_endpoints":   [dict(r) for r in endpoints],
        "attack_breakdown": [dict(r) for r in attack_types],
        "attacker_breakdown": [dict(r) for r in attacker_types],
    }


async def fetch_malicious_requests(limit: int = 50) -> list[dict]:
    """Return recent confirmed malicious requests."""
    pool = await get_db_pool()
    rows = await pool.fetch(
        """
        SELECT id, source_ip, method, endpoint, headers, payload, timestamp,
               detection_status, attack_type, detection_score,
               session_id, response_generated,
               ai_attack_type, ai_confidence_score,
               country, city, asn, reputation_score, reputation_tags,
               response, response_type,
               attacker_score, attacker_type, attack_pattern
        FROM requests
        WHERE detection_status = 'malicious'
        ORDER BY timestamp DESC
        LIMIT $1
        """,
        limit,
    )
    return [_row_to_dict(r) for r in rows]


async def fetch_filtered_requests(
    limit: int = 50,
    offset: int = 0,
    ip: str | None = None,
    method: str | None = None,
    attack_type: str | None = None,
    from_date: str | None = None,
    to_date: str | None = None,
) -> list[dict]:
    pool = await get_db_pool()
    query = """
        SELECT id, source_ip, method, endpoint, headers, payload, timestamp,
               detection_status, attack_type, detection_score,
               session_id, response_generated,
               ai_attack_type, ai_confidence_score,
               country, city, asn, reputation_score, reputation_tags,
               attacker_score, attacker_type, attack_pattern
        FROM requests
        WHERE 1=1
    """
    args: list = []
    
    if ip:
        args.append(ip)
        query += f" AND source_ip = ${len(args)}"
    if method:
        args.append(method)
        query += f" AND method = ${len(args)}"
    if attack_type:
        args.append(attack_type)
        query += f" AND attack_type = ${len(args)}"
    if from_date:
        args.append(from_date)
        query += f" AND timestamp >= ${len(args)}::timestamp"
    if to_date:
        args.append(to_date)
        query += f" AND timestamp <= ${len(args)}::timestamp"
        
    query += f" ORDER BY timestamp DESC LIMIT ${len(args)+1} OFFSET ${len(args)+2}"
    args.append(limit)
    args.append(offset)
    
    rows = await pool.fetch(query, *args)
    return [_row_to_dict(r) for r in rows]


async def fetch_session_timeline(session_id: str) -> list[dict]:
    pool = await get_db_pool()
    rows = await pool.fetch(
        """
        SELECT id, source_ip, method, endpoint, headers, payload, timestamp,
               detection_status, attack_type, detection_score,
               ai_attack_type, ai_confidence_score
        FROM requests
        WHERE session_id = $1
        ORDER BY timestamp ASC
        """,
        session_id
    )
    return [_row_to_dict(r) for r in rows]


async def fetch_sessions(limit: int = 100) -> list[dict]:
    """Return attacker sessions from the sessions table, most recent first."""
    pool = await get_db_pool()
    try:
        rows = await pool.fetch(
            """
            SELECT session_id, source_ip, first_seen, last_seen,
                   request_count, attack_types,
                   EXTRACT(EPOCH FROM (last_seen - first_seen))::INTEGER AS duration_seconds
            FROM sessions
            ORDER BY last_seen DESC
            LIMIT $1
            """,
            limit,
        )
        return [_session_row_to_dict(r) for r in rows]
    except Exception as exc:  # noqa: BLE001
        # sessions table may not exist yet on old deployment — return empty
        logger.warning(f"fetch_sessions error: {exc}")
        return []

def _row_to_dict(row: asyncpg.Record) -> dict:
    from datetime import datetime
    import json as _json
    d = dict(row)
    # Convert JSONB Record to plain dict
    if "headers" in d:
        h = d["headers"]
        d["headers"] = _json.loads(h) if isinstance(h, str) else h
    # Make timestamp JSON-serializable
    for k, v in d.items():
        if isinstance(v, datetime):
            d[k] = v.isoformat() + "Z"
        elif k == "timestamp" and hasattr(v, "isoformat") and not isinstance(v, str):
            d[k] = v.isoformat() + "Z"
    return d


def _session_row_to_dict(row: asyncpg.Record) -> dict:
    import json as _json
    d = dict(row)
    # Parse JSONB attack_types list
    if "attack_types" in d:
        at = d["attack_types"]
        d["attack_types"] = _json.loads(at) if isinstance(at, str) else (at or [])
    # Make timestamps JSON-serializable
    for field in ("first_seen", "last_seen"):
        if field in d:
            ts = d[field]
            if not isinstance(ts, str) and hasattr(ts, "isoformat"):
                d[field] = ts.isoformat() + "Z"
    # Compute top attack type
    types = d.get("attack_types", [])
    d["top_attack_type"] = max(set(types), key=types.count) if types else ""
    return d

async def fetch_attacker_profiles(limit: int = 50) -> list[dict]:
    pool = await get_db_pool()
    rows = await pool.fetch(
        """
        SELECT DISTINCT ON (session_id) 
               session_id, attacker_score, attacker_type, attack_pattern, source_ip, timestamp
        FROM requests
        WHERE session_id != '' AND attacker_type != 'unknown' AND attacker_type != ''
        ORDER BY session_id, timestamp DESC
        LIMIT $1
        """,
        limit
    )
    return [_row_to_dict(r) for r in rows]

async def fetch_alerts(limit: int = 50) -> list[dict]:
    pool = await get_db_pool()
    try:
        rows = await pool.fetch(
            """
            SELECT id, timestamp, source_ip, session_id, attack_type, severity, message
            FROM alerts
            ORDER BY timestamp DESC
            LIMIT $1
            """,
            limit
        )
        return [_row_to_dict(r) for r in rows]
    except Exception:
        # Table might not exist if Docker entrypoint didn't run, return empty gracefully
        return []

async def fetch_analytics_timeline() -> list[dict]:
    pool = await get_db_pool()
    rows = await pool.fetch(
        """
        SELECT date_trunc('hour', timestamp) AS time_bucket, COUNT(*) AS event_count
        FROM requests
        WHERE timestamp >= NOW() - INTERVAL '24 hours'
        GROUP BY time_bucket
        ORDER BY time_bucket ASC
        """
    )
    return [_row_to_dict(r) for r in rows]
