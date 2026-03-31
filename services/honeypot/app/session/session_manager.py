"""
Session Tracking Module — Day 3
services/honeypot/app/session/session_manager.py

Tracks attacker sessions across multiple requests using source IP as the
correlation key. Sessions are stored both in-memory (for speed) and
persisted to PostgreSQL (for durability across restarts).

Session lifecycle:
  - New IP detected   → create session, generate deterministic session_id
  - Existing IP seen  → update last_seen, increment request_count
  - Idle TTL expired  → evicted from memory, but permanent in PostgreSQL

Thread safety: single asyncio.Lock for in-memory dict mutations.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from app.logger import get_logger

logger = get_logger()

SESSION_TTL_SECONDS: int = int(os.environ.get("SESSION_TTL_SECONDS", "3600"))


@dataclass
class Session:
    session_id:    str
    source_ip:     str
    first_seen:    str          # ISO-8601 UTC string
    last_seen:     str          # ISO-8601 UTC string
    request_count: int = 1
    attack_types:  list = field(default_factory=list)   # rolling list, capped at 50
    endpoints_hit: set = field(default_factory=set)
    payload_lengths: list = field(default_factory=list)
    attacker_score: float = 0.0
    attacker_type: str = "unknown"
    attack_pattern: str = "none"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _generate_session_id(source_ip: str, first_seen: str) -> str:
    """Deterministic: 'sess_' + first 12 hex chars of SHA-256(ip+timestamp)."""
    digest = hashlib.sha256(f"{source_ip}:{first_seen}".encode()).hexdigest()[:12]
    return f"sess_{digest}"


class SessionManager:
    """
    Module-level singleton that manages attacker sessions.

    Call `await session_manager.get_or_create(source_ip=..., ...)` from
    the request handler to get a session_id to attach to each record.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}   # keyed by source_ip
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get_or_create(
        self,
        *,
        source_ip: str,
        attack_type: str = "unknown",
        pool=None,
    ) -> Session:
        """
        Return the matching Session for source_ip, creating one if needed.
        Updates last_seen and request_count on every call.
        The pool argument (asyncpg Pool) is used for DB persistence; if
        None the session is tracked in-memory only.
        """
        async with self._lock:
            existing = self._sessions.get(source_ip)
            if existing is not None:
                existing.last_seen     = _now_iso()
                existing.request_count += 1
                if attack_type and attack_type != "unknown":
                    existing.attack_types.append(attack_type)
                    existing.attack_types = existing.attack_types[-50:]
                session = existing
                is_new  = False
            else:
                now = _now_iso()
                session = Session(
                    session_id    = _generate_session_id(source_ip, now),
                    source_ip     = source_ip,
                    first_seen    = now,
                    last_seen     = now,
                    request_count = 1,
                    attack_types  = [attack_type] if attack_type != "unknown" else [],
                )
                self._sessions[source_ip] = session
                is_new = True

        if is_new:
            logger.info(
                f"New session {session.session_id} for {source_ip}",
                extra={
                    "event_type": "session_created",
                    "session_id": session.session_id,
                    "source_ip":  source_ip,
                },
            )

        if pool is not None:
            await self._upsert(session, pool)

        return session

    def get_all(self) -> list[dict]:
        """Snapshot of all in-memory sessions as dicts."""
        return [self._to_dict(s) for s in self._sessions.values()]

    def get_active(self, *, ttl: int | None = None) -> list[dict]:
        """Sessions seen within the last `ttl` seconds (default: SESSION_TTL_SECONDS)."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=ttl or SESSION_TTL_SECONDS)
        result = []
        for s in self._sessions.values():
            last = datetime.fromisoformat(s.last_seen)
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            if last >= cutoff:
                result.append(self._to_dict(s))
        return sorted(result, key=lambda x: x["last_seen"], reverse=True)

    def count(self) -> int:
        return len(self._sessions)

    def evict_stale(self) -> int:
        """Evict sessions silent for > SESSION_TTL_SECONDS. Returns count removed."""
        cutoff  = datetime.now(timezone.utc) - timedelta(seconds=SESSION_TTL_SECONDS)
        to_drop = [
            ip for ip, s in self._sessions.items()
            if _parse_dt(s.last_seen) < cutoff
        ]
        for ip in to_drop:
            del self._sessions[ip]
        if to_drop:
            logger.info(
                f"Evicted {len(to_drop)} stale sessions",
                extra={"event_type": "sessions_evicted", "count": len(to_drop)},
            )
        return len(to_drop)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _to_dict(s: Session) -> dict:
        top = ""
        if s.attack_types:
            top = max(set(s.attack_types), key=s.attack_types.count)
        return {
            "session_id":        s.session_id,
            "source_ip":         s.source_ip,
            "first_seen":        s.first_seen,
            "last_seen":         s.last_seen,
            "request_count":     s.request_count,
            "top_attack_type":   top,
            "attack_types_seen": sorted(set(s.attack_types)),
        }

    @staticmethod
    async def _upsert(session: Session, pool) -> None:
        """Upsert session row — INSERT or UPDATE on conflict."""
        try:
            await pool.execute(
                """
                INSERT INTO sessions (
                    session_id, source_ip, first_seen, last_seen,
                    request_count, attack_types
                )
                VALUES ($1, $2, $3::timestamp, $4::timestamp, $5, $6::jsonb)
                ON CONFLICT (session_id) DO UPDATE
                    SET last_seen     = EXCLUDED.last_seen,
                        request_count = EXCLUDED.request_count,
                        attack_types  = EXCLUDED.attack_types
                """,
                session.session_id,
                session.source_ip,
                _parse_dt(session.first_seen),
                _parse_dt(session.last_seen),
                session.request_count,
                json.dumps(sorted(set(session.attack_types))),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                f"Session DB upsert failed: {exc}",
                extra={"event_type": "session_db_error", "session_id": session.session_id},
            )


def _parse_dt(iso: str) -> datetime:
    """Parse ISO string to offset-naive datetime for asyncpg TIMESTAMP column."""
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


# Module-level singleton — import everywhere as `from app.session.session_manager import session_manager`
session_manager = SessionManager()
