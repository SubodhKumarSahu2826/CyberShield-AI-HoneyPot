"""
Honeypot Service - Route Handlers  (Day 4 Update)

Full request processing pipeline:
  1. Extract IP, endpoint, method, headers, payload
  2. Rule-based detection engine                         (Day 2)
  3. AI classifier — only for 'suspicious' traffic      (Day 4)
  4. Session manager — get or create attacker session   (Day 3)
  5. Structured JSON log with full context              (Day 3)
  6. Persist to PostgreSQL (incl. AI fields)            (Day 4)
  7. Return convincing fake response
"""

import asyncio
import httpx
import urllib.parse
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from app.classifier_client import ai_classify
from app.database import get_db_pool, insert_request
from app.detection.engine import analyze
from app.logging.structured_logger import get_structured_logger, log_event
from app.session.session_manager import session_manager
from app.enrichment.geo import get_geolocation
from app.enrichment.reputation import get_reputation
from app.async_pipeline.queue_manager import manager as queue_manager, ClassificationJob
from app.behavior.profiler import update_profile
from app.adaptive.decision_engine import decide_response_strategy
from app.security.rate_limiter import is_rate_limited
from app.security.firewall_rules import is_ip_blocked
from app.security.input_sanitizer import sanitize_payload
from app.alerts.alert_manager import check_and_trigger_alerts

slogger = get_structured_logger("honeypot.structured")
router  = APIRouter()

# ---------------------------------------------------------------------------
# Fake response templates
# ---------------------------------------------------------------------------
_FAKE_RESPONSES: dict[str, dict] = {
    "/login":          {"status": "error", "message": "Invalid credentials", "code": 401},
    "/admin":          {"status": "error", "message": "Access denied", "code": 403},
    "/api/users":      {"users": [], "total": 0, "page": 1},
    "/config":         {"error": "Unauthorized", "message": "Configuration access requires admin privileges"},
    "/uploads":        {"status": "error", "message": "Upload failed: invalid session"},
    "/wp-login.php":   {"error": "Invalid username", "code": 403},
    "/.env":           {"APP_ENV": "production", "DB_HOST": "localhost", "SECRET_KEY": "REDACTED"},
}

_DEFAULT_FAKE_RESPONSE = {"status": "ok", "message": "Request processed"}


def _get_fake_response(endpoint: str) -> dict:
    for key, resp in _FAKE_RESPONSES.items():
        if endpoint.startswith(key):
            return resp
    return _DEFAULT_FAKE_RESPONSE


def _status_code_for(endpoint: str, method: str) -> int:
    if endpoint.startswith("/login"):   return 401
    if endpoint.startswith("/admin"):   return 403
    if method in ("POST", "PUT", "PATCH") and endpoint.startswith("/uploads"): return 400
    if endpoint in ("/.env", "/.git"):  return 200
    return 200


async def _extract_payload(request: Request) -> str:
    try:
        body = await request.body()
        return body[:65536].decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return ""


def _sanitize_headers(headers: dict) -> dict:
    return {
        k.replace("\x00", ""): v.replace("\x00", "") if isinstance(v, str) else v
        for k, v in headers.items()
    }


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@router.get("/_health")
async def health_check() -> JSONResponse:
    return JSONResponse({
        "status":          "healthy",
        "service":         "honeypot",
        "active_sessions": session_manager.count(),
    })


@router.get("/_queue_size")
async def get_queue_size() -> JSONResponse:
    """Expose the AI queue depth for the Dashboard (Day 5)"""
    return JSONResponse({"queue_size": queue_manager.get_size()})


# ---------------------------------------------------------------------------
# Catch-all route — handles ALL paths and ALL HTTP methods
# ---------------------------------------------------------------------------
@router.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def capture_request(path: str, request: Request) -> Response:
    request_id = str(uuid.uuid4())
    now        = datetime.now(timezone.utc)

    # 1. Extract request details
    endpoint = request.url.path
    if request.url.query:
        endpoint += f"?{urllib.parse.unquote(request.url.query)}"
    
    xff = request.headers.get("x-forwarded-for", "")
    source_ip = (
        xff.split(",")[0].strip()
        if xff
        else (request.client.host if request.client else "0.0.0.0")
    )

    # Ensure immediate block if IP is dynamically blacklisted (Milestone 3)
    if await is_ip_blocked(source_ip):
        return JSONResponse({"status": "error", "message": "Access denied by security policy"}, status_code=403)

    # Check Rate Limit (Milestone 3)
    if await is_rate_limited(source_ip):
        slogger.warning(f"Rate limit exceeded for {source_ip}", extra={"event_type": "rate_limit_exceeded"})
        return JSONResponse({"status": "error", "message": "Too many requests"}, status_code=429)

    method    = request.method
    headers   = _sanitize_headers(dict(request.headers))
    raw_payload = await _extract_payload(request)
    payload   = sanitize_payload(raw_payload)  # Strip invisible control chars
    timestamp = now.isoformat()

    # 2. Rule-based detection engine (Day 2)
    detection = analyze(
        endpoint=endpoint,
        payload=payload,
        headers=headers,
    )

    # 3. AI classifier — Moved to Background Async Queue (Day 5)
    #    The request is inserted first, then queued so it doesn't block capture.
    ai_attack_type      = ""
    ai_confidence_score = 0.0
    final_status = detection.status

    # 4. Session tracking (Day 3 + Milestone 2B)
    adaptive_strategy = "low_sophistication: Return standard minimal dummy responses."
    session = None
    try:
        pool    = await get_db_pool()
        session = await session_manager.get_or_create(
            source_ip=source_ip,
            attack_type=detection.attack_type,
            pool=pool,
        )
        session_id = session.session_id
        
        # Profile behavioral intelligence and generate dynamic strategy
        update_profile(session, endpoint, len(payload))
        adaptive_strategy = decide_response_strategy(session)
        
        # Check alerts threshold asynchronously (Milestone 3)
        asyncio.create_task(
            check_and_trigger_alerts(
                source_ip, 
                session_id, 
                detection.attack_type, 
                session.attacker_score, 
                session.request_count
            )
        )
    except Exception as exc:  # noqa: BLE001
        session_id = ""
        slogger.warning(f"Session manager error: {exc}", extra={"event_type": "session_error"})

    # 5. Structured JSON log with full context (Day 3 + Day 4)
    log_event(
        slogger,
        event="attack_detected" if final_status == "malicious" else "request_captured",
        level="warning" if final_status == "malicious" else "info",
        source_ip=source_ip,
        session_id=session_id,
        endpoint=endpoint,
        method=method,
        attack_type=ai_attack_type if final_status == "malicious" and ai_attack_type else detection.attack_type,
        classification_status=final_status,
        detection_score=detection.detection_score,
        request_id=request_id,
        ai_attack_type=ai_attack_type,
        ai_confidence_score=ai_confidence_score,
    )

    # 5b. Threat Intelligence Enrichment (Day 4)
    geo_data = {"country": "", "city": "", "asn": ""}
    rep_data = {"reputation_score": 0, "reputation_tags": []}
    try:
        results = await asyncio.gather(
            get_geolocation(source_ip),
            get_reputation(source_ip, detection.attack_type),
            return_exceptions=True
        )
        if not isinstance(results[0], Exception):
            geo_data = results[0]
        if not isinstance(results[1], Exception):
            rep_data = results[1]
    except Exception as exc:  # noqa: BLE001
        slogger.warning(f"Enrichment error: {exc}", extra={"event_type": "enrichment_error"})

    # 6. Persist to PostgreSQL (incl. AI fields)
    try:
        row_id = await insert_request(
            source_ip=source_ip,
            method=method,
            endpoint=endpoint,
            headers=headers,
            payload=payload,
            timestamp=timestamp,
            detection_status=final_status,
            attack_type=ai_attack_type if final_status == "malicious" and ai_attack_type else detection.attack_type,
            detection_score=detection.detection_score,
            session_id=session_id,
            response_generated=False,
            ai_attack_type=ai_attack_type,
            ai_confidence_score=ai_confidence_score,
            country=geo_data.get("country", ""),
            city=geo_data.get("city", ""),
            asn=geo_data.get("asn", ""),
            reputation_score=rep_data.get("reputation_score", 0),
            reputation_tags=rep_data.get("reputation_tags", []),
            attacker_score=session.attacker_score if session else 0.0,
            attacker_type=session.attacker_type if session else "unknown",
            attack_pattern=session.attack_pattern if session else "none",
        )
        slogger.debug(
            f"Stored row id={row_id}",
            extra={"event_type": "db_stored", "request_id": request_id, "db_row_id": row_id},
        )
    except Exception as exc:  # noqa: BLE001
        row_id = -1
        slogger.error(f"Database insert error: {exc}", extra={"event_type": "db_error"})

    # 7. Enqueue Async AI Classification for evaded requests (Day 5 + Evasion Defense)
    #    Only if the rule-based engine MISSED the attack (not malicious).
    #    This avoids wasting LLM resources when the rule engine already caught it.
    if row_id != -1 and final_status != "malicious":
        job = ClassificationJob(
            request_id=row_id,
            method=method,
            endpoint=endpoint,
            headers=headers,
            payload=payload,
            source_ip=source_ip,
            session_id=session_id,
        )
        queue_manager.enqueue(job)
        slogger.debug(f"Enqueued async classification for {row_id} (rule_status={final_status})")
    elif row_id != -1:
        slogger.debug(f"Skipping AI classification for {row_id} - already caught by rule engine.")


    # 8. Return convincing fake response (Milestone 2A)
    fake_body = _get_fake_response(endpoint)
    status_code    = _status_code_for(endpoint, method)
    res_type = "static_fallback"
    
    if final_status in ("malicious", "suspicious"):
        try:
            async with httpx.AsyncClient(timeout=90.0) as client:
                res = await client.post(
                    "http://response-generator:3002/generate-response",
                    json={
                        "payload": payload,
                        "endpoint": endpoint,
                        "method": method,
                        "attack_type": detection.attack_type,
                        "session_id": session_id,
                        "strategy": adaptive_strategy,
                        "attacker_type": session.attacker_type if session else "unknown",
                        "attack_pattern": session.attack_pattern if session else "none"
                    }
                )
                if res.status_code == 200:
                    data = res.json()
                    fake_body = data.get("response", fake_body)
                    res_type = data.get("response_type", "unknown")
                    # Update database with the response
                    from app.database import update_request_response
                    if row_id != -1:
                        await update_request_response(
                            request_id=row_id,
                            response=fake_body,
                            response_type=res_type
                        )
        except Exception as exc:
            slogger.error(f"Response Gen error: {exc}", extra={"event_type": "response_gen_error"})

    return JSONResponse(
        content=fake_body,
        status_code=status_code,

        headers={
            "X-Request-ID": request_id,
            "Server": "Apache/2.4.54 (Ubuntu)",
        },
    )
