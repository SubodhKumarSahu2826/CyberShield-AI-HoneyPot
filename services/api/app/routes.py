"""
API Service - Route Handlers  (Day 3 Update)

Endpoints:
  GET /requests              — paginated list (incl. session_id)
  GET /requests/latest       — last 20 requests
  GET /detections            — confirmed malicious requests only
  GET /sessions              — attacker sessions and stats  [Day 3]
  GET /stats                 — aggregate stats incl. session count
  GET /_health               — Docker health check
"""

from fastapi import APIRouter, Query, Response
from fastapi.responses import JSONResponse, PlainTextResponse
import csv
import io

from app.database import (
    fetch_filtered_requests,
    fetch_latest_requests,
    fetch_malicious_requests,
    fetch_sessions,
    fetch_stats,
    fetch_session_timeline,
    fetch_attacker_profiles,
    fetch_analytics_timeline,
    fetch_alerts
)

router = APIRouter()


@router.get("/_health")
async def health() -> JSONResponse:
    return JSONResponse({"status": "healthy", "service": "api"})


@router.get("/requests")
async def get_requests(
    limit:  int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0,  ge=0),
    ip: str | None = None,
    method: str | None = None,
    attack_type: str | None = None,
    from_date: str | None = None,
    to_date: str | None = None,
) -> JSONResponse:
    """Return recent captured requests with pagination and optional filtering."""
    rows = await fetch_filtered_requests(
        limit=limit, offset=offset, ip=ip, method=method, 
        attack_type=attack_type, from_date=from_date, to_date=to_date
    )
    return JSONResponse({"requests": rows, "count": len(rows)})


@router.get("/requests/latest")
async def get_latest_requests() -> JSONResponse:
    """Return the last 20 captured requests."""
    rows = await fetch_latest_requests(limit=20)
    return JSONResponse({"requests": rows, "count": len(rows)})


@router.get("/attacker-profiles")
async def get_attacker_profiles() -> JSONResponse:
    """Return aggregated attacker profiler intelligence logs."""
    rows = await fetch_attacker_profiles(limit=50)
    return JSONResponse({"profiles": rows, "count": len(rows)})

@router.get("/stats")
async def get_stats() -> JSONResponse:
    """Return aggregate statistics: total, unique IPs, malicious count, attack breakdown."""
    stats = await fetch_stats()
    return JSONResponse(stats)


@router.get("/detections")
async def get_detections(
    limit: int = Query(default=50, ge=1, le=500),
) -> JSONResponse:
    """Return recent confirmed malicious requests from the detection engine."""
    rows = await fetch_malicious_requests(limit=limit)
    return JSONResponse({"detections": rows, "count": len(rows)})


@router.get("/sessions")
async def get_sessions(
    limit: int = Query(default=100, ge=1, le=1000),
) -> JSONResponse:
    """Return attacker sessions from the sessions table."""
    sessions = await fetch_sessions(limit=limit)
    return JSONResponse({"sessions": sessions, "count": len(sessions)})


@router.get("/analytics")
async def get_analytics() -> JSONResponse:
    """Return timeline analytics for charts."""
    rows = await fetch_analytics_timeline()
    return JSONResponse({"timeline": rows})


@router.get("/alerts")
async def get_alerts(limit: int = Query(default=50, le=1000)) -> JSONResponse:
    """Return recent system alerts."""
    rows = await fetch_alerts(limit=limit)
    return JSONResponse({"alerts": rows, "count": len(rows)})


@router.get("/export/json")
async def export_dataset_json() -> Response:
    """Export the entire dataset as JSON."""
    rows = await fetch_filtered_requests(limit=100000)
    return JSONResponse({"requests": rows})


@router.get("/export/csv")
async def export_dataset_csv() -> Response:
    """Export the entire dataset as CSV."""
    rows = await fetch_filtered_requests(limit=100000)
    if not rows:
        return PlainTextResponse("No data")
    
    output = io.StringIO()
    import json as _json
    for row in rows:
        if "headers" in row and isinstance(row["headers"], dict):
            row["headers"] = _json.dumps(row["headers"])
        if "reputation_tags" in row and isinstance(row["reputation_tags"], list):
            row["reputation_tags"] = _json.dumps(row["reputation_tags"])
            
    writer = csv.DictWriter(output, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    return PlainTextResponse(output.getvalue(), media_type="text/csv")


@router.get("/sessions/{session_id}/timeline")
async def get_session_timeline(session_id: str) -> JSONResponse:
    """Return chronologically ordered events for a session."""
    rows = await fetch_session_timeline(session_id)
    return JSONResponse({"requests": rows, "count": len(rows)})


@router.get("/metrics")
async def get_metrics() -> PlainTextResponse:
    """Prometheus compatible metrics format."""
    try:
        stats = await fetch_stats()
    except Exception:  # If DB isn't ready
        return PlainTextResponse("")
    
    lines = [
        "# HELP honeypot_requests_total Total number of HTTP requests captured.",
        "# TYPE honeypot_requests_total counter",
        f"honeypot_requests_total {stats.get('total_requests', 0)}",
        "",
        "# HELP honeypot_unique_ips_total Total unique source IPs seen.",
        "# TYPE honeypot_unique_ips_total counter",
        f"honeypot_unique_ips_total {stats.get('unique_ips', 0)}",
        "",
        "# HELP honeypot_malicious_requests_total Total confirmed malicious requests.",
        "# TYPE honeypot_malicious_requests_total counter",
        f"honeypot_malicious_requests_total {stats.get('malicious_count', 0)}",
    ]
    
    return PlainTextResponse("\n".join(lines) + "\n")
