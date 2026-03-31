"""
Structured Logger — Day 3
services/honeypot/app/logging/structured_logger.py

Provides a get_structured_logger() factory that wraps Python's standard
logging with a JSON formatter matching the AI training dataset schema.

Every emitted record is guaranteed to include:
  timestamp, service, event, source_ip, session_id,
  endpoint, attack_type, classification_status, detection_score

Use the `log_event()` helper for one-line structured emission.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Any

SERVICE_NAME: str = os.environ.get("SERVICE_NAME", "honeypot")
LOG_LEVEL:    str = os.environ.get("LOG_LEVEL",    "INFO").upper()
LOG_FILE:     str = os.environ.get("LOG_FILE",     "/logs/honeypot_structured.log")
MAX_BYTES:    int = 50 * 1024 * 1024   # 50 MB per file
BACKUP_COUNT: int = 5                  # keep 5 rotated files


class _JSONFormatter(logging.Formatter):
    """Formats every log record as a single-line JSON object."""

    _STANDARD_FIELDS = {
        "timestamp", "service", "event", "level",
        "source_ip", "session_id", "endpoint",
        "attack_type", "classification_status", "detection_score",
        "method", "request_id", "message",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp":            datetime.now(timezone.utc).isoformat(),
            "service":              SERVICE_NAME,
            "level":                record.levelname,
            "event":                getattr(record, "event", "log"),
            "message":              record.getMessage(),
            "source_ip":            getattr(record, "source_ip",            ""),
            "session_id":           getattr(record, "session_id",           ""),
            "endpoint":             getattr(record, "endpoint",              ""),
            "method":               getattr(record, "method",                ""),
            "attack_type":          getattr(record, "attack_type",           ""),
            "classification_status": getattr(record, "classification_status", ""),
            "detection_score":      getattr(record, "detection_score",      0.0),
            "request_id":           getattr(record, "request_id",           ""),
        }
        # Merge any extra fields not already captured
        for key, val in record.__dict__.items():
            if key not in payload and not key.startswith("_") and key not in {
                "args", "created", "exc_info", "exc_text", "filename",
                "funcName", "levelname", "levelno", "lineno", "module",
                "msecs", "msg", "name", "pathname", "process", "processName",
                "relativeCreated", "stack_info", "thread", "threadName",
            }:
                payload[key] = val
        try:
            return json.dumps(payload, default=str)
        except Exception:  # noqa: BLE001
            return json.dumps({"event": "log_serialization_error", "raw": str(record.getMessage())})


_structured_loggers: dict[str, logging.Logger] = {}


def get_structured_logger(name: str = "honeypot.structured") -> logging.Logger:
    """
    Return a cached structured JSON logger. Safe to call multiple times.
    Writes to stdout AND to the rotating log file at LOG_FILE.
    """
    if name in _structured_loggers:
        return _structured_loggers[name]

    log = logging.getLogger(name)
    log.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    log.propagate = False   # Don't double-emit to the root logger

    fmt = _JSONFormatter()

    # Stdout handler
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    log.addHandler(sh)

    # Rotating file handler (writes to Docker volume)
    try:
        fh = RotatingFileHandler(
            LOG_FILE, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8"
        )
        fh.setFormatter(fmt)
        log.addHandler(fh)
    except (OSError, PermissionError):
        log.warning(f"Could not open log file {LOG_FILE} — file logging disabled")

    _structured_loggers[name] = log
    return log


def log_event(
    logger: logging.Logger,
    *,
    event:                 str,
    level:                 str  = "info",
    source_ip:             str  = "",
    session_id:            str  = "",
    endpoint:              str  = "",
    method:                str  = "",
    attack_type:           str  = "",
    classification_status: str  = "",
    detection_score:       float = 0.0,
    request_id:            str  = "",
    **extra: Any,
) -> None:
    """
    Emit a structured log event in one call.

    Example:
        log_event(
            slogger,
            event="request_captured",
            source_ip="1.2.3.4",
            session_id="sess_abc123",
            endpoint="/login",
            attack_type="SQL Injection",
            classification_status="malicious",
            detection_score=0.98,
        )
    """
    _level = getattr(logging, level.upper(), logging.INFO)
    logger.log(
        _level,
        f"[{event}] {source_ip} → {endpoint}",
        extra={
            "event":                 event,
            "source_ip":             source_ip,
            "session_id":            session_id,
            "endpoint":              endpoint,
            "method":                method,
            "attack_type":           attack_type,
            "classification_status": classification_status,
            "detection_score":       detection_score,
            "request_id":            request_id,
            **extra,
        },
    )
