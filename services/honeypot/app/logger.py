"""
Honeypot Service - Structured JSON Logger
All log records include: timestamp, service_name, event_type, message, request_id
"""

import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path


LOG_DIR = Path("/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)


class JsonFormatter(logging.Formatter):
    """Format log records as structured JSON lines."""

    SERVICE_NAME = "honeypot"

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "service_name": self.SERVICE_NAME,
            "event_type":   getattr(record, "event_type", "general"),
            "level":        record.levelname,
            "message":      record.getMessage(),
            "request_id":   getattr(record, "request_id", str(uuid.uuid4())),
        }
        # Merge any extra keys provided by the caller
        for key, value in record.__dict__.items():
            if key not in (
                "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "name",
                "event_type", "request_id", "message",
            ):
                payload[key] = value

        return json.dumps(payload, default=str)


def _build_logger(name: str = "honeypot") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # Already configured

    logger.setLevel(logging.DEBUG)

    # --- stdout handler --------------------------------------------------
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(JsonFormatter())
    logger.addHandler(stdout_handler)

    # --- file handler ----------------------------------------------------
    file_handler = logging.FileHandler(LOG_DIR / "honeypot.log", encoding="utf-8")
    file_handler.setFormatter(JsonFormatter())
    logger.addHandler(file_handler)

    logger.propagate = False
    return logger


logger = _build_logger()


def get_logger() -> logging.Logger:
    return logger
