"""Structured logging configuration for RouteGhost.

Sets up Python's logging module with:
- RotatingFileHandler (app.log, 10MB, 5 backups)
- StreamHandler (stdout) for console output
- Structured format: [timestamp] LEVEL [module] message
"""
import os
import logging
import logging.handlers
import json
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Optional JSON formatter for structured log output."""

    def format(self, record):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "extra_data"):
            log_entry["data"] = record.extra_data
        return json.dumps(log_entry)


class HumanFormatter(logging.Formatter):
    """Human-readable formatter for console/file output."""

    def __init__(self):
        super().__init__(
            fmt="[%(asctime)s] %(levelname)-7s [%(name)s] %(request_id)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )


class RequestIDFilter(logging.Filter):
    """Inject request_id into log records from Flask's g context."""

    def filter(self, record):
        try:
            from flask import g, has_request_context
            if has_request_context():
                record.request_id = getattr(g, "request_id", "-")[:8]
            else:
                record.request_id = "-"
        except Exception:
            record.request_id = "-"
        return True


_configured = False
_log_dir = None


def setup_logging(log_dir=None, level=logging.INFO, json_format=False):
    """Configure structured logging for the application.

    Args:
        log_dir: Directory for log files. Uses DATA_DIR if None.
        level: Minimum log level (default: INFO).
        json_format: Use JSON formatter instead of human-readable.
    """
    global _configured, _log_dir

    if _configured:
        return

    if log_dir is None:
        log_dir = os.environ.get("DATA_DIR", os.path.join(os.path.dirname(__file__), "data"))

    _log_dir = log_dir
    os.makedirs(log_dir, exist_ok=True)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    formatter = JSONFormatter() if json_format else HumanFormatter()
    request_filter = RequestIDFilter()

    # Rotating file handler
    log_file = os.path.join(log_dir, "app.log")
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    file_handler.addFilter(request_filter)
    root_logger.addHandler(file_handler)

    # Console handler (only if not already configured via Tee)
    console_handler = logging.StreamHandler(__import__("sys").stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(request_filter)
    root_logger.addHandler(console_handler)

    _configured = True
    logging.getLogger("routeghost").info("Logging initialized (level=%s)", logging.getLevelName(level))


def get_logger(name="routeghost"):
    """Get a named logger for the application.

    Usage:
        from logging_config import get_logger
        logger = get_logger(__name__)
        logger.info("Service enabled", extra={"extra_data": {"service_id": 123}})
    """
    return logging.getLogger(name)
