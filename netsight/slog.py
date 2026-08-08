"""Structured JSON logging (feature F10).

One line per event, ``RotatingFileHandler`` for bounded disk use, and
stdlib-only (no external deps). Call ``configure()`` once at startup
with the user-supplied path; every module then does
``logging.getLogger("netsight.<name>")`` as usual.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

_MAX_BYTES = 5 * 1024 * 1024   # 5 MiB per file
_BACKUP_COUNT = 3               # keep .1, .2, .3

_CONFIGURED = False


class _JsonFormatter(logging.Formatter):
    """Render each LogRecord as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        for key in ("subnet", "host_count", "scan_id", "event"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        return json.dumps(payload, default=str)


def configure(log_file: str | Path | None,
              level: int = logging.INFO) -> logging.Logger:
    """Set up the root ``netsight`` logger.

    Args:
        log_file: Path to the JSON log file, or None to disable file
            logging (console-only via rich stays unchanged).
        level: Minimum level written to the file handler.

    Returns:
        The configured root ``netsight`` logger.
    """
    global _CONFIGURED
    root = logging.getLogger("netsight")
    if _CONFIGURED:
        return root

    root.setLevel(level)
    root.propagate = False  # don't double-print through the root logger

    if log_file is not None:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            path,
            maxBytes=_MAX_BYTES,
            backupCount=_BACKUP_COUNT,
            encoding="utf-8",
        )
        handler.setFormatter(_JsonFormatter())
        root.addHandler(handler)

    # A NullHandler keeps ``logging.lastResort`` silent if nothing else
    # is attached (library-style behaviour).
    if not root.handlers:
        root.addHandler(logging.NullHandler())

    _CONFIGURED = True
    return root


def get_logger(name: str) -> logging.Logger:
    """Return a ``netsight.<name>`` child logger."""
    return logging.getLogger(f"netsight.{name}")
