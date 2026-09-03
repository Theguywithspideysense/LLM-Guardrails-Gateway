"""Bounded JSONL logs with UTC timestamps and no prompt/response bodies."""
import json
import logging
from collections import deque
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from threading import RLock
from app.config import settings

_lock = RLock()
_handlers = {}
MAX_LOG_BYTES = 1_048_576

def append_event(name: str, event_type: str, data: dict) -> None:
    event = {"timestamp": datetime.now(timezone.utc).isoformat(),
             "event_type": event_type, "data": data}
    try:
        with _lock:
            if name not in _handlers:
                settings.log_dir.mkdir(parents=True, exist_ok=True)
                handler = RotatingFileHandler(settings.log_dir / f"{name}.jsonl",
                                              maxBytes=MAX_LOG_BYTES, backupCount=3,
                                              encoding="utf-8")
                handler.setFormatter(logging.Formatter("%(message)s"))
                _handlers[name] = handler
            record = logging.LogRecord(name, logging.INFO, "", 0,
                                       json.dumps(event, ensure_ascii=True), (), None)
            _handlers[name].handle(record)
    except OSError:
        logging.getLogger(__name__).error("Could not write gateway event log")

def recent_events(name: str, limit: int) -> list:
    path = settings.log_dir / f"{name}.jsonl"
    if not path.exists():
        return []
    events = deque(maxlen=max(1, min(limit, 100)))
    with _lock, path.open(encoding="utf-8") as source:
        for line in source:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return list(reversed(events))
