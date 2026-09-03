from app.services.event_store import append_event, recent_events

def log_security_event(event_type: str, data: dict):
    append_event("security_events", event_type, data)

def get_recent_events(limit: int = 10) -> list:
    return recent_events("security_events", limit)
