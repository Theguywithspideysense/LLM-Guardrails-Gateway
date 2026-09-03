from app.services.event_store import append_event

def log_audit_event(event_type: str, data: dict):
    append_event("audit", event_type, data)
