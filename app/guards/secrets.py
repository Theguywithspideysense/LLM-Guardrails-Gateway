from app.guards.sensitive_data import find_sensitive_data, summarize

def detect_secrets(text: str) -> dict:
    detected = summarize(find_sensitive_data(text, {"secrets"}))
    return {"blocked": bool(detected), "reason": "SECRET_DETECTED" if detected else None,
            "detected": detected}
