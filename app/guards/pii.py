from app.guards.sensitive_data import find_sensitive_data, summarize

def detect_pii(text: str) -> dict:
    detected = summarize(find_sensitive_data(text, {"pii"}))
    return {"blocked": bool(detected), "reason": "PII_DETECTED" if detected else None,
            "detected": detected}
