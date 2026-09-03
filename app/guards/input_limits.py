from app.config import settings

def check_input_limits(text: str) -> dict:
    if len(text) > settings.max_input_length:
        return {"blocked": True, "reason": "INPUT_TOO_LONG",
                "details": {"length": len(text), "maximum": settings.max_input_length}}
    lines = text.count("\n") + 1
    if lines > settings.max_line_count:
        return {"blocked": True, "reason": "TOO_MANY_LINES",
                "details": {"lines": lines, "maximum": settings.max_line_count}}
    return {"blocked": False, "reason": None, "details": {}}
