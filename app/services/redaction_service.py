from app.guards.sensitive_data import find_sensitive_data

def redact_sensitive_data(text: str, groups: set[str] | None = None) -> str:
    """Merge overlapping matches and remove whole values, including PEM bodies."""
    findings = sorted(find_sensitive_data(text, groups), key=lambda f: (f.start, -f.end))
    spans = []
    for finding in findings:
        if spans and finding.start < spans[-1][1]:
            start, end, kind = spans[-1]
            spans[-1] = (start, max(end, finding.end), kind)
        else:
            spans.append((finding.start, finding.end, finding.kind))
    for start, end, kind in reversed(spans):
        text = text[:start] + f"[{kind}_REDACTED]" + text[end:]
    return text
