from app.guards.pii import detect_pii
from app.guards.secrets import detect_secrets

def check_output(text: str) -> dict:
    """Mixed PII/secret output must obey both policies."""
    violations, checks, detected = [], [], []
    for guardrail, detector in (("output_pii", detect_pii), ("output_secrets", detect_secrets)):
        result = detector(text)
        checks.append({"guardrail": guardrail, "stage": "output",
                       "status": "triggered" if result["blocked"] else "passed",
                       "blocked": result["blocked"]})
        detected.extend(result["detected"])
        if result["blocked"]:
            violations.append({"guardrail": guardrail, "stage": "output",
                               "reason": result["reason"],
                               "details": {"detected": result["detected"]}})
    return {"blocked": bool(violations), "reason": "UNSAFE_OUTPUT" if violations else None,
            "details": {"detected": detected}, "violations": violations, "checks": checks}
