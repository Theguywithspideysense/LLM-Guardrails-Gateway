"""Cheap checks run before any model call; the gateway runs semantic checks later."""
from app.guards.injection import detect_prompt_injection
from app.guards.input_limits import check_input_limits
from app.guards.jailbreak import detect_jailbreak
from app.guards.pii import detect_pii
from app.guards.prompt_leakage import detect_prompt_leakage
from app.guards.secrets import detect_secrets

DETECTORS = [
    ("input_limits", check_input_limits),
    ("prompt_injection", detect_prompt_injection),
    ("jailbreak", detect_jailbreak),
    ("prompt_leakage", detect_prompt_leakage),
    ("pii", detect_pii),
    ("secrets", detect_secrets),
]

class GuardrailEngine:
    def check_input(self, prompt: str) -> dict:
        checks, violations = [], []
        too_large = False
        for guardrail, detector in DETECTORS:
            if too_large:
                checks.append({"guardrail": guardrail, "stage": "input",
                               "status": "skipped", "blocked": False})
                continue
            result = detector(prompt)
            checks.append({"guardrail": guardrail, "stage": "input",
                           "status": "triggered" if result["blocked"] else "passed",
                           "blocked": result["blocked"]})
            if result["blocked"]:
                violations.append({"guardrail": guardrail, "stage": "input",
                                   "reason": result["reason"],
                                   "details": result.get("details") or {
                                       "detected": result.get("detected", [])}})
            if guardrail == "input_limits":
                too_large = result["blocked"]
        return {"blocked": bool(violations), "violation_count": len(violations),
                "violations": violations, "checks": checks}
