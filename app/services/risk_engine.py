RISK_WEIGHTS = {
    "pii": 20,
    "secrets": 50,
    "prompt_injection": 70,
    "jailbreak": 80,
    "semantic": 60,
    "input_limits": 30,
    "prompt_leakage": 80,
    "output_pii": 30,
    "output_secrets": 60,
}


def calculate_risk(violations: list) -> dict:

    score = 0
    risk_factors = []

    seen = set()
    for violation in violations:

        guardrail = violation.get("guardrail")
        if guardrail in seen:
            continue
        seen.add(guardrail)

        points = RISK_WEIGHTS.get(
            guardrail,
            10
        )

        score += points

        risk_factors.append({
            "guardrail": guardrail,
            "points": points
        })

    score = min(score, 100)

    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
        "factors": risk_factors
    }


def should_block(risk: dict) -> bool:

    return risk["score"] >= 80