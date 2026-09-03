from app.services.risk_engine import calculate_risk


def test_no_violations():

    result = calculate_risk([])

    assert result["score"] == 0
    assert result["level"] == "LOW"


def test_pii():

    result = calculate_risk([
        {
            "guardrail": "pii"
        }
    ])

    assert result["score"] == 20


def test_secret():

    result = calculate_risk([
        {
            "guardrail": "secrets"
        }
    ])

    assert result["score"] == 50


def test_jailbreak():

    result = calculate_risk([
        {
            "guardrail": "jailbreak"
        }
    ])

    assert result["score"] == 80