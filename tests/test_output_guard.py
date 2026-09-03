from app.guards.output_guard import check_output


def test_safe_output():

    result = check_output(
        "Here is a Python function."
    )

    assert result["blocked"] is False


def test_email_detection():

    result = check_output(
        "Email: test@example.com"
    )

    assert result["blocked"] is True


def test_github_token_detection():

    result = check_output(
        "Token: ghp_123456789012345678901234567890"
    )

    assert result["blocked"] is True