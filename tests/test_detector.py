from app.detector import analyze_email


def test_suspicious_email_is_high_risk():
    email = """
    Subject: Urgent action required
    Your account suspended. Verify your account immediately.
    Visit https://example.com/login
    """
    result = analyze_email(email)

    assert result["risk_score"] == 55
    assert result["risk_level"] == "high"


def test_normal_email_is_low_risk():
    email = """
    Subject: Meeting reminder
    Hi, our team meeting is scheduled for tomorrow.
    """
    result = analyze_email(email)

    assert result["risk_level"] == "low"
    assert result["risk_score"] == 0


def test_email_with_url_has_indicator():
    result = analyze_email(
        "Please visit https://example.com for information."
    )

    assert result["risk_score"] == 10
    assert any(
        item["type"] == "contains_url"
        for item in result["indicators"]
    )


def test_ip_address_url_is_flagged():
    result = analyze_email(
        "Please visit http://192.168.1.10/login"
    )

    assert any(
        item["type"] == "ip_address_url"
        for item in result["indicators"]
    )


def test_shortened_url_is_flagged():
    result = analyze_email(
        "Please open https://bit.ly/example"
    )

    assert any(
        item["type"] == "shortened_url"
        for item in result["indicators"]
    )


def test_credential_request_is_flagged():
    result = analyze_email(
        "Please enter your password to continue."
    )

    assert any(
        item["type"] == "credential_request"
        for item in result["indicators"]
    )


def test_impersonation_language_is_flagged():
    result = analyze_email(
        "Dear customer, the security team needs your attention."
    )

    assert any(
        item["type"] == "possible_impersonation"
        for item in result["indicators"]
    )

def test_http_url_is_flagged():
    result = analyze_email("Please visit http://example.com/login")

    assert any(
        item["type"] == "http_url"
        for item in result["indicators"]
    )


def test_url_with_at_symbol_is_flagged():
    result = analyze_email(
        "Please visit https://trusted.example@evil.example/login"
    )

    assert any(
        item["type"] == "suspicious_url_format"
        for item in result["indicators"]
    )


def test_possible_brand_impersonation_is_flagged():
    result = analyze_email(
        "Sign in at https://paypal-login.example/account"
    )

    assert any(
        item["type"] == "possible_brand_impersonation"
        for item in result["indicators"]
    )


def test_legitimate_brand_domain_is_not_flagged_by_brand_rule():
    result = analyze_email(
        "Visit https://www.paypal.com/account"
    )

    assert not any(
        item["type"] == "possible_brand_impersonation"
        for item in result["indicators"]
    )
