
from app.parser import parse_email
from app.detector import analyze_email
from app.ml_detector import predict_email


def analyze_message(email_text: str) -> dict:
    """Combine parsing, rule-based detection, and ML prediction."""

    parsed_email = parse_email(email_text)
    rule_result = analyze_email(email_text)
    ml_result = predict_email(email_text)

    return {
        "email": parsed_email,
        "risk_score": rule_result["risk_score"],
        "risk_level": rule_result["risk_level"],
        "indicators": rule_result["indicators"],
        "ml_prediction": ml_result["prediction"],
        "ml_phishing_probability": ml_result["phishing_probability"],
    }


if __name__ == "__main__":
    sample_email = """From: security@example.com
Subject: Urgent action required

Your account suspended. Verify your account immediately.
Visit https://example.com/login
"""

    report = analyze_message(sample_email)

    print("PHISHGUARD AI — ANALYSIS REPORT")
    print("-" * 35)
    print(f"Sender: {report['email']['sender']}")
    print(f"Subject: {report['email']['subject']}")
    print(f"Rule-based risk score: {report['risk_score']}/100")
    print(f"Rule-based risk level: {report['risk_level'].upper()}")
    print(f"ML prediction: {report['ml_prediction']}")
    print(
        "ML phishing probability: "
        f"{report['ml_phishing_probability']:.2%}"
    )
    print("\nDetection indicators:")

    for indicator in report["indicators"]:
        print(f"- {indicator['type']}: {indicator['evidence']}")
