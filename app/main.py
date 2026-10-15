
from app.parser import parse_email
from app.detector import analyze_email


def analyze_message(email_text: str) -> dict:
    """Parse an email and produce a phishing risk report."""

    parsed_email = parse_email(email_text)
    detection = analyze_email(email_text)

    return {
        "email": parsed_email,
        "risk_score": detection["risk_score"],
        "risk_level": detection["risk_level"],
        "indicators": detection["indicators"],
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
    print(f"Risk score: {report['risk_score']}/100")
    print(f"Risk level: {report['risk_level'].upper()}")
    print("\nDetection indicators:")

    for indicator in report["indicators"]:
        print(f"- {indicator['type']}: {indicator['evidence']}")
