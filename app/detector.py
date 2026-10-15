
import re
from urllib.parse import urlparse

SUSPICIOUS_PHRASES = [
    "verify your account",
    "account suspended",
    "urgent action required",
    "click here immediately",
    "confirm your password",
    "your account will be closed",
]

CREDENTIAL_PHRASES = [
    "enter your password",
    "send your password",
    "confirm your password",
    "share your credentials",
    "provide your login details",
]

IMPERSONATION_PHRASES = [
    "dear customer",
    "security team",
    "account department",
    "IT support",
]

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "ow.ly",
}

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE,
)

IPV4_PATTERN = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"
)


def analyze_email(email_text: str) -> dict:
    """Analyze an email using explainable phishing indicators."""

    text = email_text.lower()
    indicators = []
    score = 0

    def add_indicator(
        indicator_type: str,
        evidence: str,
        reason: str,
        points: int,
    ) -> None:
        nonlocal score
        indicators.append({
            "type": indicator_type,
            "evidence": evidence,
            "reason": reason,
        })
        score += points

    for phrase in SUSPICIOUS_PHRASES:
        if phrase in text:
            add_indicator(
                "suspicious_phrase",
                phrase,
                "May indicate urgency or credential theft.",
                15,
            )

    for phrase in CREDENTIAL_PHRASES:
        if phrase in text:
            add_indicator(
                "credential_request",
                phrase,
                "Requests for passwords or credentials can indicate phishing.",
                15,
            )

    for phrase in IMPERSONATION_PHRASES:
        if phrase in text:
            add_indicator(
                "possible_impersonation",
                phrase,
                "This wording may imitate a trusted support or security team.",
                5,
            )

    urls = URL_PATTERN.findall(email_text)

    if urls:
        add_indicator(
            "contains_url",
            ", ".join(urls),
            "Links should be checked before being trusted.",
            10,
        )

    for url in urls:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        if parsed.scheme.lower() == "http":
            add_indicator(
                "http_url",
                url,
                "The link does not use HTTPS, so its connection may lack encryption.",
                5,
            )

        if "@" in parsed.netloc:
            add_indicator(
                "suspicious_url_format",
                url,
                "The URL contains '@', which can make the actual destination misleading.",
                15,
            )


        if IPV4_PATTERN.fullmatch(hostname):
            octets = hostname.split(".")
            if all(0 <= int(octet) <= 255 for octet in octets):
                add_indicator(
                    "ip_address_url",
                    url,
                    "The link uses an IP address instead of a domain name.",
                    20,
                )

        if hostname in SHORTENER_DOMAINS:
            add_indicator(
                "shortened_url",
                url,
                "A URL shortener can conceal the final destination.",
                15,
            )

    score = min(score, 100)

    if score >= 40:
        risk = "high"
    elif score >= 15:
        risk = "medium"
    else:
        risk = "low"

    return {
        "risk_score": score,
        "risk_level": risk,
        "indicators": indicators,
    }
