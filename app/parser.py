
import re


URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE,
)


def parse_email(email_text: str) -> dict:
    """Extract basic fields from a plain-text email."""

    lines = email_text.splitlines()
    sender = None
    subject = None
    body_lines = []
    body_started = False

    for line in lines:
        if not body_started and line.strip() == "":
            body_started = True
            continue

        if not body_started:
            if line.lower().startswith("from:"):
                sender = line.split(":", 1)[1].strip()
            elif line.lower().startswith("subject:"):
                subject = line.split(":", 1)[1].strip()
            else:
                body_lines.append(line)
        else:
            body_lines.append(line)

    body = "\n".join(body_lines).strip()
    urls = URL_PATTERN.findall(email_text)

    return {
        "sender": sender,
        "subject": subject,
        "body": body,
        "urls": urls,
    }
