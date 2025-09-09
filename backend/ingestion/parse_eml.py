from typing import Dict, Any
from email.message import EmailMessage


def validate_email_message(msg: EmailMessage) -> bool:
    """
    Validate that the parsed message has minimum required email components.
    """
    # Check for essential headers
    required_headers = ["From", "To", "Subject"]
    present_headers = [h for h in required_headers if msg.get(h)]

    # Must have at least From and To headers
    if len(present_headers) < 2:
        return False

    # Check if message has any content
    if not msg.is_multipart():
        try:
            content = msg.get_content()
            if not content:
                return False
        except (AttributeError, TypeError):
            return False

    return True


def eml_to_parts(msg: EmailMessage) -> Dict[str, Any]:
    subject = msg.get("Subject", "") or ""
    text, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = (part.get_content_type() or "").lower()
            if ctype == "text/plain" and not text:
                try:
                    text = (part.get_content() or "").strip()
                except (AttributeError, TypeError):
                    text = ""
            elif ctype == "text/html" and not html:
                try:
                    html = (part.get_content() or "").strip()
                except (AttributeError, TypeError):
                    html = ""
    else:
        ctype = (msg.get_content_type() or "").lower()
        try:
            body = (msg.get_content() or "").strip()
        except (AttributeError, TypeError):
            body = ""
        if ctype == "text/html":
            html = body
        else:
            text = body

    headers = {k: str(v) for k, v in msg.items()}
    return {
        "headers": headers,
        "subject": subject,
        "body": text,
        "html": html,
        "attachments": [],
    }
