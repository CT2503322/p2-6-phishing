import pytest
from backend.ingestion.parse_eml import validate_email_message, eml_to_parts
from email.message import EmailMessage
from email import policy
from email.parser import BytesParser


def test_validate_email_message_valid():
    """Test validation of a valid email message."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Subject"
    msg.set_content("This is the body.")

    assert validate_email_message(msg) is True


def test_validate_email_message_missing_headers():
    """Test validation with missing required headers."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    # Missing To and Subject
    msg.set_content("This is the body.")

    assert validate_email_message(msg) is False


def test_validate_email_message_no_content():
    """Test validation with no content."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Subject"
    # No content set

    assert validate_email_message(msg) is False


def test_eml_to_parts_text_only():
    """Test parsing a text-only email."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Subject"
    msg.set_content("This is the plain text body.")

    parts = eml_to_parts(msg)
    assert parts["subject"] == "Test Subject"
    assert parts["body"] == "This is the plain text body."
    assert parts["html"] == ""
    assert "From" in parts["headers"]
    assert "To" in parts["headers"]


def test_eml_to_parts_html_only():
    """Test parsing an HTML-only email."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Subject"
    msg.set_content(
        "<html><body><p>This is HTML content.</p></body></html>", subtype="html"
    )

    parts = eml_to_parts(msg)
    assert parts["subject"] == "Test Subject"
    assert parts["body"] == ""
    assert parts["html"] == "<html><body><p>This is HTML content.</p></body></html>"
    assert "From" in parts["headers"]


def test_eml_to_parts_multipart():
    """Test parsing a multipart email."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Subject"

    # Add text part
    text_part = EmailMessage()
    text_part.set_content("This is the plain text body.")
    msg.attach(text_part)

    # Add HTML part
    html_part = EmailMessage()
    html_part.set_content(
        "<html><body><p>This is HTML content.</p></body></html>", subtype="html"
    )
    msg.attach(html_part)

    parts = eml_to_parts(msg)
    assert parts["subject"] == "Test Subject"
    assert parts["body"] == "This is the plain text body."
    assert parts["html"] == "<html><body><p>This is HTML content.</p></body></html>"
    assert "From" in parts["headers"]


def test_eml_to_parts_no_subject():
    """Test parsing email with no subject."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg.set_content("This is the body.")

    parts = eml_to_parts(msg)
    assert parts["subject"] == ""
    assert parts["body"] == "This is the body."


def test_eml_to_parts_headers():
    """Test that headers are properly extracted."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Subject"
    msg["X-Custom"] = "Custom Value"
    msg.set_content("Body")

    parts = eml_to_parts(msg)
    assert parts["headers"]["From"] == "sender@example.com"
    assert parts["headers"]["To"] == "recipient@example.com"
    assert parts["headers"]["Subject"] == "Test Subject"
    assert parts["headers"]["X-Custom"] == "Custom Value"
