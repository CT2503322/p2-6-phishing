import pytest
from backend.ingestion.parse_eml import (
    validate_email_message,
    eml_to_parts,
    get_message_text,
    get_message_html,
)
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


def test_get_message_text_simple():
    """Test get_message_text with simple text/plain."""
    msg = EmailMessage()
    msg.set_content("This is plain text.")

    text = get_message_text(msg)
    assert text == "This is plain text."


def test_get_message_text_html_only():
    """Test get_message_text with HTML only."""
    msg = EmailMessage()
    msg.set_content("<p>This is HTML.</p>", subtype="html")

    text = get_message_text(msg)
    assert text == ""


def test_get_message_text_multipart_alternative_text_first():
    """Test get_message_text with multipart/alternative, text/plain first."""
    msg = EmailMessage()
    msg.make_alternative()

    text_part = EmailMessage()
    text_part.set_content("Plain text version.")
    msg.attach(text_part)

    html_part = EmailMessage()
    html_part.set_content("<p>HTML version.</p>", subtype="html")
    msg.attach(html_part)

    text = get_message_text(msg)
    assert text == "Plain text version."


def test_get_message_text_multipart_alternative_html_first():
    """Test get_message_text with multipart/alternative, text/html first."""
    msg = EmailMessage()
    msg.make_alternative()

    html_part = EmailMessage()
    html_part.set_content("<p>HTML version.</p>", subtype="html")
    msg.attach(html_part)

    text_part = EmailMessage()
    text_part.set_content("Plain text version.")
    msg.attach(text_part)

    text = get_message_text(msg)
    assert text == "Plain text version."


def test_get_message_text_multipart_mixed():
    """Test get_message_text with multipart/mixed."""
    msg = EmailMessage()
    msg.make_mixed()

    text_part = EmailMessage()
    text_part.set_content("First text.")
    msg.attach(text_part)

    html_part = EmailMessage()
    html_part.set_content("<p>HTML.</p>", subtype="html")
    msg.attach(html_part)

    text_part2 = EmailMessage()
    text_part2.set_content("Second text.")
    msg.attach(text_part2)

    text = get_message_text(msg)
    assert text == "First text.\n\nSecond text."


def test_get_message_html_simple():
    """Test get_message_html with simple text/html."""
    msg = EmailMessage()
    msg.set_content("<p>This is HTML.</p>", subtype="html")

    html = get_message_html(msg)
    assert html == "<p>This is HTML.</p>"


def test_get_message_html_text_only():
    """Test get_message_html with text/plain only."""
    msg = EmailMessage()
    msg.set_content("This is plain text.")

    html = get_message_html(msg)
    assert html == ""


def test_get_message_html_multipart_alternative():
    """Test get_message_html with multipart/alternative."""
    msg = EmailMessage()
    msg.make_alternative()

    text_part = EmailMessage()
    text_part.set_content("Plain text.")
    msg.attach(text_part)

    html_part = EmailMessage()
    html_part.set_content("<p>HTML version.</p>", subtype="html")
    msg.attach(html_part)

    html = get_message_html(msg)
    assert html == "<p>HTML version.</p>"


def test_get_message_html_multipart_related():
    """Test get_message_html with multipart/related."""
    msg = EmailMessage()
    msg.make_related()

    html_part = EmailMessage()
    html_part.set_content("<p>HTML with image.</p>", subtype="html")
    msg.attach(html_part)

    image_part = EmailMessage()
    image_part.set_content(b"image data", maintype="image", subtype="png")
    msg.attach(image_part)

    html = get_message_html(msg)
    assert html == "<p>HTML with image.</p>"


def test_get_message_html_nested_multipart():
    """Test get_message_html with nested multiparts."""
    msg = EmailMessage()
    msg.make_mixed()

    alt_part = EmailMessage()
    alt_part.make_alternative()

    text_part = EmailMessage()
    text_part.set_content("Text.")
    alt_part.attach(text_part)

    html_part = EmailMessage()
    html_part.set_content("<p>HTML.</p>", subtype="html")
    alt_part.attach(html_part)

    msg.attach(alt_part)

    html = get_message_html(msg)
    assert html == "<p>HTML.</p>"


# Test charset decoding
def test_get_message_text_charset():
    """Test get_message_text with charset decoding."""
    msg = EmailMessage()
    msg.set_content("Héllo wörld", subtype="plain", charset="utf-8")

    text = get_message_text(msg)
    assert text == "Héllo wörld"


def test_get_message_html_charset():
    """Test get_message_html with charset decoding."""
    msg = EmailMessage()
    msg.set_content("<p>Héllo wörld</p>", subtype="html", charset="utf-8")

    html = get_message_html(msg)
    assert html == "<p>Héllo wörld</p>"
