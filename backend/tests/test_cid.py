import pytest
from backend.ingestion.mime import MultiPartParser
from email.message import EmailMessage
from email import policy
from email.parser import BytesParser
from email.generator import BytesGenerator
from io import BytesIO


def test_content_id_parsing():
    """Test parsing Content-ID headers."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Subject"
    msg.make_mixed()

    # Add part with Content-ID
    part = EmailMessage()
    part.set_content(b"content", maintype="image", subtype="png")
    part.add_header("Content-ID", "<image1@example.com>")
    msg.attach(part)

    # Serialize to bytes
    fp = BytesIO()
    g = BytesGenerator(fp, policy=policy.default)
    g.flatten(msg)
    raw_eml = fp.getvalue()

    parser = MultiPartParser(raw_eml)
    parts = parser.get_multi_parts()
    assert len(parts) == 1
    assert parts[0].get_content_id() == "image1@example.com"


def test_content_id_with_angle_brackets():
    """Test Content-ID with angle brackets."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Subject"
    msg.make_mixed()

    # Add part with Content-ID in angle brackets
    part = EmailMessage()
    part.set_content(b"content", maintype="image", subtype="png")
    part.add_header("Content-ID", "<image1@example.com>")
    msg.attach(part)

    # Serialize to bytes
    fp = BytesIO()
    g = BytesGenerator(fp, policy=policy.default)
    g.flatten(msg)
    raw_eml = fp.getvalue()

    parser = MultiPartParser(raw_eml)
    parts = parser.get_multi_parts()
    assert len(parts) == 1
    assert parts[0].get_content_id() == "image1@example.com"


def test_content_id_without_angle_brackets():
    """Test Content-ID without angle brackets."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Subject"
    msg.make_mixed()

    # Add part with Content-ID without angle brackets
    part = EmailMessage()
    part.set_content(b"content", maintype="image", subtype="png")
    part.add_header("Content-ID", "image1@example.com")
    msg.attach(part)

    # Serialize to bytes
    fp = BytesIO()
    g = BytesGenerator(fp, policy=policy.default)
    g.flatten(msg)
    raw_eml = fp.getvalue()

    parser = MultiPartParser(raw_eml)
    parts = parser.get_multi_parts()
    assert len(parts) == 1
    assert parts[0].get_content_id() == "image1@example.com"


def test_content_id_none():
    """Test parts without Content-ID."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Subject"
    msg.make_mixed()

    # Add part without Content-ID
    part = EmailMessage()
    part.set_content(b"content", maintype="text", subtype="plain")
    msg.attach(part)

    # Serialize to bytes
    fp = BytesIO()
    g = BytesGenerator(fp, policy=policy.default)
    g.flatten(msg)
    raw_eml = fp.getvalue()

    parser = MultiPartParser(raw_eml)
    parts = parser.get_multi_parts()
    assert len(parts) == 1
    assert parts[0].get_content_id() is None
