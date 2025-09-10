import pytest
from backend.ingestion.mime import MultiPartParser
from email.message import EmailMessage
from email import policy
from email.parser import BytesParser
from email.generator import BytesGenerator
from io import BytesIO


def test_multipart_parser_simple():
    """Test MultiPartParser with a simple email."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Subject"
    msg.set_content("This is the body.")

    # Serialize to bytes
    fp = BytesIO()
    g = BytesGenerator(fp, policy=policy.default)
    g.flatten(msg)
    raw_eml = fp.getvalue()

    parser = MultiPartParser(raw_eml)
    assert parser.get_header("Subject") == "Test Subject"
    assert parser.get_body() == "This is the body."
    ctype = parser.get_content_type()
    assert ctype["media_type"] == "text"
    assert ctype["sub_type"] == "plain"
    assert parser.get_multi_parts() == []
    assert parser.get_filename() is None
    assert parser.get_content_id() is None
    assert parser.is_attachment is False
    assert parser.is_inline_image is False
    assert parser.content_type == "text/plain"


def test_multipart_parser_multipart():
    """Test MultiPartParser with multipart email."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Subject"
    msg.make_mixed()  # Make it multipart

    # Add text part
    text_part = EmailMessage()
    text_part.set_content("This is the plain text body.")
    msg.attach(text_part)

    # Add HTML part
    html_part = EmailMessage()
    html_part.set_content("<html><body><p>HTML</p></body></html>", subtype="html")
    msg.attach(html_part)

    # Serialize to bytes
    fp = BytesIO()
    g = BytesGenerator(fp, policy=policy.default)
    g.flatten(msg)
    raw_eml = fp.getvalue()

    parser = MultiPartParser(raw_eml)
    assert parser.get_header("Subject") == "Test Subject"
    assert parser.get_body() is None  # Multipart
    ctype = parser.get_content_type()
    assert ctype["media_type"] == "multipart"
    assert ctype["sub_type"] == "mixed"
    parts = parser.get_multi_parts()
    assert len(parts) == 2
    assert parts[0].get_body() == "This is the plain text body."
    assert parts[1].get_body() == "<html><body><p>HTML</p></body></html>"


def test_multipart_parser_attachment():
    """Test MultiPartParser with attachment."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Subject"
    msg.make_mixed()  # Make it multipart

    # Add attachment
    attachment = EmailMessage()
    attachment.set_content(
        b"attachment content", maintype="application", subtype="octet-stream"
    )
    attachment.add_header("Content-Disposition", "attachment", filename="test.txt")
    msg.attach(attachment)

    # Serialize to bytes
    fp = BytesIO()
    g = BytesGenerator(fp, policy=policy.default)
    g.flatten(msg)
    raw_eml = fp.getvalue()

    parser = MultiPartParser(raw_eml)
    parts = parser.get_multi_parts()
    assert len(parts) == 1
    assert parts[0].is_attachment is True
    assert parts[0].get_filename() == "test.txt"


def test_get_attachments_attachment_disposition():
    """Test get_attachments with Content-Disposition: attachment."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Subject"
    msg.make_mixed()

    # Add attachment
    attachment = EmailMessage()
    attachment.set_content(
        b"attachment content", maintype="application", subtype="octet-stream"
    )
    attachment.add_header("Content-Disposition", "attachment", filename="test.txt")
    msg.attach(attachment)

    # Serialize to bytes
    fp = BytesIO()
    g = BytesGenerator(fp, policy=policy.default)
    g.flatten(msg)
    raw_eml = fp.getvalue()

    parser = MultiPartParser(raw_eml)
    attachments = parser.get_attachments()
    assert len(attachments) == 1
    assert attachments[0].filename == "test.txt"
    assert attachments[0].content_type == "application/octet-stream"
    assert attachments[0].content == b"attachment content"
    assert attachments[0].filesize == len(b"attachment content")
    assert attachments[0].content_disposition == 'attachment; filename="test.txt"'


def test_get_attachments_filename_only():
    """Test get_attachments with filename but no attachment disposition."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Subject"
    msg.make_mixed()

    # Add part with filename but no disposition
    part = EmailMessage()
    part.set_content(b"file content", maintype="application", subtype="octet-stream")
    part.add_header("Content-Disposition", "inline", filename="inline.txt")
    msg.attach(part)

    # Serialize to bytes
    fp = BytesIO()
    g = BytesGenerator(fp, policy=policy.default)
    g.flatten(msg)
    raw_eml = fp.getvalue()

    parser = MultiPartParser(raw_eml)
    attachments = parser.get_attachments()
    assert len(attachments) == 1
    assert attachments[0].filename == "inline.txt"


def test_get_attachments_exclude_inline_with_cid():
    """Test get_attachments excludes inline images with Content-ID."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Subject"
    msg.make_mixed()

    # Add inline image with CID
    image = EmailMessage()
    image.set_content(b"image data", maintype="image", subtype="png")
    image.add_header("Content-Disposition", "inline", filename="image.png")
    image.add_header("Content-ID", "<image1@example.com>")
    msg.attach(image)

    # Serialize to bytes
    fp = BytesIO()
    g = BytesGenerator(fp, policy=policy.default)
    g.flatten(msg)
    raw_eml = fp.getvalue()

    parser = MultiPartParser(raw_eml)
    attachments = parser.get_attachments()
    assert len(attachments) == 0  # Should be excluded as it's an inline image
