import pytest
from backend.ingestion.parse_eml import EmlReader
from email.message import EmailMessage
from email import policy
from email.parser import BytesParser
from email.generator import BytesGenerator
from io import BytesIO


# Tests for EmlReader Integration (T14)
def test_eml_reader_basic():
    """Test basic EmlReader functionality."""
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

    reader = EmlReader(raw_eml)

    # Test header access
    assert reader.get_subject() == "Test Subject"
    assert reader.get_from() == "sender@example.com"
    assert reader.get_to() == "recipient@example.com"

    # Test body methods
    assert reader.get_body_text() == "This is the body."
    assert reader.get_body_html() == ""


def test_eml_reader_multipart():
    """Test EmlReader with multipart email."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Subject"
    msg.make_mixed()

    # Add text part
    text_part = EmailMessage()
    text_part.set_content("Plain text.")
    msg.attach(text_part)

    # Add HTML part
    html_part = EmailMessage()
    html_part.set_content("<p>HTML content.</p>", subtype="html")
    msg.attach(html_part)

    # Serialize to bytes
    fp = BytesIO()
    g = BytesGenerator(fp, policy=policy.default)
    g.flatten(msg)
    raw_eml = fp.getvalue()

    reader = EmlReader(raw_eml)

    assert reader.get_body_text() == "Plain text."
    assert reader.get_body_html() == "<p>HTML content.</p>"


def test_eml_reader_attachments():
    """Test EmlReader attachment handling."""
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

    reader = EmlReader(raw_eml)

    attachments = reader.get_attachments()
    assert len(attachments) == 1
    assert attachments[0].filename == "test.txt"
    assert attachments[0].content == b"attachment content"


def test_eml_reader_inline_images():
    """Test EmlReader inline image handling."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Subject"
    msg.make_mixed()

    # Add HTML with inline image
    html_part = EmailMessage()
    html_part.set_content('<img src="cid:image1">', subtype="html")
    msg.attach(html_part)

    # Add inline image
    image = EmailMessage()
    image.set_content(b"image data", maintype="image", subtype="png")
    image.add_header("Content-Disposition", "inline", filename="image.png")
    image.add_header("Content-ID", "<image1>")
    msg.attach(image)

    # Serialize to bytes
    fp = BytesIO()
    g = BytesGenerator(fp, policy=policy.default)
    g.flatten(msg)
    raw_eml = fp.getvalue()

    reader = EmlReader(raw_eml)

    images = reader.get_inline_images()
    assert len(images) == 1
    assert images[0].filename == "image.png"
    assert images[0].content_id == "image1"


def test_eml_reader_address_methods():
    """Test EmlReader address helper methods."""
    msg = EmailMessage()
    msg["From"] = "John Doe <john@example.com>"
    msg["To"] = "Jane Smith <jane@example.com>, Bob <bob@example.com>"
    msg["Cc"] = "cc@example.com"

    # Serialize to bytes
    fp = BytesIO()
    g = BytesGenerator(fp, policy=policy.default)
    g.flatten(msg)
    raw_eml = fp.getvalue()

    reader = EmlReader(raw_eml)

    # Test parsed addresses
    from_parsed = reader.get_from_parsed()
    assert from_parsed == ("John Doe", "john@example.com")

    to_parsed = reader.get_to_parsed()
    assert len(to_parsed) == 2
    assert ("Jane Smith", "jane@example.com") in to_parsed
    assert ("Bob", "bob@example.com") in to_parsed

    # Test email lists
    assert reader.get_from_emails() == ["john@example.com"]
    assert set(reader.get_to_emails()) == {"jane@example.com", "bob@example.com"}
    assert reader.get_cc_emails() == ["cc@example.com"]


def test_eml_reader_date_parsing():
    """Test EmlReader date parsing."""
    msg = EmailMessage()
    msg["Date"] = "Wed, 21 Oct 2015 07:28:00 -0700"

    # Serialize to bytes
    fp = BytesIO()
    g = BytesGenerator(fp, policy=policy.default)
    g.flatten(msg)
    raw_eml = fp.getvalue()

    reader = EmlReader(raw_eml)

    date = reader.get_date()
    assert date is not None
    assert date.year == 2015
    assert date.month == 10
    assert date.day == 21


def test_eml_reader_multipart_parser_exposure():
    """Test that _multipart_parser is exposed for advanced usage."""
    msg = EmailMessage()
    msg.set_content("Test")

    # Serialize to bytes
    fp = BytesIO()
    g = BytesGenerator(fp, policy=policy.default)
    g.flatten(msg)
    raw_eml = fp.getvalue()

    reader = EmlReader(raw_eml)

    # Should be able to access the underlying parser
    assert hasattr(reader, "_multipart_parser")
    assert reader._multipart_parser is not None
    assert reader._multipart_parser.get_body() == "Test"
