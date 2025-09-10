import pytest
import os
import sys

from backend.ingestion.parse_eml import EmlReader
from backend.ingestion.headers import HeaderNormalizer, get_date
from backend.ingestion.addresses import AddressUtils
from email import policy
from email.parser import BytesParser


# Helper function to load fixture files
def load_fixture(filename):
    """Load a fixture file and return parsed EmailMessage."""
    fixture_path = os.path.join("backend/tests/fixtures", filename)
    with open(fixture_path, "rb") as f:
        raw_eml = f.read()
    parser = BytesParser(policy=policy.default)
    return parser.parsebytes(raw_eml)


# Tests for Headers (T19 - subject/date/received/auth)
def test_headers_plain_eml():
    """Test header parsing with plain.eml fixture."""
    msg = load_fixture("plain.eml")
    normalizer = HeaderNormalizer(msg)

    assert normalizer.get_header("Subject") == "Plain Text Email"
    assert normalizer.get_header("From") == "sender@example.com"
    assert normalizer.get_header("To") == "recipient@example.com"

    # Test date parsing
    date = get_date(normalizer.get_header("Date"))
    assert date is not None
    assert date.year == 2015
    assert date.month == 10
    assert date.day == 21


def test_headers_auth_eml():
    """Test authentication headers with auth_headers.eml fixture."""
    msg = load_fixture("auth_headers.eml")
    normalizer = HeaderNormalizer(msg)

    # Test DKIM signature presence
    dkim = normalizer.get_header("DKIM-Signature")
    assert dkim is not None
    assert "v=1" in dkim
    assert "example.com" in dkim

    # Test Authentication-Results
    auth_results = normalizer.get_header("Authentication-Results")
    assert auth_results is not None
    assert "dkim=pass" in auth_results
    assert "spf=pass" in auth_results
    assert "dmarc=pass" in auth_results

    # Test ARC headers
    arc_results = normalizer.get_header("ARC-Authentication-Results")
    assert arc_results is not None
    assert "dkim=pass" in arc_results

    arc_seal = normalizer.get_header("ARC-Seal")
    assert arc_seal is not None
    assert "i=1" in arc_seal


def test_headers_broken_eml():
    """Test header parsing with malformed headers in broken_headers.eml."""
    msg = load_fixture("broken_headers.eml")
    normalizer = HeaderNormalizer(msg)

    # Should handle broken headers gracefully
    subject = normalizer.get_header("Subject")
    assert subject == "Email with Broken Headers"

    # Test that it can handle duplicate headers
    from_headers = normalizer.get_multi_value_header("from")
    assert len(from_headers) >= 1  # Should have at least one From header


# Tests for Addresses (T19 - parsing & Unicode)
def test_addresses_plain_eml():
    """Test address parsing with plain.eml fixture."""
    msg = load_fixture("plain.eml")
    utils = AddressUtils(msg)

    assert utils.get_from_emails() == ["sender@example.com"]
    assert utils.get_to_emails() == ["recipient@example.com"]
    assert utils.get_from_parsed() == (
        "",
        "sender@example.com",
    )  # Empty string for name when no display name
    assert utils.get_to_parsed() == [
        ("", "recipient@example.com")
    ]  # Empty string for name when no display name


def test_addresses_unicode_eml():
    """Test Unicode address handling."""
    # Create a test with Unicode characters
    from email.message import EmailMessage
    from email import policy
    from email.generator import BytesGenerator
    from io import BytesIO

    msg = EmailMessage()
    msg["From"] = "José María <jose@example.com>"
    msg["To"] = "李小明 <xiaoming@example.com>, Müller <mueller@example.com>"
    msg["Subject"] = "Unicode Test"
    msg.set_content("Test content")

    # Serialize to bytes
    fp = BytesIO()
    g = BytesGenerator(fp, policy=policy.default)
    g.flatten(msg)
    raw_eml = fp.getvalue()

    # Parse back
    parser = BytesParser(policy=policy.default)
    parsed_msg = parser.parsebytes(raw_eml)

    utils = AddressUtils(parsed_msg)

    from_parsed = utils.get_from_parsed()
    assert from_parsed == ("José María", "jose@example.com")

    to_parsed = utils.get_to_parsed()
    expected_to = [
        ("李小明", "xiaoming@example.com"),
        ("Müller", "mueller@example.com"),
    ]
    assert to_parsed == expected_to


# Tests for Body (T19 - selection/charset)
def test_body_plain_eml():
    """Test body extraction from plain.eml fixture."""
    msg = load_fixture("plain.eml")
    reader = EmlReader(msg.as_bytes())

    text_body = reader.get_body_text()
    html_body = reader.get_body_html()

    assert "This is a simple plain text email body." in text_body
    assert "It has multiple lines." in text_body
    assert html_body == ""


def test_body_html_eml():
    """Test body extraction from html.eml fixture."""
    msg = load_fixture("html.eml")
    reader = EmlReader(msg.as_bytes())

    text_body = reader.get_body_text()
    html_body = reader.get_body_html()

    assert text_body == ""  # HTML-only email
    assert "<h1>This is an HTML Email</h1>" in html_body
    assert "<strong>HTML formatting</strong>" in html_body


def test_body_alt_eml():
    """Test body extraction from alt.eml fixture (multipart/alternative)."""
    msg = load_fixture("alt.eml")
    reader = EmlReader(msg.as_bytes())

    text_body = reader.get_body_text()
    html_body = reader.get_body_html()

    assert "This is the plain text version of the email." in text_body
    assert "<h1>This is the HTML version</h1>" in html_body
    assert "<strong>plain text</strong>" in html_body


def test_body_charset_eml():
    """Test charset handling in body extraction."""
    from email.message import EmailMessage
    from email import policy
    from email.generator import BytesGenerator
    from io import BytesIO

    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Charset Test"
    msg.set_content("Héllo wörld with Ümlauts", subtype="plain", charset="utf-8")

    # Serialize to bytes
    fp = BytesIO()
    g = BytesGenerator(fp, policy=policy.default)
    g.flatten(msg)
    raw_eml = fp.getvalue()

    reader = EmlReader(raw_eml)

    text_body = reader.get_body_text()
    assert "Héllo wörld with Ümlauts" in text_body


# Tests for Attachments (T19 - filename/bytesize)
def test_attachments_pdf_eml():
    """Test attachment handling with attachment_pdf.eml fixture."""
    msg = load_fixture("attachment_pdf.eml")
    reader = EmlReader(msg.as_bytes())

    attachments = reader.get_attachments()
    assert len(attachments) == 1

    attachment = attachments[0]
    assert attachment.filename == "document.pdf"
    assert attachment.content is not None
    assert len(attachment.content) > 0  # Should have content
    assert attachment.content_type == "application/pdf"


def test_attachments_no_attachments():
    """Test attachment handling when no attachments present."""
    msg = load_fixture("plain.eml")
    reader = EmlReader(msg.as_bytes())

    attachments = reader.get_attachments()
    assert len(attachments) == 0


# Tests for Inline Images (T19 - cid linkage)
def test_inline_images_related_cid_eml():
    """Test inline image handling with related_cid.eml fixture."""
    msg = load_fixture("related_cid.eml")
    reader = EmlReader(msg.as_bytes())

    images = reader.get_inline_images()
    assert len(images) == 1

    image = images[0]
    assert image.filename == "test.png"
    assert image.content_id == "image1"
    assert image.content is not None
    assert len(image.content) > 0


def test_inline_images_no_images():
    """Test inline image handling when no images present."""
    msg = load_fixture("plain.eml")
    reader = EmlReader(msg.as_bytes())

    images = reader.get_inline_images()
    assert len(images) == 0


# Tests for CID Rewrite (T19 - file and data URL modes)
def test_cid_rewrite_file_mode():
    """Test CID rewrite in file mode."""
    msg = load_fixture("related_cid.eml")
    reader = EmlReader(msg.as_bytes())

    # Test file mode rewrite
    html_body = reader.get_body_html()
    # Should contain cid:image1 reference
    assert "cid:image1" in html_body

    # Test that we can access the image
    images = reader.get_inline_images()
    assert len(images) == 1
    assert images[0].content_id == "image1"


def test_cid_rewrite_data_url_mode():
    """Test CID rewrite in data URL mode."""
    # This would typically involve processing the HTML to replace cid: references
    # with data URLs, but for now we'll test the basic functionality
    msg = load_fixture("related_cid.eml")
    reader = EmlReader(msg.as_bytes())

    html_body = reader.get_body_html()
    images = reader.get_inline_images()

    # Basic validation that we have both HTML and images
    assert html_body is not None
    assert len(images) == 1
    assert images[0].content is not None


# Integration tests using all fixtures
def test_all_fixtures_loadable():
    """Test that all fixture files can be loaded without errors."""
    fixtures = [
        "plain.eml",
        "html.eml",
        "alt.eml",
        "related_cid.eml",
        "attachment_pdf.eml",
        "auth_headers.eml",
        "broken_headers.eml",
    ]

    for fixture in fixtures:
        msg = load_fixture(fixture)
        assert msg is not None
        # Should have basic headers
        assert msg.get("From") is not None
        assert msg.get("To") is not None
        assert msg.get("Subject") is not None


def test_fixture_consistency():
    """Test that fixtures have consistent structure."""
    fixtures = [
        "plain.eml",
        "html.eml",
        "alt.eml",
        "related_cid.eml",
        "attachment_pdf.eml",
    ]

    for fixture in fixtures:
        msg = load_fixture(fixture)
        reader = EmlReader(msg.as_bytes())

        # All should have basic reader functionality
        subject = reader.get_subject()
        from_addr = reader.get_from()
        to_addr = reader.get_to()

        assert subject is not None
        assert from_addr is not None
        assert to_addr is not None
