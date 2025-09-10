"""
Tests for MIME parts and content metrics functionality.
"""

import pytest
from email import policy
from email.parser import BytesParser
from backend.ingestion.parse_eml import eml_to_parts
from backend.ingestion.mime import MultiPartParser
from backend.ingestion.metrics import extract_html_metrics, extract_text_metrics


class TestMimeParts:
    """Test MIME parts metadata extraction."""

    def test_mime_part_metadata_basic(self):
        """Test basic MIME part metadata extraction."""
        # Create a simple email message
        raw_email = """From: test@example.com
To: recipient@example.com
Subject: Test Email
Content-Type: text/plain

Hello World
"""
        parser = BytesParser(policy=policy.default)
        msg = parser.parsebytes(raw_email.encode("utf-8"))

        multipart_parser = MultiPartParser(message=msg)
        mime_parts = multipart_parser.get_all_mime_parts()

        assert len(mime_parts) == 1
        part = mime_parts[0]

        assert part.content_type == "text/plain"
        assert part.size > 0
        assert part.hash is not None
        assert not part.is_attachment
        assert not part.is_inline_image

    def test_mime_part_metadata_multipart(self):
        """Test MIME part metadata for multipart messages."""
        raw_email = """From: test@example.com
To: recipient@example.com
Subject: Test Email
Content-Type: multipart/mixed; boundary="boundary"

--boundary
Content-Type: text/plain

Hello World

--boundary
Content-Type: text/html

<html><body>Hello World</body></html>

--boundary--
"""
        parser = BytesParser(policy=policy.default)
        msg = parser.parsebytes(raw_email.encode("utf-8"))

        multipart_parser = MultiPartParser(message=msg)
        mime_parts = multipart_parser.get_all_mime_parts()

        # Should have 3 parts: multipart container + text/plain + text/html
        assert len(mime_parts) >= 2

        # Check that we have both text/plain and text/html parts
        content_types = [part.content_type for part in mime_parts]
        assert "text/plain" in content_types
        assert "text/html" in content_types

    def test_mime_part_metadata_attachment(self):
        """Test MIME part metadata for attachments."""
        raw_email = """From: test@example.com
To: recipient@example.com
Subject: Test Email
Content-Type: multipart/mixed; boundary="boundary"

--boundary
Content-Type: text/plain

Hello World

--boundary
Content-Type: application/pdf
Content-Disposition: attachment; filename="test.pdf"

PDF content here

--boundary--
"""
        parser = BytesParser(policy=policy.default)
        msg = parser.parsebytes(raw_email.encode("utf-8"))

        multipart_parser = MultiPartParser(message=msg)
        mime_parts = multipart_parser.get_all_mime_parts()

        # Find the attachment part
        attachment_parts = [part for part in mime_parts if part.is_attachment]
        assert len(attachment_parts) == 1

        part = attachment_parts[0]
        assert part.content_type == "application/pdf"
        assert part.filename == "test.pdf"
        assert part.disposition is not None
        assert "attachment" in part.disposition


class TestHtmlMetrics:
    """Test HTML metrics extraction."""

    def test_html_metrics_basic(self):
        """Test basic HTML metrics extraction."""
        html = "<html><body><p>Hello World</p></body></html>"
        subject = "Test Subject"

        metrics = extract_html_metrics(html, subject)

        assert metrics.length == len(html)
        assert metrics.link_count == 0
        assert metrics.image_count == 0
        assert not metrics.remote_css
        assert metrics.tracking_pixels == 0
        assert metrics.ratio_text_to_html > 0
        assert not metrics.uses_soft_hyphen
        assert not metrics.has_emoji_in_subject

    def test_html_metrics_with_links_and_images(self):
        """Test HTML metrics with links and images."""
        html = """
        <html>
        <body>
            <a href="http://example.com">Link 1</a>
            <a href="https://test.com">Link 2</a>
            <img src="image1.jpg" alt="Image 1">
            <img src="image2.png" alt="Image 2">
            <img src="http://tracking.com/pixel.gif" width="1" height="1">
        </body>
        </html>
        """

        metrics = extract_html_metrics(html)

        assert metrics.link_count == 2
        assert metrics.image_count == 3
        assert metrics.tracking_pixels >= 1  # At least the 1x1 tracking pixel

    def test_html_metrics_soft_hyphen(self):
        """Test detection of soft hyphens."""
        html = "Hello­World"  # Contains soft hyphen

        metrics = extract_html_metrics(html)

        assert metrics.uses_soft_hyphen

    def test_html_metrics_emoji_in_subject(self):
        """Test detection of emoji in subject."""
        html = "<html><body>Test</body></html>"
        subject = "Test Subject 🔔"

        metrics = extract_html_metrics(html, subject)

        assert metrics.has_emoji_in_subject

    def test_html_metrics_remote_css(self):
        """Test detection of remote CSS."""
        html = """
        <html>
        <head>
            <link rel="stylesheet" href="http://example.com/style.css">
        </head>
        <body>Test</body>
        </html>
        """

        metrics = extract_html_metrics(html)

        assert metrics.remote_css


class TestTextMetrics:
    """Test text metrics extraction."""

    def test_text_metrics_basic(self):
        """Test basic text metrics extraction."""
        text = "Hello World"

        metrics = extract_text_metrics(text)

        assert metrics.length == len(text)
        assert metrics.emoji_count == 0
        # "Hello World" has 2 uppercase letters out of 11 characters
        assert abs(metrics.shouting_ratio - (2 / 11)) < 0.01

    def test_text_metrics_shouting(self):
        """Test shouting ratio calculation."""
        text = "HELLO WORLD"

        metrics = extract_text_metrics(text)

        # "HELLO WORLD" has 10 uppercase letters out of 11 characters
        assert abs(metrics.shouting_ratio - (10 / 11)) < 0.01

    def test_text_metrics_mixed_case(self):
        """Test shouting ratio with mixed case."""
        text = "Hello World"

        metrics = extract_text_metrics(text)

        # "Hello World" has 2 uppercase letters out of 11 characters
        assert abs(metrics.shouting_ratio - (2 / 11)) < 0.01

    def test_text_metrics_emoji(self):
        """Test emoji counting."""
        text = "Hello 😀 World 🌟"

        metrics = extract_text_metrics(text)

        assert metrics.emoji_count == 2

    def test_text_metrics_language_detection(self):
        """Test language detection."""
        english_text = "The quick brown fox jumps over the lazy dog"
        spanish_text = "El zorro marrón rápido salta sobre el perro perezoso"

        english_metrics = extract_text_metrics(english_text)
        spanish_metrics = extract_text_metrics(spanish_text)

        assert english_metrics.language == "en"
        assert spanish_metrics.language == "es"


class TestEmlToPartsIntegration:
    """Test integration of new metrics in eml_to_parts."""

    def test_eml_to_parts_includes_new_fields(self):
        """Test that eml_to_parts includes all new fields."""
        raw_email = """From: test@example.com
To: recipient@example.com
Subject: Test Email
Content-Type: text/plain

Hello World
"""
        parser = BytesParser(policy=policy.default)
        msg = parser.parsebytes(raw_email.encode("utf-8"))

        result = eml_to_parts(msg)

        # Check that all required fields are present
        assert "mime_parts" in result
        assert "html_metrics" in result
        assert "text_metrics" in result
        assert "attachments" in result

        # Check structure of new fields
        assert isinstance(result["mime_parts"], list)
        assert isinstance(result["html_metrics"], dict)
        assert isinstance(result["text_metrics"], dict)
        assert isinstance(result["attachments"], list)

        # Check that mime_parts has expected structure
        if result["mime_parts"]:
            part = result["mime_parts"][0]
            assert "content_type" in part
            assert "size" in part
            assert "hash" in part

        # Check that metrics have expected fields
        assert "length" in result["html_metrics"]
        assert "link_count" in result["html_metrics"]
        assert "image_count" in result["html_metrics"]

        assert "length" in result["text_metrics"]
        assert "emoji_count" in result["text_metrics"]
        assert "shouting_ratio" in result["text_metrics"]

    def test_eml_to_parts_attachments_populated(self):
        """Test that attachments are properly populated."""
        raw_email = """From: test@example.com
To: recipient@example.com
Subject: Test Email
Content-Type: multipart/mixed; boundary="boundary"

--boundary
Content-Type: text/plain

Hello World

--boundary
Content-Type: application/pdf
Content-Disposition: attachment; filename="test.pdf"

PDF content

--boundary--
"""
        parser = BytesParser(policy=policy.default)
        msg = parser.parsebytes(raw_email.encode("utf-8"))

        result = eml_to_parts(msg)

        # Should have at least one attachment
        assert len(result["attachments"]) >= 1

        # Check attachment structure
        attachment = result["attachments"][0]
        assert "filename" in attachment
        assert "content_type" in attachment
        assert "filesize" in attachment
