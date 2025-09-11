import pytest

from backend.utils.text import (
    clean_html_body,
    clean_text_body,
    get_cleaned_body_html,
    get_cleaned_body_text,
    strip_html_tags,
)


class TestCleanTextBody:
    """Test text body cleaning functionality."""

    def test_clean_text_body_empty(self):
        """Test cleaning empty text."""
        assert clean_text_body("") == ""

    def test_clean_text_body_whitespace(self):
        """Test cleaning text with excessive whitespace."""
        text = "  Hello   world  \n\n\n  Test  "
        expected = "Hello world\n\nTest"
        assert clean_text_body(text) == expected

    def test_clean_text_body_line_endings(self):
        """Test normalizing line endings."""
        text = "Line 1\r\nLine 2\rLine 3\n"
        expected = "Line 1\nLine 2\nLine 3"
        assert clean_text_body(text) == expected

    def test_clean_text_body_control_chars(self):
        """Test removing control characters."""
        text = "Hello\x00world\x01test"
        expected = "Helloworldtest"
        assert clean_text_body(text) == expected

    def test_clean_text_body_multiple_spaces(self):
        """Test normalizing multiple spaces."""
        text = "Hello    world   test"
        expected = "Hello world test"
        assert clean_text_body(text) == expected

    def test_clean_text_body_normal_text(self):
        """Test cleaning normal text (should remain unchanged)."""
        text = "This is a normal message."
        assert clean_text_body(text) == text


class TestCleanHtmlBody:
    """Test HTML body cleaning functionality."""

    def test_clean_html_body_empty(self):
        """Test cleaning empty HTML."""
        assert clean_html_body("") == ""

    def test_clean_html_body_script_removal(self):
        """Test removing script tags."""
        html = '<html><script>alert("hack")</script><p>Safe content</p></html>'
        expected = "<html><p>Safe content</p></html>"
        assert clean_html_body(html) == expected

    def test_clean_html_body_style_removal(self):
        """Test removing style tags."""
        html = "<html><style>body { color: red; }</style><p>Safe content</p></html>"
        expected = "<html><p>Safe content</p></html>"
        assert clean_html_body(html) == expected

    def test_clean_html_body_event_handlers(self):
        """Test removing event handlers."""
        html = '<a href="#" onclick="alert(\'hack\')">Link</a>'
        expected = '<a href="#">Link</a>'
        assert clean_html_body(html) == expected

    def test_clean_html_body_javascript_urls(self):
        """Test removing javascript URLs."""
        html = "<a href=\"javascript:alert('hack')\">Link</a>"
        expected = '<a href="#">Link</a>'
        assert clean_html_body(html) == expected

    def test_clean_html_body_data_urls(self):
        """Test removing data URLs."""
        html = '<img src="data:image/png;base64,kjhFCGHJKNEGIFYUcwgiufguiwi456kghjn3c4g==">'
        expected = '<img src="#">'
        assert clean_html_body(html) == expected

    def test_clean_html_body_dangerous_attributes(self):
        """Test removing dangerous attributes."""
        html = '<input type="text" autofocus onfocus="alert(\'hack\')" formaction="evil.com">'
        result = clean_html_body(html)
        assert "autofocus" not in result
        assert "onfocus" not in result
        assert "formaction" not in result

    def test_clean_html_body_comments(self):
        """Test removing HTML comments."""
        html = "<p>Content</p><!-- This is a comment --><p>More content</p>"
        expected = "<p>Content</p><p>More content</p>"
        assert clean_html_body(html) == expected

    def test_clean_html_body_whitespace_normalization(self):
        """Test that whitespace is preserved to maintain content integrity."""
        html = "<p>  Content  </p>   <p>  More  </p>"
        # Whitespace normalization is disabled to preserve original formatting
        # and prevent corruption of text content like "HTML formatting"
        expected = "<p>  Content  </p>   <p>  More  </p>"
        assert clean_html_body(html) == expected

    def test_clean_html_body_safe_content(self):
        """Test that safe HTML content is preserved."""
        html = '<html><head><title>Test</title></head><body><h1>Title</h1><p>Paragraph</p><a href="http://safe.com">Link</a></body></html>'
        result = clean_html_body(html)
        assert "<h1>Title</h1>" in result
        assert "<p>Paragraph</p>" in result
        assert 'href="http://safe.com"' in result


class TestGetCleanedBodyFunctions:
    """Test the safe wrapper functions."""

    def test_get_cleaned_body_text_success(self):
        """Test successful text cleaning."""
        text = "  Test   text  "
        expected = "Test text"
        assert get_cleaned_body_text(text) == expected

    def test_get_cleaned_body_text_exception(self):
        """Test exception handling in text cleaning."""
        # This should not raise an exception
        result = get_cleaned_body_text(None)
        assert result == ""

    def test_get_cleaned_body_html_success(self):
        """Test successful HTML cleaning."""
        html = '<script>alert("hack")</script><p>Safe</p>'
        expected = "<p>Safe</p>"
        assert get_cleaned_body_html(html) == expected

    def test_get_cleaned_body_html_exception(self):
        """Test exception handling in HTML cleaning."""
        # This should not raise an exception
        result = get_cleaned_body_html(None)
        assert result == ""


class TestStripHtmlTags:
    """Test HTML tag stripping functionality."""

    def test_strip_html_tags_empty(self):
        """Test stripping tags from empty string."""
        assert strip_html_tags("") == ""

    def test_strip_html_tags_simple(self):
        """Test stripping simple HTML tags."""
        html = "<p>Hello <strong>world</strong></p>"
        expected = "Hello world"
        assert strip_html_tags(html) == expected

    def test_strip_html_tags_complex(self):
        """Test stripping complex HTML."""
        html = '<html><body><h1>Title</h1><p>Paragraph with <a href="#">link</a></p></body></html>'
        expected = "TitleParagraph with link"
        assert strip_html_tags(html) == expected

    def test_strip_html_tags_entities(self):
        """Test handling HTML entities."""
        html = "<p>Tom & Jerry's</p>"
        expected = "Tom & Jerry's"
        assert strip_html_tags(html) == expected

    def test_strip_html_tags_script(self):
        """Test that script content is also stripped."""
        html = '<p>Content</p><script>alert("hack")</script><p>More</p>'
        expected = "ContentMore"
        assert strip_html_tags(html) == expected

    def test_strip_html_tags_with_attributes(self):
        """Test stripping tags with attributes."""
        html = '<a href="http://example.com" class="link">Link text</a>'
        expected = "Link text"
        assert strip_html_tags(html) == expected


class TestInvisibleCharacterStripping:
    """Test invisible and special character stripping."""

    def test_clean_text_body_invisible_chars(self):
        """Test stripping zero-width and invisible Unicode characters."""
        text = "Hello\u200bworld\u200etest\ufeff"
        expected = "Helloworldtest"
        assert clean_text_body(text) == expected

    def test_clean_text_body_special_spaces(self):
        """Test normalizing special Unicode spaces."""
        text = "Hello\u00a0world\u2000test\u3000"
        expected = "Hello world test"
        assert clean_text_body(text) == expected

    def test_clean_text_body_figure_spaces(self):
        """Test handling figure spaces and other special spaces."""
        text = "Price:\u2007$100\u2008and\u2009more"
        expected = "Price: $100 and more"
        assert clean_text_body(text) == expected

    def test_clean_text_body_bidi_controls(self):
        """Test removing bidirectional control characters."""
        text = "Hello\u202aworld\u202btest\u200f"
        expected = "Helloworldtest"
        assert clean_text_body(text) == expected
