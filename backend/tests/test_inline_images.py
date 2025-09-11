import pytest
from backend.ingestion.mime import MultiPartParser
from backend.ingestion.parse_eml import get_message_html_with_inline_images
from backend.utils.models import InlineImage
from email.message import EmailMessage
from email import policy
from email.parser import BytesParser
from email.generator import BytesGenerator
from io import BytesIO


def test_multipart_parser_inline_image():
    """Test MultiPartParser with inline image."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Subject"
    msg.make_mixed()  # Make it multipart

    # Add inline image
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
    parts = parser.get_multi_parts()
    assert len(parts) == 1
    assert parts[0].is_inline_image is True
    assert parts[0].get_filename() == "image.png"
    assert parts[0].get_content_id() == "image1@example.com"


def test_get_inline_images():
    """Test get_inline_images."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Subject"
    msg.make_mixed()

    # Add inline image
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
    images = parser.get_inline_images()
    assert len(images) == 1
    assert images[0].filename == "image.png"
    assert images[0].content_type == "image/png"
    assert images[0].content == b"image data"
    assert images[0].filesize == len(b"image data")
    assert images[0].content_id == "image1@example.com"
    assert images[0].content_disposition == 'inline; filename="image.png"'


def test_get_inline_images_no_cid():
    """Test get_inline_images excludes images without Content-ID."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Subject"
    msg.make_mixed()

    # Add image without CID
    image = EmailMessage()
    image.set_content(b"image data", maintype="image", subtype="png")
    image.add_header("Content-Disposition", "inline", filename="image.png")
    msg.attach(image)

    # Serialize to bytes
    fp = BytesIO()
    g = BytesGenerator(fp, policy=policy.default)
    g.flatten(msg)
    raw_eml = fp.getvalue()

    parser = MultiPartParser(raw_eml)
    images = parser.get_inline_images()
    assert len(images) == 0  # Should be excluded as no CID


def test_get_message_html_with_inline_images_data_urls():
    """Test rewriting HTML with inline images to data URLs."""
    html = '<img src="cid:image1"> <img src="cid:image2">'
    inline_images = [
        InlineImage(
            filename="test1.png",
            content_type="image/png",
            content=b"fake png data",
            filesize=14,
            content_id="image1",
        ),
        InlineImage(
            filename="test2.jpg",
            content_type="image/jpeg",
            content=b"fake jpg data",
            filesize=14,
            content_id="image2",
        ),
    ]

    result = get_message_html_with_inline_images(
        html, inline_images, use_data_urls=True
    )

    # Check that CIDs are replaced with data URLs
    assert "data:image/png;base64," in result
    assert "data:image/jpeg;base64," in result
    assert "cid:image1" not in result
    assert "cid:image2" not in result


def test_get_message_html_with_inline_images_file_paths(tmp_path):
    """Test rewriting HTML with inline images to file paths."""
    html = '<img src="cid:image1">'
    inline_images = [
        InlineImage(
            filename="test1.png",
            content_type="image/png",
            content=b"fake png data",
            filesize=14,
            content_id="image1",
        ),
    ]

    save_dir = str(tmp_path / "images")
    result = get_message_html_with_inline_images(
        html, inline_images, save_images_to=save_dir
    )

    # Check that file was created
    assert (tmp_path / "images" / "test1.png").exists()

    # Check that CID is replaced with file path (converted to forward slashes)
    expected_path = save_dir.replace("\\", "/") + "/test1.png"
    assert expected_path in result
    assert "cid:image1" not in result


def test_get_message_html_with_inline_images_no_replacement():
    """Test that HTML is unchanged when no save_images_to or use_data_urls."""
    html = '<img src="cid:image1">'
    inline_images = [
        InlineImage(
            filename="test1.png",
            content_type="image/png",
            content=b"fake png data",
            filesize=14,
            content_id="image1",
        ),
    ]

    result = get_message_html_with_inline_images(html, inline_images)

    # Should remain unchanged
    assert result == html


def test_get_message_html_with_inline_images_missing_cid():
    """Test handling of CIDs not in inline_images list."""
    html = '<img src="cid:image1"> <img src="cid:image2">'
    inline_images = [
        InlineImage(
            filename="test1.png",
            content_type="image/png",
            content=b"fake png data",
            filesize=14,
            content_id="image1",
        ),
    ]

    result = get_message_html_with_inline_images(
        html, inline_images, use_data_urls=True
    )

    # image1 should be replaced, image2 should remain
    assert "data:image/png;base64," in result
    assert "cid:image2" in result
