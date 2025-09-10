from typing import Optional, List, Dict, Any
from datetime import datetime
import re
import os
import base64
from dataclasses import asdict
from email.message import EmailMessage
from email import policy
from email.parser import BytesParser
from .mime import MultiPartParser
from .headers import HeaderNormalizer, get_date
from .addresses import AddressUtils
from .models import (
    Attachment,
    InlineImage,
    MimePart,
    HtmlMetrics,
    TextMetrics,
    RoutingHop,
    RoutingData,
)
from .body_cleaner import get_cleaned_body_text, get_cleaned_body_html
from .auth_parser import get_auth_data
from .metrics import extract_html_metrics, extract_text_metrics


class EmlReader:
    """
    Integrated EML reader that takes raw bytes and provides access to all email components.
    """

    def __init__(self, raw_eml_bytes: bytes):
        self.__multipart_parser = MultiPartParser(raw_eml_bytes)
        self._header_normalizer = HeaderNormalizer(self.__multipart_parser.message)
        self._address_utils = AddressUtils(self.__multipart_parser.message)

    @property
    def _multipart_parser(self) -> MultiPartParser:
        """Expose the underlying MultiPartParser for advanced usage."""
        return self.__multipart_parser

    # Header access methods
    def get_header(self, key: str, case_insensitive: bool = True) -> Optional[str]:
        """Get header value with case-insensitive access."""
        return self._header_normalizer.get_header(key, case_insensitive)

    def get_subject(self) -> Optional[str]:
        """Get the Subject header."""
        return self.get_header("Subject")

    def get_date(self) -> Optional[datetime]:
        """Get the Date header parsed to datetime."""
        date_str = self.get_header("Date")
        if date_str:
            return get_date(date_str)
        return None

    def get_type(self) -> str:
        """Get email type: 'sent' if no Received header, 'received' if Received header present."""
        received_headers = self.get_multi_value_header("Received")
        return "received" if received_headers else "sent"

    def get_all_headers(self) -> Dict[str, str]:
        """Get all headers normalized."""
        return self._header_normalizer.get_all_headers()

    def get_multi_value_header(self, key: str) -> List[str]:
        """Get multi-value headers like Received."""
        return self._header_normalizer.get_multi_value_header(key)

    # Address helpers
    def get_from(self) -> Optional[str]:
        """Get raw From header."""
        return self._address_utils.get_from()

    def get_to(self) -> Optional[str]:
        """Get raw To header."""
        return self._address_utils.get_to()

    def get_cc(self) -> Optional[str]:
        """Get raw Cc header."""
        return self._address_utils.get_cc()

    def get_bcc(self) -> Optional[str]:
        """Get raw Bcc header."""
        return self._address_utils.get_bcc()

    def get_reply_to(self) -> Optional[str]:
        """Get raw Reply-To header."""
        return self._address_utils.get_reply_to()

    def get_from_emails(self) -> List[str]:
        """Get list of email addresses from From header."""
        return self._address_utils.get_from_emails()

    def get_to_emails(self) -> List[str]:
        """Get list of email addresses from To header."""
        return self._address_utils.get_to_emails()

    def get_cc_emails(self) -> List[str]:
        """Get list of email addresses from Cc header."""
        return self._address_utils.get_cc_emails()

    def get_bcc_emails(self) -> List[str]:
        """Get list of email addresses from Bcc header."""
        return self._address_utils.get_bcc_emails()

    def get_reply_to_emails(self) -> List[str]:
        """Get list of email addresses from Reply-To header."""
        return self._address_utils.get_reply_to_emails()

    def get_from_names(self) -> List[str]:
        """Get list of names from From header."""
        return self._address_utils.get_from_names()

    def get_to_names(self) -> List[str]:
        """Get list of names from To header."""
        return self._address_utils.get_to_names()

    def get_cc_names(self) -> List[str]:
        """Get list of names from Cc header."""
        return self._address_utils.get_cc_names()

    def get_bcc_names(self) -> List[str]:
        """Get list of names from Bcc header."""
        return self._address_utils.get_bcc_names()

    def get_reply_to_names(self) -> List[str]:
        """Get list of names from Reply-To header."""
        return self._address_utils.get_reply_to_names()

    def get_from_parsed(self) -> Optional[tuple[str, str]]:
        """Get parsed From header as (name, email) tuple."""
        return self._address_utils.get_from_parsed()

    def get_to_parsed(self) -> List[tuple[str, str]]:
        """Get parsed To header as list of (name, email) tuples."""
        return self._address_utils.get_to_parsed()

    def get_cc_parsed(self) -> List[tuple[str, str]]:
        """Get parsed Cc header as list of (name, email) tuples."""
        return self._address_utils.get_cc_parsed()

    def get_bcc_parsed(self) -> List[tuple[str, str]]:
        """Get parsed Bcc header as list of (name, email) tuples."""
        return self._address_utils.get_bcc_parsed()

    def get_reply_to_parsed(self) -> Optional[tuple[str, str]]:
        """Get parsed Reply-To header as (name, email) tuple."""
        return self._address_utils.get_reply_to_parsed()

    # Body methods
    def get_body_text(self) -> str:
        """Get the best text body content."""
        return get_message_text(self._multipart_parser.message)

    def get_body_html(self) -> str:
        """Get the best HTML body content."""
        return get_message_html(self._multipart_parser.message)

    def get_message_text(self) -> str:
        """Get the best text body content (alias for get_body_text)."""
        return self.get_body_text()

    def get_message_html(self) -> str:
        """Get the best HTML body content (alias for get_body_html)."""
        return self.get_body_html()

    def get_body_html_with_inline_images(
        self, save_images_to: Optional[str] = None, use_data_urls: bool = False
    ) -> str:
        """Get HTML body with inline images rewritten."""
        html = self.get_body_html()
        inline_images = self.get_inline_images()
        return get_message_html_with_inline_images(
            html, inline_images, save_images_to, use_data_urls
        )

    # Attachment and inline image methods
    def get_attachments(self) -> List[Attachment]:
        """Get list of attachments."""
        return self._multipart_parser.get_attachments()

    def get_inline_images(self) -> List[InlineImage]:
        """Get list of inline images."""
        return self._multipart_parser.get_inline_images()


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
    text = get_message_text(msg)
    html = get_message_html(msg)

    # Extract subscription metadata
    header_normalizer = HeaderNormalizer(msg)

    # Create multipart parser for MIME analysis
    parser = MultiPartParser(message=msg)

    # Extract MIME parts metadata
    mime_parts = parser.get_all_mime_parts()

    # Extract HTML metrics
    html_metrics = extract_html_metrics(html, subject)

    # Extract text metrics
    text_metrics = extract_text_metrics(text)

    # Get attachments (ensure it's always a list, even if empty)
    attachments = parser.get_attachments()

    # Extract routing data
    routing_data = extract_routing_data(msg)

    return {
        "mime_parts": [asdict(part) for part in mime_parts],
        "html_metrics": asdict(html_metrics),
        "text_metrics": asdict(text_metrics),
        "attachments": [asdict(att) for att in attachments],
        "routing_data": asdict(routing_data),
    }


def get_message_text(msg: EmailMessage) -> str:
    """
    Extract the best candidate text content from the MIME tree.
    Prefers multipart/alternative > text/plain, with charset & CTE decoding.
    """
    return _find_best_text(msg)


def get_message_html(msg: EmailMessage) -> str:
    """
    Extract the best candidate HTML content from the MIME tree.
    Prefers text/html in alternative or related parts, with charset & CTE decoding.
    """
    return _find_best_html(msg)


def _find_best_text(msg: EmailMessage) -> str:
    """
    Recursively find the best text/plain part.
    For multipart/alternative, prefer text/plain over text/html.
    Applies cleaning to the extracted content.
    """
    if not msg.is_multipart():
        ctype = (msg.get_content_type() or "").lower()
        if ctype == "text/plain":
            try:
                raw_content = msg.get_content() or ""
                return get_cleaned_body_text(raw_content)
            except (AttributeError, TypeError):
                return ""
        return ""

    subtype = (msg.get_content_subtype() or "").lower()
    if subtype == "alternative":
        # In alternative, prefer text/plain
        for part in msg.get_payload():
            if isinstance(part, EmailMessage):
                ctype = (part.get_content_type() or "").lower()
                if ctype == "text/plain":
                    try:
                        raw_content = part.get_content() or ""
                        return get_cleaned_body_text(raw_content)
                    except (AttributeError, TypeError):
                        return ""
        # If no text/plain, fall back to first text part
        for part in msg.get_payload():
            if isinstance(part, EmailMessage):
                ctype = (part.get_content_type() or "").lower()
                if ctype.startswith("text/"):
                    try:
                        raw_content = part.get_content() or ""
                        return get_cleaned_body_text(raw_content)
                    except (AttributeError, TypeError):
                        return ""

    # For other multiparts, recurse and concatenate
    texts = []
    for part in msg.get_payload():
        if isinstance(part, EmailMessage):
            text = _find_best_text(part)
            if text:
                texts.append(text)
    combined_text = "\n\n".join(texts)
    return get_cleaned_body_text(combined_text)


def _find_best_html(msg: EmailMessage) -> str:
    """
    Recursively find the best text/html part.
    Prefers text/html in any multipart.
    Applies cleaning to the extracted content.
    """
    if not msg.is_multipart():
        ctype = (msg.get_content_type() or "").lower()
        if ctype == "text/html":
            try:
                raw_content = msg.get_content() or ""
                return get_cleaned_body_html(raw_content)
            except (AttributeError, TypeError):
                return ""
        return ""

    # For any multipart, look for text/html
    for part in msg.get_payload():
        if isinstance(part, EmailMessage):
            html = _find_best_html(part)
            if html:
                return html  # Return first found HTML

    return ""


def parse_received_header(received_line: str) -> RoutingHop:
    """
    Parse a Received header line into a RoutingHop object.
    Example: "from mail.example.com (mail.example.com [192.168.1.1]) by mx.example.com (Postfix) with ESMTP id ABC123 for <user@example.com>; Mon, 01 Jan 2024 12:00:00 +0000 (UTC)"
    """
    hop = RoutingHop()

    # Extract timestamp - usually at the end after semicolon
    timestamp_match = re.search(r";\s*(.+?)\s*$", received_line)
    if timestamp_match:
        hop.timestamp = timestamp_match.group(1).strip()

    # Extract 'by' - the receiving server
    by_match = re.search(r"\sby\s+([^\s()]+)", received_line, re.IGNORECASE)
    if by_match:
        hop.by = by_match.group(1).strip("()")

    # Extract 'from' - the sending server
    from_match = re.search(r"\sfrom\s+([^\s()]+)", received_line, re.IGNORECASE)
    if from_match:
        hop.from_ = from_match.group(1).strip("()")

    # Extract 'with' - the protocol used
    with_match = re.search(r"\swith\s+([^\s;()]+)", received_line, re.IGNORECASE)
    if with_match:
        hop.with_ = with_match.group(1).strip("()")

    return hop


def extract_routing_data(msg: EmailMessage) -> RoutingData:
    """
    Extract all routing-related headers from the email message.
    """
    header_normalizer = HeaderNormalizer(msg)

    # Get Received headers (can be multiple)
    received = header_normalizer.get_multi_value_header("Received")

    # Parse received headers into hops
    hops = [parse_received_header(line) for line in received]

    # Get other routing headers
    x_received = header_normalizer.get_multi_value_header("X-Received")

    x_original_to = header_normalizer.get_header("X-Original-To")
    delivered_to = header_normalizer.get_header("Delivered-To")

    return RoutingData(
        received=received,
        hops=hops,
        x_received=x_received,
        x_original_to=x_original_to,
        delivered_to=delivered_to,
    )


# Pre-compile regex for CID replacement
CID_PATTERN = re.compile(r'src=["\']cid:([^"\']+)["\']', re.IGNORECASE)


def get_message_html_with_inline_images(
    html_body: str,
    inline_images: List[InlineImage],
    save_images_to: Optional[str] = None,
    use_data_urls: bool = False,
) -> str:
    """
    Replace src="cid:XYZ" in HTML with file paths or data: URLs for inline images.

    Args:
        html_body: The HTML content string.
        inline_images: List of InlineImage objects.
        save_images_to: Directory path to save images to. If provided, replaces with file paths.
        use_data_urls: If True, replaces with data: URLs instead of file paths.

    Returns:
        Modified HTML string with rewritten image sources.
    """
    if not html_body or not inline_images:
        return html_body

    # Create a mapping from content_id to InlineImage
    cid_to_image = {img.content_id: img for img in inline_images if img.content_id}

    def replace_cid(match):
        cid = match.group(1).strip("<>")
        if cid in cid_to_image:
            img = cid_to_image[cid]
            if use_data_urls:
                # Create data URL
                try:
                    encoded = base64.b64encode(img.content).decode("ascii")
                    return f"data:{img.content_type};base64,{encoded}"
                except (AttributeError, UnicodeDecodeError):
                    return match.group(0)
            elif save_images_to:
                # Save to file and return path
                try:
                    os.makedirs(save_images_to, exist_ok=True)
                    ext = (
                        img.content_type.split("/")[-1]
                        if "/" in img.content_type
                        else "png"
                    )
                    filename = img.filename or f"{cid}.{ext}"
                    filepath = os.path.join(save_images_to, filename)
                    with open(filepath, "wb") as f:
                        f.write(img.content)
                    # Convert to URL-friendly path (forward slashes)
                    return filepath.replace("\\", "/")
                except (OSError, AttributeError):
                    return match.group(0)
            else:
                # No replacement, return original
                return match.group(0)
        return match.group(0)

    return CID_PATTERN.sub(replace_cid, html_body)
