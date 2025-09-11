from typing import Optional, List, Dict, Any
from datetime import datetime
import re
import os
import base64
from dataclasses import asdict
from email.message import EmailMessage
from urllib.parse import urlparse
from backend.ingestion.mime import MultiPartParser
from backend.ingestion.headers import HeaderNormalizer, get_date
from backend.ingestion.addresses import AddressUtils
from backend.utils.models import (
    Attachment,
    WhitelistHit,
    InlineImage,
    RoutingHop,
    RoutingData,
    RoutingVerdict,
)
from backend.utils.text import get_cleaned_body_text, get_cleaned_body_html
from backend.utils.metrics import extract_html_metrics, extract_text_metrics
from backend.core.attachments import AttachmentAnalyzer
from backend.core.whitelist import check_whitelist_hit, load_whitelist


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

    # Analyze attachments for security findings
    attachment_findings = AttachmentAnalyzer.analyze_attachments(attachments)

    # Extract routing data
    routing_data = extract_routing_data(msg)

    # Analyze routing verdict
    routing_verdict = analyze_routing_verdict(routing_data)

    # Extract domains and check whitelist
    wl = load_whitelist()
    whitelist_hit = []
    all_content = subject + "\n" + text + "\n" + html
    domains = extract_domains(all_content)
    for domain in domains:
        hits = check_whitelist_hit(domain, wl)
        if hits:
            whitelist_hit.extend(hits)

    return {
        "subject": subject,
        "body": text,  # Alias for text_body for backward compatibility
        "html": html,  # Alias for html_body for backward compatibility
        "text_body": text,  # Plain text body for keyword analysis
        "html_body": html,  # HTML body for completeness
        "mime_parts": [asdict(part) for part in mime_parts],
        "html_metrics": asdict(html_metrics),
        "text_metrics": asdict(text_metrics),
        "attachments": [asdict(att) for att in attachments],
        "attachment_findings": [asdict(finding) for finding in attachment_findings],
        "routing_data": asdict(routing_data),
        "routing_verdict": asdict(routing_verdict),
        "whitelist_hit": [asdict(hit) for hit in whitelist_hit],
        "headers": header_normalizer.get_all_headers(),  # Extract headers
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


def analyze_routing_verdict(routing_data: RoutingData) -> RoutingVerdict:
    """
    Analyze routing data and create a condensed verdict.

    Args:
        routing_data: Parsed routing information

    Returns:
        RoutingVerdict with analysis results
    """
    findings_parts = []
    evidence_parts = []
    helo_domain = None
    helo_ip_mismatch = False
    suspicious_hop = False

    # Basic received chain count
    received_chain_count = len(routing_data.received)

    # Analyze first hop for HELO information
    if routing_data.received:
        first_received = routing_data.received[0]

        # Extract HELO hostname and IP
        helo_match = re.search(r"from\s+([^\s(\[]+)", first_received, re.IGNORECASE)
        if helo_match:
            helo_hostname = helo_match.group(1).strip("()")
            helo_domain = helo_hostname
            evidence_parts.append(f"HELO/EHLO hostname: {helo_hostname}")

            # Check for IP in square brackets
            ip_match = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", first_received)
            if ip_match:
                helo_ip = ip_match.group(1)
                # Check for IP mismatch (simplified - could be expanded with DNS resolution)
                if helo_hostname != helo_ip:
                    helo_ip_mismatch = True
                    evidence_parts.append(
                        f"HELO IP {helo_ip} may not match hostname {helo_hostname}"
                    )

    # Check for suspicious hops
    for i, hop in enumerate(routing_data.hops):
        # Check for private IPs in external positions
        if hop.from_:
            private_ip_match = re.match(
                r"(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+)",
                hop.from_,
            )
            if private_ip_match and i > 0:  # Private IP not in first hop
                suspicious_hop = True
                evidence_parts.append(
                    f"Private IP {hop.from_} found in routing hop {i+1}"
                )

        # Check for malformed entries
        if (
            (not hop.by and not hop.from_)
            or (hop.by and not hop.from_)
            or (hop.from_ and not hop.by)
        ):
            suspicious_hop = True
            if not hop.by and not hop.from_:
                evidence_parts.append(
                    f"Malformed routing hop {i+1}: missing from and by fields"
                )
            elif not hop.from_:
                evidence_parts.append(
                    f"Malformed routing hop {i+1}: missing from field"
                )
            elif not hop.by:
                evidence_parts.append(f"Malformed routing hop {i+1}: missing by field")

        # Check for missing timestamp
        if not hop.timestamp:
            suspicious_hop = True
            evidence_parts.append(f"Routing hop {i+1} missing timestamp")

    # Build condensed findings
    if received_chain_count == 0:
        findings_parts.append("No routing information present - may be a sent email")
    elif received_chain_count == 1:
        findings_parts.append("Minimal routing - direct delivery")
    elif received_chain_count <= 3:
        findings_parts.append("Normal routing chain length")
    else:
        findings_parts.append(
            "Extended routing chain - may indicate forwarding or complex delivery path"
        )

    if helo_ip_mismatch:
        findings_parts.append("HELO hostname/IP mismatch detected")

    if suspicious_hop:
        findings_parts.append("Suspicious routing patterns detected")
    else:
        findings_parts.append("No obvious routing anomalies")

    routing_findings = "; ".join(findings_parts)
    evidence = (
        "; ".join(evidence_parts) if evidence_parts else "Standard routing analysis"
    )

    return RoutingVerdict(
        routing_findings=routing_findings,
        helo_domain=helo_domain,
        helo_ip_mismatch=helo_ip_mismatch,
        received_chain_count=received_chain_count,
        suspicious_hop=suspicious_hop,
        evidence=evidence,
    )


# Pre-compile regex for CID replacement
CID_PATTERN = re.compile(r'src=["\']cid:([^"\']+)["\']', re.IGNORECASE)


def check_whitelist_hit(
    domain: str, wl: set[str], reason: str = "manual-whitelist"
) -> Optional[list]:
    """
    Check if domain is whitelisted and return hit details.

    Args:
        domain: Domain to check
        wl: Whitelist set
        reason: Reason for whitelist hit

    Returns:
        WhitelistHit if matched, None otherwise
    """
    from backend.core.whitelist import check_whitelist_hit as orig_check

    return orig_check(domain, wl, reason)


def extract_domains(text: str) -> set[str]:
    """
    Extract domains from URLs in text.

    Args:
        text: Input text containing URLs

    Returns:
        Set of unique domains in lowercase
    """
    if not text:
        return set()

    # Pre-compile regex for efficiency
    URL_PATTERN = re.compile(r"https?://[^\s]+")
    domains = set()
    urls = URL_PATTERN.findall(text)
    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain:
                domains.add(domain)
        except Exception:
            # Skip malformed URLs
            continue
    return domains


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
