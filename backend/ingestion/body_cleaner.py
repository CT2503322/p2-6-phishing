"""
Body cleaning utilities for EML processing.

This module provides functions to clean and sanitize both text and HTML body content
from email messages, removing potentially harmful elements and normalizing content.
"""

import re
from typing import Optional
from html import escape as html_escape


def clean_text_body(text: str) -> str:
    """
    Clean and normalize text body content.

    Args:
        text: Raw text content from email body

    Returns:
        Cleaned and normalized text content
    """
    if not text:
        return ""

    # Remove excessive whitespace and normalize line endings
    text = re.sub(r"\r\n", "\n", text)  # Normalize Windows line endings
    text = re.sub(r"\r", "\n", text)  # Normalize Mac line endings

    # Remove control characters except for common whitespace
    text = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", text)

    # Replace non-breaking and special Unicode spaces with regular space
    text = text.replace("\u00a0", " ")  # NBSP -> space
    text = re.sub(r"[\u2000-\u200A\u202F\u205F\u3000]", " ", text)

    # Remove zero-width and bidi control characters
    text = re.sub(
        r"[\u200B-\u200D\u2060\uFEFF\u034F\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]",
        "",
        text,
    )

    # Normalize multiple spaces to single space (but preserve single spaces)
    text = re.sub(r" +", " ", text)

    # Normalize multiple newlines to maximum of 2
    text = re.sub(r"\n{3,}", "\n\n", text)

    # Strip leading/trailing whitespace from each line
    lines = text.split("\n")
    lines = [line.strip() for line in lines]
    text = "\n".join(lines)

    # Strip leading/trailing whitespace from entire text
    text = text.strip()

    return text


def clean_html_body(html: str) -> str:
    """
    Clean and sanitize HTML body content.

    Removes potentially harmful elements like scripts, event handlers,
    and dangerous attributes while preserving basic formatting.

    Args:
        html: Raw HTML content from email body

    Returns:
        Cleaned and sanitized HTML content
    """
    if not html:
        return ""

    # Remove script tags and their content
    html = re.sub(
        r"<script[^>]*>.*?</script>", "", html, flags=re.IGNORECASE | re.DOTALL
    )

    # Remove style tags and their content
    html = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.IGNORECASE | re.DOTALL)

    # Remove event handlers (onclick, onload, etc.)
    html = re.sub(r'\s+on\w+="[^"]*"', "", html, flags=re.IGNORECASE)
    html = re.sub(r"\s+on\w+='[^']*'", "", html, flags=re.IGNORECASE)

    # Remove javascript: and data: URLs from href/src attributes
    html = re.sub(
        r'href="[^"]*javascript:[^"]*"',
        'href="#"',
        html,
        flags=re.IGNORECASE,
    )
    html = re.sub(
        r"href='[^']*javascript:[^']*'",
        "href='#'",
        html,
        flags=re.IGNORECASE,
    )
    html = re.sub(
        r'src="[^"]*javascript:[^"]*"',
        'src="#"',
        html,
        flags=re.IGNORECASE,
    )
    html = re.sub(
        r"src='[^']*javascript:[^']*'",
        "src='#'",
        html,
        flags=re.IGNORECASE,
    )
    html = re.sub(
        r'href="[^"]*data:[^"]*"',
        'href="#"',
        html,
        flags=re.IGNORECASE,
    )
    html = re.sub(
        r"href='[^']*data:[^']*'",
        "href='#'",
        html,
        flags=re.IGNORECASE,
    )
    html = re.sub(
        r'src="[^"]*data:[^"]*"',
        'src="#"',
        html,
        flags=re.IGNORECASE,
    )
    html = re.sub(
        r"src='[^']*data:[^']*'",
        "src='#'",
        html,
        flags=re.IGNORECASE,
    )

    # Remove potentially dangerous attributes
    dangerous_attrs = [
        "formaction",
        "form",
        "formenctype",
        "formmethod",
        "formnovalidate",
        "formtarget",
        "autofocus",
        "autoplay",
        "loop",
        "controls",
        "muted",
    ]

    for attr in dangerous_attrs:
        # Only match when it's an actual HTML attribute, not part of text content
        html = re.sub(
            rf'(\s){attr}(=["\'][^"\']*["\'])?(?=\s|>)',
            r"\1",
            html,
            flags=re.IGNORECASE,
        )

    # Remove comments
    html = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)

    # Skip whitespace normalization for now to preserve original formatting
    # html = re.sub(r"[ \t]+", " ", html)  # Collapse multiple spaces/tabs to single space
    # Don't remove spaces around newlines as they might be meaningful in text content
    # html = re.sub(
    #     r"\n{3,}", "\n\n", html
    # )  # Collapse excessive newlines to double newline

    # Strip leading/trailing whitespace
    html = html.strip()

    return html


def get_cleaned_body_text(text: str) -> str:
    """
    Get cleaned text body content with fallback to empty string.

    Args:
        text: Raw text content

    Returns:
        Cleaned text content or empty string
    """
    try:
        return clean_text_body(text)
    except Exception:
        return ""


def get_cleaned_body_html(html: str) -> str:
    """
    Get cleaned HTML body content with fallback to empty string.

    Args:
        html: Raw HTML content

    Returns:
        Cleaned HTML content or empty string
    """
    try:
        return clean_html_body(html)
    except Exception:
        return ""


def strip_html_tags(html: str) -> str:
    """
    Strip HTML tags from content, useful for creating text previews.

    Args:
        html: HTML content

    Returns:
        Text content with HTML tags removed
    """
    if not html:
        return ""

    # Remove script and style tags and their content first
    html = re.sub(
        r"<script[^>]*>.*?</script>", "", html, flags=re.IGNORECASE | re.DOTALL
    )
    html = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.IGNORECASE | re.DOTALL)

    # Remove HTML tags
    text = re.sub(r"<[^>]+>", "", html)

    # Decode HTML entities
    import html

    text = html.unescape(text)

    # Clean the resulting text
    return clean_text_body(text)
