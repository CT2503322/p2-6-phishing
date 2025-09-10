"""
Metrics extraction utilities for email content analysis.

This module provides functions to extract various metrics from HTML and text content
including link counts, image counts, language detection, emoji detection, etc.
"""

import re
from typing import Optional, Tuple
from .models import HtmlMetrics, TextMetrics
from .body_cleaner import strip_html_tags


def extract_html_metrics(html_content: str, subject: str = "") -> HtmlMetrics:
    """
    Extract HTML-specific metrics from email content.

    Args:
        html_content: The HTML content to analyze
        subject: Email subject for emoji detection

    Returns:
        HtmlMetrics object with extracted metrics
    """
    if not html_content:
        return HtmlMetrics()

    # Basic length
    length = len(html_content)

    # Count links (anchor tags with href)
    link_count = len(
        re.findall(r'<a[^>]*href=["\'][^"\']*["\']', html_content, re.IGNORECASE)
    )

    # Count images (img tags)
    image_count = len(re.findall(r"<img[^>]*>", html_content, re.IGNORECASE))

    # Check for remote CSS (link tags with href to external resources)
    remote_css = bool(
        re.search(
            r'<link[^>]*href=["\'][^"\']*://[^"\']*["\']', html_content, re.IGNORECASE
        )
    )

    # Count tracking pixels (1x1 images or images with tracking domains)
    tracking_pixels = len(
        re.findall(
            r'<img[^>]*(width=["\']1["\']|height=["\']1["\'])[^>]*>',
            html_content,
            re.IGNORECASE,
        )
    )
    # Also check for common tracking domains
    tracking_domains = [
        "doubleclick",
        "googletagmanager",
        "google-analytics",
        "facebook.com/tr",
        "pixel",
    ]
    for domain in tracking_domains:
        tracking_pixels += len(
            re.findall(
                rf'<img[^>]*src=["\'][^"\']*{re.escape(domain)}[^"\']*["\']',
                html_content,
                re.IGNORECASE,
            )
        )

    # Calculate text to HTML ratio
    text_content = strip_html_tags(html_content)
    text_length = len(text_content)
    ratio_text_to_html = text_length / length if length > 0 else 0.0

    # Check for soft hyphens
    uses_soft_hyphen = "\u00ad" in html_content

    # Check for emoji in subject
    has_emoji_in_subject = bool(
        re.search(
            r"[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF\U0001F680-\U0001F6FF\U0001F1E0-\U0001F1FF]",
            subject or "",
        )
    )

    # Calculate non-ASCII ratio
    ascii_chars = sum(1 for c in html_content if ord(c) < 128)
    non_ascii_ratio = 1.0 - (ascii_chars / length) if length > 0 else 0.0

    return HtmlMetrics(
        length=length,
        link_count=link_count,
        image_count=image_count,
        remote_css=remote_css,
        tracking_pixels=tracking_pixels,
        ratio_text_to_html=ratio_text_to_html,
        uses_soft_hyphen=uses_soft_hyphen,
        has_emoji_in_subject=has_emoji_in_subject,
        non_ascii_ratio=non_ascii_ratio,
    )


def extract_text_metrics(text_content: str) -> TextMetrics:
    """
    Extract text-specific metrics from email content.

    Args:
        text_content: The text content to analyze

    Returns:
        TextMetrics object with extracted metrics
    """
    if not text_content:
        return TextMetrics()

    # Basic length
    length = len(text_content)

    # Detect language (simple heuristic based on common words)
    language = detect_language(text_content)

    # Count emojis
    emoji_pattern = r"[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF\U0001F680-\U0001F6FF\U0001F1E0-\U0001F1FF]"
    emoji_count = len(re.findall(emoji_pattern, text_content))

    # Calculate shouting ratio (uppercase characters)
    uppercase_chars = sum(1 for c in text_content if c.isupper())
    shouting_ratio = uppercase_chars / length if length > 0 else 0.0

    return TextMetrics(
        length=length,
        language=language,
        emoji_count=emoji_count,
        shouting_ratio=shouting_ratio,
    )


def detect_language(text: str) -> Optional[str]:
    """
    Simple language detection based on common words and patterns.

    Args:
        text: Text to analyze

    Returns:
        Detected language code or None
    """
    if not text:
        return None

    text_lower = text.lower()
    words = text_lower.split()

    if not words:
        return None

    # English patterns (more distinctive words)
    english_words = [
        "the",
        "and",
        "is",
        "in",
        "to",
        "of",
        "a",
        "that",
        "it",
        "with",
        "this",
        "for",
        "are",
        "but",
        "not",
        "you",
        "all",
        "can",
        "had",
        "her",
    ]
    english_count = sum(1 for word in words if word in english_words)

    # Spanish patterns (more distinctive words)
    spanish_words = [
        "el",
        "la",
        "de",
        "que",
        "y",
        "en",
        "un",
        "es",
        "se",
        "no",
        "los",
        "del",
        "las",
        "por",
        "una",
        "con",
        "para",
        "como",
        "más",
        "su",
    ]
    spanish_count = sum(1 for word in words if word in spanish_words)

    # French patterns
    french_words = [
        "le",
        "la",
        "de",
        "et",
        "à",
        "un",
        "il",
        "être",
        "et",
        "en",
        "les",
        "du",
        "sur",
        "avec",
        "pour",
        "dans",
        "par",
        "son",
        "qui",
        "faire",
    ]
    french_count = sum(1 for word in words if word in french_words)

    # German patterns
    german_words = [
        "der",
        "die",
        "und",
        "in",
        "den",
        "von",
        "zu",
        "das",
        "mit",
        "sich",
        "auf",
        "für",
        "ist",
        "im",
        "ein",
        "nicht",
        "eine",
        "als",
        "auch",
        "es",
    ]
    german_count = sum(1 for word in words if word in german_words)

    # Find the language with the highest match count
    languages = {
        "en": english_count,
        "es": spanish_count,
        "fr": french_count,
        "de": german_count,
    }

    max_lang = max(languages.items(), key=lambda x: x[1])

    # Only return a language if we have at least some matches and it's clearly dominant
    if max_lang[1] > 0:
        # Check if this language has significantly more matches than others
        sorted_langs = sorted(languages.items(), key=lambda x: x[1], reverse=True)
        if len(sorted_langs) > 1 and sorted_langs[0][1] > sorted_langs[1][1]:
            return max_lang[0]

    return None
