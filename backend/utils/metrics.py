"""
Metrics extraction utilities for email content analysis.

This module provides functions to extract various metrics from HTML and text content
including link counts, image counts, language detection, emoji detection, etc.
"""

import re
import ipaddress
from urllib.parse import urlparse, urljoin
from typing import Optional, Tuple, List

from backend.core.confusables import DETECTOR
from backend.utils.text import strip_html_tags
from backend.utils.models import HtmlMetrics, TextMetrics, UrlFinding


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

    # Extract URL findings
    url_findings = extract_url_findings(html_content)

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
        url_findings=url_findings,
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


def extract_url_findings(html_content: str) -> List[UrlFinding]:
    """
    Extract URLs from HTML content and analyze them for phishing indicators.

    Args:
        html_content: HTML content to analyze

    Returns:
        List of UrlFinding objects with detailed analysis
    """
    if not html_content:
        return []

    findings = []
    seen_urls = set()  # Track unique URLs to avoid duplicates

    # Extract base URL if present
    base_url = _extract_base_url(html_content)
    base_parsed = urlparse(base_url) if base_url else None

    # Find all anchor tags with href attributes
    link_pattern = r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>'
    matches = re.findall(link_pattern, html_content, re.IGNORECASE | re.DOTALL)

    for href, anchor_text in matches:
        # Resolve relative URLs
        absolute_href = _resolve_url(href, base_url)

        if absolute_href in seen_urls:
            continue
        seen_urls.add(absolute_href)

        # Parse the URL
        parsed_url = urlparse(absolute_href)
        if not parsed_url.netloc:
            continue  # Skip invalid URLs

        # Clean anchor text
        clean_text = _clean_anchor_text(anchor_text)

        # Analyze URL components
        # Check for confusables in domain
        confusable_finding = DETECTOR.analyze_domain(parsed_url.netloc)

        # Update evidence with confusable results
        confusable_evidence = ""
        if confusable_finding.evidence:
            confusable_evidence = f"; {confusable_finding.evidence}"

        finding = UrlFinding(
            text=clean_text,
            href=absolute_href,
            netloc=parsed_url.netloc,
            is_ip_literal=_is_ip_literal(parsed_url.netloc),
            is_punycode=parsed_url.netloc.startswith("xn--"),
            skeleton_match=confusable_finding.skeleton_match,
            is_shortener=_is_url_shortener(parsed_url.netloc),
            text_href_mismatch=_has_text_href_mismatch(clean_text, parsed_url.netloc),
            brand_match=confusable_finding.matched_brand,
            first_seen_pos=html_content.find(
                absolute_href
            ),  # Position of the URL itself
            evidence=_generate_evidence(
                clean_text,
                absolute_href,
                parsed_url.netloc,
                _is_ip_literal(parsed_url.netloc),
                parsed_url.netloc.startswith("xn--"),
                _is_url_shortener(parsed_url.netloc),
                _has_text_href_mismatch(clean_text, parsed_url.netloc),
                confusable_finding.matched_brand,
            )
            + confusable_evidence,
        )
        findings.append(finding)

    return findings


def _extract_base_url(html_content: str) -> Optional[str]:
    """Extract base URL from <base href="..."> tag."""
    base_pattern = r'<base[^>]*href=["\']([^"\']+)["\']'
    match = re.search(base_pattern, html_content, re.IGNORECASE)
    return match.group(1) if match else None


def _resolve_url(href: str, base_url: Optional[str]) -> str:
    """Resolve relative URLs to absolute URLs."""
    if not base_url:
        # If href is already absolute or protocol-relative, return as-is
        if href.startswith(("http://", "https://", "//")):
            return href if href.startswith("//") else href
        else:
            # Assume http:// as default for relative URLs without base
            return f"http://{href}"
    else:
        return urljoin(base_url, href)


def _clean_anchor_text(anchor_text: str) -> str:
    """Clean and normalize anchor text."""
    # Remove HTML tags and extra whitespace
    text = re.sub(r"<[^>]+>", "", anchor_text)
    return text.strip()


def _is_ip_literal(netloc: str) -> bool:
    """Check if netloc is an IP literal (IPv4 or IPv6)."""
    try:
        # Handle IPv6 addresses in brackets
        if netloc.startswith("[") and "]" in netloc:
            ip_part = netloc[1 : netloc.find("]")]
            ipaddress.IPv6Address(ip_part)
            return True
        else:
            # Handle IPv4 or plain IPv6
            ipaddress.ip_address(netloc.split(":")[0])
            return True
    except ValueError:
        return False


def _is_url_shortener(netloc: str) -> bool:
    """Check if netloc is a known URL shortener service."""
    shorteners = {
        "bit.ly",
        "t.co",
        "tinyurl.com",
        "goo.gl",
        "cutt.ly",
        "rebrand.ly",
        "lnkd.in",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "adf.ly",
        "bl.ink",
        "linktr.ee",
        "tiny.cc",
    }
    domain = netloc.lower().split(":")[0]  # Remove port if present
    return domain in shorteners


def _normalize_domain(domain: str) -> str:
    """Normalize domain for comparison (remove www. prefix, convert to lowercase)."""
    domain = domain.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def _has_text_href_mismatch(text: str, netloc: str) -> bool:
    """Check if anchor text looks like a URL/brand but points elsewhere."""
    if not text or not netloc:
        return False

    # Check if text looks like a URL
    url_like_patterns = [
        r"https?://[^\s]+",  # http:// or https://
        r"www\.[^\s]+",  # www.something
        r"[a-zA-Z0-9-]+\.[a-zA-Z]{2,}",  # domain-like pattern
    ]

    text_looks_like_url = any(
        re.search(pattern, text, re.IGNORECASE) for pattern in url_like_patterns
    )

    if text_looks_like_url:
        # Extract domain from text if it looks like a URL
        text_domain = re.search(
            r"(?:https?://|www\.|)([^\s/\?#]+)", text, re.IGNORECASE
        )
        if text_domain:
            normalized_text_domain = _normalize_domain(text_domain.group(1))
            normalized_href_domain = _normalize_domain(netloc)
            return normalized_text_domain != normalized_href_domain

    return False


def _match_brand(netloc: str) -> Optional[str]:
    """Check if URL domain matches known brands."""
    known_brands = {
        "google.com": "Google",
        "facebook.com": "Facebook",
        "amazon.com": "Amazon",
        "microsoft.com": "Microsoft",
        "apple.com": "Apple",
        "paypal.com": "PayPal",
        "github.com": "GitHub",
        "twitter.com": "Twitter",
        "instagram.com": "Instagram",
        "linkedin.com": "LinkedIn",
        "youtube.com": "YouTube",
    }

    domain = _normalize_domain(netloc.split(":")[0])  # Remove port

    # Check exact match
    if domain in known_brands:
        return known_brands[domain]

    # Check subdomain match
    for brand_domain, brand_name in known_brands.items():
        if domain.endswith("." + brand_domain):
            return brand_name

    return None


def _generate_evidence(
    text: str,
    href: str,
    netloc: str,
    is_ip: bool,
    is_puny: bool,
    is_shortener: bool,
    has_mismatch: bool,
    brand: Optional[str],
) -> str:
    """Generate explanation string for the URL finding."""
    reasons = []

    if is_ip:
        reasons.append("Uses IP literal instead of domain name")
    if is_puny:
        reasons.append("Uses Punycode/IDN encoding")
    if is_shortener:
        reasons.append("Uses URL shortening service")
    if has_mismatch:
        reasons.append(f"Anchor text '{text}' doesn't match domain '{netloc}'")
    if brand:
        reasons.append(f"Domain appears legitimate ({brand})")

    if reasons:
        return "; ".join(reasons)
    else:
        return "Clean URL"
