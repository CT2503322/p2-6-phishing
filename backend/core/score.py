from typing import Dict, Any, List
from .keywords import find
from .whitelist import load_whitelist, is_whitelisted
from urllib.parse import urlparse
import re
from ..ingestion.body_cleaner import strip_html_tags

# Configuration constants
WHITELIST_PATH = "backend/data/whitelist.txt"

# Pre-compile regex for efficiency
URL_PATTERN = re.compile(r"https?://[^\s]+")

# Load whitelist once at module level
wl = load_whitelist(WHITELIST_PATH)


def extract_domains(text: str) -> set[str]:
    """
    Extract domains from URLs in text using pre-compiled regex.

    Args:
        text: Input text containing URLs

    Returns:
        Set of unique domains in lowercase
    """
    if not text:
        return set()

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


def check_keywords(subject: str, body: str) -> Dict[str, Any]:
    kws = find(subject + "\n" + body)
    return {"meta": {"keywords": kws}}


def check_whitelist(subject: str, body: str, html: str) -> Dict[str, Any]:
    domains = extract_domains(subject + "\n" + body + "\n" + html)
    whitelisted = any(is_whitelisted(d, wl) for d in domains)
    return {
        "whitelisted": whitelisted,
        "reasons": ["WHITELISTED"] if whitelisted else [],
    }


def analyze(
    headers: Dict[str, Any], subject: str, body: str, html: str
) -> Dict[str, Any]:
    # Run checks
    kw_res = check_keywords(subject, body)
    wl_res = check_whitelist(subject, body, html)

    # Extract domains from all content
    all_content = subject + "\n" + body + "\n" + html
    domains = extract_domains(all_content)

    # Aggregate reasons (without scoring)
    reasons = wl_res["reasons"]
    # Removed scoring logic

    # Extract key headers for display
    key_headers = {
        "from": headers.get("From", ""),
        "to": headers.get("To", ""),
        "cc": headers.get("Cc", ""),
        "bcc": headers.get("Bcc", ""),
        "date": headers.get("Date", ""),
        "reply_to": headers.get("Reply-To", ""),
        "return_path": headers.get("Return-Path", ""),
        "message_id": headers.get("Message-ID", ""),
        "content_type": headers.get("Content-Type", ""),
    }

    # Create body preview (first 500 characters)
    body_preview = body[:500] + ("..." if len(body) > 500 else "")

    # Create HTML preview if present
    html_preview = ""
    html_text = ""
    if html:
        # Strip HTML tags for preview using improved function
        html_clean = strip_html_tags(html)
        html_preview = html_clean[:500] + ("..." if len(html_clean) > 500 else "")
        # Full HTML text without truncation
        html_text = html_clean

    return {
        "reasons": reasons,
        "meta": {
            **kw_res["meta"],
            "headers": headers,
            "key_headers": key_headers,
            "subject": subject,
            "body_preview": body_preview,
            "html_preview": html_preview,
            "html_text": html_text,
            "domains": list(domains),
            "whitelisted_domains": [d for d in domains if is_whitelisted(d, wl)],
            "content_stats": {
                "body_length": len(body),
                "html_length": len(html),
                "has_html": bool(html),
                "domain_count": len(domains),
            },
        },
    }
