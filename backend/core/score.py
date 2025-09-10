from typing import Dict, Any, List
from .keywords import analyze_keywords
from .position import calculate_positioned_score
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
    # Use new position-aware keyword analysis
    keyword_analysis = analyze_keywords(subject, body, use_positions=True)
    return {
        "meta": keyword_analysis,
        "simplified_keywords": [
            {"keyword": hit.term, "count": 1}
            for hit in keyword_analysis["keyword_hits"]
        ],
    }


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

    # Extract domains from all content (removed since this is now handled at API level)
    all_content = subject + "\n" + body + "\n" + html
    domains = extract_domains(all_content)

    # Aggregate reasons (without scoring)
    reasons = wl_res["reasons"]
    keyword_score = kw_res["meta"]["total_score"]

    # Add keyword-based reasons if score is high
    if keyword_score >= 3.0:
        reasons.append(f"HIGH_KEYWORD_SCORE:{keyword_score:.1f}")
    elif keyword_score >= 1.5:
        reasons.append(f"MEDIUM_KEYWORD_SCORE:{keyword_score:.1f}")

    # Get whitelist information for domains (for frontend display)
    whitelisted_domains = [d for d in domains if is_whitelisted(d, wl)]

    return {
        "reasons": reasons,
        "keywords": kw_res["simplified_keywords"],
        "keyword_analysis": kw_res["meta"],
        "keyword_score": keyword_score,
        "whitelisted_domains": whitelisted_domains,
    }
