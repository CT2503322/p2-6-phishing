from typing import Dict, Any, List
from .keywords import analyze_keywords
from .position import calculate_positioned_score
from .whitelist import load_whitelist, is_whitelisted
from urllib.parse import urlparse
import re
from ..ingestion.body_cleaner import strip_html_tags
from ..ingestion.confusables import DETECTOR

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


def calculate_confusable_score_boost(domains: List[str]) -> float:
    """
    Calculate scoring boost for brand matches using confusables analysis.

    Args:
        domains: List of domains to check for brand matches

    Returns:
        Total boost amount (1.5 per qualifying brand match)
    """
    total_boost = 0.0
    boosted_brands = set()  # Track brands to avoid double-counting subdomains

    for domain in domains:
        if not domain:
            continue

        finding = DETECTOR.analyze_domain(domain)

        # Apply boost if this qualifies as a brand match
        if DETECTOR.should_apply_brand_boost(finding):
            if finding.matched_brand not in boosted_brands:
                total_boost += 1.5
                boosted_brands.add(finding.matched_brand)

    return total_boost


def analyze(
    headers: Dict[str, Any],
    subject: str,
    body: str,
    html: str,
    sender_identity: Any = None,
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

    # Calculate confusable score boost
    confusable_boost = 0.0
    if sender_identity:
        # Collect all domains from sender identity for boosting
        sender_domains = []
        if sender_identity.from_domain:
            sender_domains.append(sender_identity.from_domain)
        if sender_identity.reply_to_domain:
            sender_domains.append(sender_identity.reply_to_domain)
        if sender_identity.return_path_domain:
            sender_domains.append(sender_identity.return_path_domain)

        # Add unique domains from content analysis
        sender_domains.extend(list(domains))

        confusable_boost = calculate_confusable_score_boost(sender_domains)

        # Add reason for confusable boost
        if confusable_boost > 0:
            reasons.append(f"BRAND_SPOOFING_BOOST:{confusable_boost:.1f}")

    # Calculate final score
    final_score = keyword_score + confusable_boost

    return {
        "reasons": reasons,
        "keywords": kw_res["simplified_keywords"],
        "keyword_analysis": kw_res["meta"],
        "keyword_score": keyword_score,
        "confusable_boost": confusable_boost,
        "final_score": final_score,
        "whitelisted_domains": whitelisted_domains,
    }
