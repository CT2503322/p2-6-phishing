from typing import Dict, Any, List
from backend.core.keywords import analyze_keywords
from backend.core.position import calculate_positioned_score
from backend.core.whitelist import load_whitelist, is_whitelisted, check_whitelist_hit
from urllib.parse import urlparse
import re
from backend.utils.text import strip_html_tags
from backend.core.confusables import DETECTOR
from backend.utils.models import RuleScore, ScoredAnalysis, Label

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

    # Use enhanced whitelist checking that provides detailed WhitelistHit information
    all_whitelist_hits = []
    whitelisted_domains = []

    for domain in domains:
        hits = check_whitelist_hit(domain, wl, reason="content-analysis")
        if hits:
            all_whitelist_hits.extend(hits)
            whitelisted_domains.append(domain)

    whitelisted = len(whitelisted_domains) > 0

    return {
        "whitelisted": whitelisted,
        "whitelist_hits": all_whitelist_hits,
        "whitelisted_domains": whitelisted_domains,
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

    # Extract domains from all content
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

    # Generate html preview and text
    html_text = strip_html_tags(html) if html else ""
    html_preview = html_text[:500] + "..." if len(html_text) > 500 else html_text

    return {
        "reasons": reasons,
        "keywords": kw_res["simplified_keywords"],
        "keyword_analysis": kw_res["meta"],
        "keyword_score": keyword_score,
        "confusable_boost": confusable_boost,
        "final_score": final_score,
        "whitelist_hits": wl_res[
            "whitelist_hits"
        ],  # Include detailed whitelist hit information
        "whitelisted_domains": wl_res["whitelisted_domains"],
        "meta": {
            "html_preview": html_preview,
            "html_text": html_text,
            "keyword_hits": kw_res["meta"]["keyword_hits"],
            "term_stats": kw_res["meta"]["term_stats"],
            "total_score": keyword_score,
        },
    }


def _detect_url_anomalies(content: str) -> List[RuleScore]:
    """Detect URL-related security anomalies."""
    rules = []
    urls = URL_PATTERN.findall(content)

    for url in urls:
        try:
            parsed = urlparse(url)

            # Rule: URL Punycode detection
            if parsed.netloc and parsed.netloc.startswith("xn--"):
                rules.append(
                    RuleScore(
                        rule="url_punycode",
                        delta=2.0,
                        evidence=f"Punycode URL detected: {url}",
                    )
                )

            # Rule: URL IP literal detection
            IP_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
            if parsed.netloc and IP_PATTERN.match(parsed.netloc):
                rules.append(
                    RuleScore(
                        rule="url_ip_literal",
                        delta=1.5,
                        evidence=f"IP literal URL detected: {url}",
                    )
                )

            # Rule: URL shortener detection
            SHORTENERS = [
                "bit.ly",
                "t.co",
                "tinyurl.com",
                "goo.gl",
                "ow.ly",
                "fb.me",
                "tiny.cc",
                "is.gd",
                "buff.ly",
            ]
            if parsed.netloc and any(
                shortener in parsed.netloc.lower() for shortener in SHORTENERS
            ):
                rules.append(
                    RuleScore(
                        rule="url_shortener",
                        delta=1.0,
                        evidence=f"URL shortener detected: {url}",
                    )
                )

        except Exception:
            continue

    return rules


def _evaluate_sender_identity(sender_identity: Any) -> List[RuleScore]:
    """Evaluate sender identity for security issues."""
    rules = []

    if not sender_identity:
        return rules

    # Rule: Reply-to mismatch
    from_domain = sender_identity.from_domain or ""
    reply_to_domain = sender_identity.reply_to_domain or ""
    return_path_domain = sender_identity.return_path_domain or ""

    if reply_to_domain and from_domain != reply_to_domain:
        rules.append(
            RuleScore(
                rule="replyto_mismatch",
                delta=1.5,
                evidence=f"Reply-To domain '{reply_to_domain}' differs from From domain '{from_domain}'",
            )
        )

    # Rule: Return-path mismatch
    if return_path_domain and from_domain != return_path_domain:
        rules.append(
            RuleScore(
                rule="return_path_mismatch",
                delta=1.0,
                evidence=f"Return-Path domain '{return_path_domain}' differs from From domain '{from_domain}'",
            )
        )

    # Rule: No SPF record match (from auth data)
    if hasattr(sender_identity, "spf_result") and sender_identity.spf_result == "fail":
        rules.append(
            RuleScore(
                rule="spf_failure",
                delta=2.0,
                evidence="SPF authentication failed for sender domain",
            )
        )

    # Rule: No DKIM signature
    if (
        hasattr(sender_identity, "dkim_verifications")
        and not sender_identity.dkim_verifications
    ):
        rules.append(
            RuleScore(
                rule="dkim_missing", delta=1.0, evidence="No DKIM signatures found"
            )
        )

    return rules


def _evaluate_content_patterns(subject: str, body: str, html: str) -> List[RuleScore]:
    """Evaluate content patterns for phishing indicators."""
    rules = []

    combined_content = subject + "\n" + body + "\n" + html

    # Rule: High urgency keywords
    urgency_keywords = [
        "urgent",
        "asap",
        "immediately",
        "now",
        "immediate action",
        "action required",
    ]
    urgency_count = sum(1 for kw in urgency_keywords if kw in combined_content.lower())
    if urgency_count >= 2:
        rules.append(
            RuleScore(
                rule="high_urgency",
                delta=1.5,
                evidence=f"High urgency pattern detected ({urgency_count} keywords)",
            )
        )

    # Rule: Suspicious HTML patterns
    if html and "<script" in html.lower():
        rules.append(
            RuleScore(
                rule="javascript_injection",
                delta=2.5,
                evidence="JavaScript code detected in HTML content",
            )
        )

    # Rule: Many exclamation marks
    exclamation_count = combined_content.count("!")
    if exclamation_count >= 10:
        rules.append(
            RuleScore(
                rule="excessive_exclamation",
                delta=0.5,
                evidence=f"Excessive exclamation marks ({exclamation_count})",
            )
        )

    return rules


def analyze_with_rules(
    headers: Dict[str, Any],
    subject: str,
    body: str,
    html: str,
    sender_identity: Any = None,
    threshold: float = 3.2,
    tuning_profile: str = "default",
) -> Dict[str, Any]:
    """
    Analyze email and return detailed rule-based scoring.

    Returns:
        Dictionary containing legacy analysis plus new ScoredAnalysis object
    """
    # Get legacy analysis results
    legacy_analysis = analyze(headers, subject, body, html, sender_identity)

    # Collect rule scores
    rule_scores = []

    # URL anomaly detection
    all_content = subject + "\n" + body + "\n" + html
    rule_scores.extend(_detect_url_anomalies(all_content))

    # Sender identity evaluation
    rule_scores.extend(_evaluate_sender_identity(sender_identity))

    # Content pattern evaluation
    rule_scores.extend(_evaluate_content_patterns(subject, body, html))

    # Base keyword scoring
    keyword_score = legacy_analysis["keyword_score"]
    if keyword_score > 0:
        rule_scores.append(
            RuleScore(
                rule="keyword_frenzy",
                delta=keyword_score,
                evidence=f"Keyword analysis score: {keyword_score:.2f}",
            )
        )

    # Confusable/brand spoofing boost
    confusable_boost = legacy_analysis["confusable_boost"]
    if confusable_boost > 0:
        rule_scores.append(
            RuleScore(
                rule="brand_spoofing",
                delta=confusable_boost,
                evidence=f"Brand spoofing detected: boost of {confusable_boost:.2f}",
            )
        )

    # Calculate total score from rules
    score_total = sum(rule.delta for rule in rule_scores)

    # Determine label based on threshold
    label = Label.PHISHING if score_total >= threshold else Label.SAFE

    # Create ScoredAnalysis object
    scored_analysis = ScoredAnalysis(
        score_breakdown=rule_scores,
        score_total=score_total,
        label=label,
        threshold_used=threshold,
        tuning_profile=tuning_profile,
    )

    # Update legacy result with comprehensive analysis
    legacy_analysis.update(
        {
            "scored_analysis": {
                "score_breakdown": [
                    {"rule": r.rule, "delta": r.delta, "evidence": r.evidence}
                    for r in rule_scores
                ],
                "score_total": score_total,
                "label": label.value,
                "threshold_used": threshold,
                "tuning_profile": tuning_profile,
            },
            "score_total": score_total,
            "label": label.value,
        }
    )

    return legacy_analysis
