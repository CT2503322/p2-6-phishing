from typing import Dict, Any, List, Tuple, Optional
from backend.core.keywords import analyze_keywords
from backend.core.position import calculate_positioned_score
from backend.core.whitelist import load_whitelist, is_whitelisted
from urllib.parse import urlparse
import re
import math
import statistics
from datetime import datetime
from backend.utils.text import strip_html_tags
from backend.core.confusables import DETECTOR
from backend.utils.models import RuleScore, ScoredAnalysis, Label, KeywordHit

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
        "whitelisted_domains": whitelisted_domains,
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


# =============================================================================
# ADVANCED SCORING ALGORITHMS
# =============================================================================


def _advanced_url_anomaly_detection(content: str, subject: str) -> List[RuleScore]:
    """
    Enhanced URL anomaly detection with sophisticated pattern analysis.

    Args:
        content: Email content to analyze
        subject: Email subject line

    Returns:
        List of enhanced rule scores for URL anomalies
    """
    rules = []

    # Get basic URL anomalies first
    basic_rules = _detect_url_anomalies(content)
    rules.extend(basic_rules)

    # Enhanced patterns
    urls = URL_PATTERN.findall(content)
    subject_urls = URL_PATTERN.findall(subject)

    # Rule: Multiple URL shorteners (suspicious pattern)
    shortener_domains = [
        "bit.ly",
        "t.co",
        "tinyurl.com",
        "goo.gl",
        "ow.ly",
        "fb.me",
        "tiny.cc",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "lnkd.in",
        "cutt.ly",
    ]

    found_shorteners = []
    for url in urls:
        try:
            parsed = urlparse(url)
            if parsed.netloc.lower() in shortener_domains:
                found_shorteners.append(parsed.netloc.lower())
        except:
            continue

    if len(set(found_shorteners)) > 1:
        rules.append(
            RuleScore(
                rule="multiple_url_shorteners",
                delta=2.5,
                evidence=f"Multiple different URL shorteners detected: {', '.join(set(found_shorteners))}",
            )
        )

    # Rule: URL in subject but body URLs different (linkbait pattern)
    if subject_urls and urls:
        subject_domains = set()
        body_domains = set()

        for url in subject_urls:
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    subject_domains.add(parsed.netloc.lower())
            except:
                continue

        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    body_domains.add(parsed.netloc.lower())
            except:
                continue

        if not subject_domains.intersection(body_domains):
            rules.append(
                RuleScore(
                    rule="subject_body_url_mismatch",
                    delta=1.8,
                    evidence=f"Subject contains URLs from domains {subject_domains} but body has different URLs from {body_domains}",
                )
            )

    # Rule: Suspicious query parameter patterns
    suspicious_params = {
        "login": 1.2,
        "password": 2.0,
        "confirm": 1.0,
        "verify": 1.5,
        "secure": 1.0,
        "auth": 1.3,
    }

    for url in urls:
        try:
            parsed = urlparse(url)
            if parsed.query:
                query_params = parsed.query.lower().split("&")
                for param in query_params:
                    param_name = param.split("=")[0]
                    if param_name in suspicious_params:
                        rules.append(
                            RuleScore(
                                rule="suspicious_url_parameter",
                                delta=suspicious_params[param_name],
                                evidence=f"Suspicious URL parameter '{param_name}' in: {url}",
                            )
                        )
        except:
            continue

    return rules


def _temporal_pattern_analysis(content: str) -> List[RuleScore]:
    """
    Analyze temporal patterns that may indicate phishing attempts.

    Args:
        content: Email content to analyze

    Returns:
        List of rule scores for temporal patterns
    """
    rules = []

    # Rule: Weekend or unusual timing patterns
    if hasattr(
        content, "timestamp"
    ):  # Assuming timestamp might be available in headers
        # This is a placeholder for temporal analysis
        # In a real implementation, you'd extract timestamps and analyze patterns
        pass

    return rules


def _behavioral_ml_features(content: str, rules: List[RuleScore]) -> Dict[str, float]:
    """
    Extract behavioral ML features from content and rules.

    This simulates ML feature extraction that would normally be done by a trained model.

    Args:
        content: Email content
        rules: List of triggered rules

    Returns:
        Dictionary of behavioral features
    """
    features = {
        "rule_diversity": 0.0,
        "content_complexity": 0.0,
        "urgency_intensity": 0.0,
        "suspicion_level": 0.0,
    }

    if not rules:
        return features

    # Rule diversity - more different types of rules = higher suspicion
    unique_rules = set(r.rule for r in rules)
    features["rule_diversity"] = (
        len(unique_rules) / 15.0
    )  # Normalize by total possible rules

    # Content complexity
    total_length = len(content)
    unique_chars = len(set(content))
    features["content_complexity"] = (
        unique_chars / total_length if total_length > 0 else 0
    )

    # Urgency intensity
    urgency_indicators = sum(
        1 for r in rules if "urgency" in r.rule or "high_" in r.rule.lower()
    )
    features["urgency_intensity"] = min(urgency_indicators, 5.0) / 5.0

    # Overall suspicion level based on rule severity
    strong_rules = sum(1 for r in rules if abs(r.delta) >= 2.0)
    features["suspicion_level"] = min(strong_rules, 10.0) / 10.0

    return features


def _ensemble_scoring_confidence(
    rules: List[RuleScore], features: Dict[str, float]
) -> float:
    """
    Use ensemble methods to determine final scoring confidence.

    Args:
        rules: List of triggered rules
        features: Behavioral features dictionary

    Returns:
        Ensemble confidence score
    """
    if not rules:
        return 0.0

    # Individual confidence measures
    rule_confidence = _calculate_rule_confidence(rules)
    feature_confidence = sum(features.values()) / len(features) if features else 0.0

    # Rule strength confidence
    total_impact = sum(abs(r.delta) for r in rules)
    strength_confidence = min(total_impact / 10.0, 1.0)

    # Consensus confidence - require agreement between multiple methods
    confidences = [rule_confidence, feature_confidence, strength_confidence]
    mean_confidence = statistics.mean(confidences)
    confidence_variance = (
        statistics.variance(confidences) if len(confidences) > 1 else 0
    )

    # Reduce confidence if methods disagree significantly
    consensus_penalty = math.sqrt(confidence_variance)
    final_confidence = mean_confidence * (1.0 - consensus_penalty * 0.5)

    return max(0.0, min(final_confidence, 0.95))


# =============================================================================
# ENHANCED ANALYSIS FUNCTIONS
# =============================================================================


def _calculate_rule_confidence(rules: List[RuleScore]) -> float:
    """
    Calculate overall confidence in the scoring based on rule consistency and strength.

    Args:
        rules: List of rule scores that triggered

    Returns:
        Confidence score between 0.0 (no confidence) and 1.0 (full confidence)
    """
    if not rules:
        return 0.0

    # Base confidence on rule count and delta variance
    rule_count = len(rules)
    deltas = [r.delta for r in rules]

    if rule_count == 1:
        # Single rule - confidence based on delta strength
        confidence = min(abs(deltas[0]) / 3.0, 0.8)
    else:
        # Multiple rules - consider consistency and total impact
        mean_delta = statistics.mean(deltas)
        variance = statistics.variance(deltas) if len(deltas) > 1 else 0
        coefficient_of_variation = (
            math.sqrt(variance) / abs(mean_delta) if mean_delta != 0 else 0
        )

        # More consistent rules (lower variance) = higher confidence
        base_confidence = 1.0 / (1.0 + coefficient_of_variation)

        # Boost confidence with more strong-rules
        strong_rules = sum(1 for d in deltas if abs(d) >= 2.0)
        total_impact_factor = min(sum(abs(d) for d in deltas) / (rule_count * 1.5), 2.0)

        confidence = (
            base_confidence * (1 + strong_rules * 0.1) * min(total_impact_factor, 2.0)
        )

    return min(confidence, 0.95)  # Cap confidence slightly below perfection


def _adaptive_weight_adjustment(
    rules: List[RuleScore], tuning_profile: str = "default"
) -> List[RuleScore]:
    """
    Apply adaptive weight adjustments based on rule interactions and patterns.

    Args:
        rules: Original rule scores
        tuning_profile: Profile for weight tuning

    Returns:
        List of rules with adjusted weights
    """
    if not rules:
        return rules

    adjusted_rules = []

    for rule in rules:
        adjusted_delta = rule.delta

        # Apply tuning profile adjustments
        if tuning_profile == "conservative":
            # Reduce high-risk rule weights
            if abs(rule.delta) >= 2.0:
                adjusted_delta *= 0.8
        elif tuning_profile == "aggressive":
            # Boost high-risk rule weights for false negatives
            if abs(rule.delta) >= 1.5:
                adjusted_delta *= 1.2

        # Rule interaction adjustments
        rule_names = [r.rule for r in rules]
        if "spf_failure" in rule_names and "dkim_missing" in rule_names:
            # Authentication failures together are more suspicious
            if rule.rule in ["spf_failure", "dkim_missing"]:
                adjusted_delta *= 1.3

        if "url_shortener" in rule_names and "high_urgency" in rule_names:
            # URL shorteners + urgency = very suspicious
            if rule.rule in ["url_shortener", "high_urgency"]:
                adjusted_delta *= 1.2

        adjusted_rules.append(
            RuleScore(
                rule=rule.rule,
                delta=adjusted_delta,
                evidence=f"{rule.evidence} (adjusted weight: {adjusted_delta:.2f})",
            )
        )

    return adjusted_rules


def _probabilistic_scoring(
    rules: List[RuleScore], total_score: float
) -> Tuple[float, float]:
    """
    Apply probabilistic analysis to the scoring result.

    Returns:
        Tuple of (phishing_probability, uncertainty_level)
    """
    if not rules:
        return 0.0, 1.0

    # Logistic function for phishing probability
    def phish_probability(score: float) -> float:
        return 1.0 / (1.0 + math.exp(-score + 3.0))  # Sigmoid centered at threshold 3.0

    probability = phish_probability(total_score)

    # Calculate uncertainty based on rule confidence and score proximity to threshold
    rule_confidence = _calculate_rule_confidence(rules)
    score_proximity = abs(total_score - 3.0)  # 3.0 is default threshold
    proximity_factor = (
        max(0, (5.0 - score_proximity)) / 5.0
    )  # Uncertainty increases near threshold

    uncertainty = 1.0 - (rule_confidence * (1.0 - proximity_factor))

    return probability, uncertainty


def _generate_detailed_explanations(
    rules: List[RuleScore], total_score: float, confidence: float
) -> Dict[str, Any]:
    """
    Generate comprehensive explanations for the scoring decision.

    Args:
        rules: List of all triggered rules
        total_score: Final calculated score
        confidence: Confidence level in the score

    Returns:
        Dictionary with detailed explanations by category
    """
    explanations = {
        "summary": "",
        "categories": {},
        "recommendations": [],
        "false_positive_risks": [],
        "false_negative_risks": [],
    }

    if not rules:
        explanations["summary"] = (
            "No phishing indicators detected. Email appears legitimate."
        )
        return explanations

    # Categorize rules
    categories = {
        "authentication": [],
        "content": [],
        "url_anomalies": [],
        "brand_spoofing": [],
        "urgency": [],
    }

    for rule in rules:
        if rule.rule in [
            "spf_failure",
            "dkim_missing",
            "replyto_mismatch",
            "return_path_mismatch",
        ]:
            categories["authentication"].append(rule)
        elif rule.rule in [
            "keyword_frenzy",
            "excessive_exclamation",
            "javascript_injection",
        ]:
            categories["content"].append(rule)
        elif rule.rule in ["url_punycode", "url_ip_literal", "url_shortener"]:
            categories["url_anomalies"].append(rule)
        elif rule.rule == "brand_spoofing":
            categories["brand_spoofing"].append(rule)
        elif rule.rule == "high_urgency":
            categories["urgency"].append(rule)

    # Generate summary based on strongest categories
    strongest_category = max(
        categories.items(), key=lambda x: sum(abs(r.delta) for r in x[1])
    )
    category_name, category_rules = strongest_category

    if total_score >= 4.0:
        explanations["summary"] = (
            f"High risk: Strong indicators in {category_name.replace('_', ' ')} category."
        )
    elif total_score >= 3.0:
        explanations["summary"] = (
            f"Moderate risk: Multiple concerns identified, especially in {category_name.replace('_', ' ')}."
        )
    else:
        explanations["summary"] = (
            f"Low-moderate risk: Some concerns in {category_name.replace('_', ' ')}, but overall modest."
        )

    if confidence < 0.6:
        explanations[
            "summary"
        ] += f" Analysis confidence is low ({confidence:.1%}); manual review recommended."

    # Detailed category breakdown
    explanations["categories"] = {}
    for cat_name, cat_rules in categories.items():
        if cat_rules:
            category_score = sum(r.delta for r in cat_rules)
            explanations["categories"][cat_name] = {
                "rules_triggered": len(cat_rules),
                "total_impact": category_score,
                "confidence_boost": len(cat_rules) * 0.1 * confidence,
                "details": [r.evidence for r in cat_rules],
            }

    # Generate recommendations
    if total_score >= 3.5:
        explanations["recommendations"].extend(
            [
                "Immediately move email to junk/spam folder",
                "Do not click any links or provide personal information",
                "Verify sender authenticity through alternative channels",
                "Report to IT/security team if suspicious",
            ]
        )
    elif total_score >= 2.5:
        explanations["recommendations"].extend(
            [
                "Examine sender email address carefully",
                "Hover over links before clicking (don't click if suspicious)",
                "Consider verifying through known contact information",
                "Watch for unusual requests or language patterns",
            ]
        )
    else:
        explanations["recommendations"].append(
            "Email appears relatively safe, but remain vigilant"
        )

    # False positive/negative analysis
    if total_score >= 3.0 and any(
        sum(abs(r.delta) for r in cat_rules) >= 2.0 for cat_rules in categories.values()
    ):
        explanations["false_negative_risks"].extend(
            [
                "High-risk indicators present - classification may be correct",
                "Multiple strong rules triggered across categories",
                "Benefit of doubt should lean toward caution",
            ]
        )

    if total_score < 2.5 and "authentication" in [
        cat for cat, rules in categories.items() if rules
    ]:
        explanations["false_positive_risks"].append(
            "Authentication issues alone may not indicate phishing"
        )

    return explanations


def advanced_analyze_with_rules(
    headers: Dict[str, Any],
    subject: str,
    body: str,
    html: str,
    sender_identity: Any = None,
    threshold: float = 3.2,
    tuning_profile: str = "default",
    enable_explanations: bool = True,
) -> Dict[str, Any]:
    """
    Advanced analysis with sophisticated scoring algorithms, confidence levels, and detailed explanations.

    Features:
    - Adaptive rule weight adjustment
    - Probabilistic scoring
    - Confidence level calculation
    - Comprehensive explanations
    - Risk assessment

    Args:
        headers: Email headers dictionary
        subject: Email subject line
        body: Email body text
        html: Email HTML content
        sender_identity: Sender identity object
        threshold: Score threshold for phishing classification
        tuning_profile: Weight tuning profile ("default", "conservative", "aggressive")
        enable_explanations: Whether to generate detailed explanations

    Returns:
        Dictionary with advanced analysis results
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

    # Apply adaptive weight adjustments
    adjusted_rules = _adaptive_weight_adjustment(rule_scores, tuning_profile)

    # Calculate adjusted total score
    adjusted_score_total = sum(rule.delta for rule in adjusted_rules)

    # Calculate confidence
    confidence_level = _calculate_rule_confidence(adjusted_rules)

    # Probabilistic analysis
    phish_probability, uncertainty = _probabilistic_scoring(
        adjusted_rules, adjusted_score_total
    )

    # Determine label with enhanced logic
    if adjusted_score_total >= threshold:
        label = Label.PHISHING
    elif adjusted_score_total >= threshold - 1.0 and uncertainty > 0.3:
        # Near threshold with high uncertainty - label as suspicious but lean conservative
        label = Label.PHISHING if phish_probability > 0.6 else Label.SAFE
    else:
        label = Label.SAFE

    # Generate detailed explanations if requested
    explanations = {}
    if enable_explanations:
        explanations = _generate_detailed_explanations(
            adjusted_rules, adjusted_score_total, confidence_level
        )

    # Create ScoredAnalysis object
    scored_analysis = ScoredAnalysis(
        score_breakdown=adjusted_rules,
        score_total=adjusted_score_total,
        label=label,
        threshold_used=threshold,
        tuning_profile=tuning_profile,
    )

    # Build comprehensive result
    result = {
        # Legacy compatibility
        **legacy_analysis,
        # Enhanced analysis
        "scored_analysis": {
            "score_breakdown": [
                {"rule": r.rule, "delta": r.delta, "evidence": r.evidence}
                for r in adjusted_rules
            ],
            "score_total": adjusted_score_total,
            "adjusted_score_total": adjusted_score_total,  # Extra field for clarity
            "original_score_total": sum(
                r.delta for r in rule_scores
            ),  # Before adjustments
            "label": label.value,
            "threshold_used": threshold,
            "tuning_profile": tuning_profile,
            "confidence_level": confidence_level,
            "phishing_probability": phish_probability,
            "uncertainty_level": uncertainty,
            "rule_counts": {
                "total_rules": len(adjusted_rules),
                "positive_contributors": sum(1 for r in adjusted_rules if r.delta > 0),
                "negative_contributors": sum(1 for r in adjusted_rules if r.delta < 0),
                "strong_contributors": sum(
                    1 for r in adjusted_rules if abs(r.delta) >= 2.0
                ),
            },
        },
        # Update top-level fields for compatibility
        "score_total": adjusted_score_total,
        "label": label.value,
    }

    if enable_explanations:
        result["explanations"] = explanations

    return result


# =============================================================================
# UTILITY FUNCTIONS FOR TESTING AND VALIDATION
# =============================================================================


def test_advanced_algorithms():
    """
    Test function to validate the new sophisticated algorithms.

    Returns:
        Dictionary with test results demonstrating new features
    """
    # Sample phishing-like content for testing
    test_subject = "URGENT: Your Account Will Be SUSPENDED!"
    test_body = "Click here immediately: https://bit.ly/login and verify your information ASAP. This is critical!"
    test_html = "<script>alert('Important!');</script><a href='http://192.168.1.1/login'>Login</a>"

    class MockSenderIdentity:
        def __init__(self):
            self.from_domain = "fake-bank.com"
            self.reply_to_domain = "support-fake-bank.com"  # Mismatch for test
            self.return_path_domain = "bounce-fake-bank.com"
            self.spf_result = "fail"
            self.dkim_verifications = []

    sender_identity = MockSenderIdentity()

    # Test advanced analysis
    result = advanced_analyze_with_rules(
        headers={},
        subject=test_subject,
        body=test_body,
        html=test_html,
        sender_identity=sender_identity,
        threshold=3.0,
        tuning_profile="aggressive",  # More sensitive for testing
        enable_explanations=True,
    )

    return {
        "test_description": "Advanced scoring algorithms validation",
        "features_tested": [
            "adaptive_weight_adjustment",
            "confidence_levels",
            "probabilistic_scoring",
            "detailed_explanations",
            "behavioral_ml_features",
        ],
        "input_data": {
            "subject": test_subject,
            "body": test_body,
            "html": test_html,
            "sender_identity_domains": [
                sender_identity.from_domain,
                sender_identity.reply_to_domain,
            ],
        },
        "results": {
            "final_score": result["score_total"],
            "label": result["label"],
            "confidence_level": result["scored_analysis"]["confidence_level"],
            "phishing_probability": result["scored_analysis"]["phishing_probability"],
            "uncertainty_level": result["scored_analysis"]["uncertainty_level"],
            "rule_counts": result["scored_analysis"]["rule_counts"],
            "explanation_summary": result.get("explanations", {}).get("summary", ""),
            "recommendations_count": len(
                result.get("explanations", {}).get("recommendations", [])
            ),
        },
        "performance_indicators": {
            "strong_rules_triggered": sum(
                1
                for r in result["scored_analysis"]["score_breakdown"]
                if abs(r["delta"]) >= 2.0
            ),
            "category_diversity": len(
                result.get("explanations", {}).get("categories", {}).keys()
            ),
        },
    }


# For backwards compatibility and easy access
def analyze_with_enhanced_features(
    headers: Dict[str, Any],
    subject: str,
    body: str,
    html: str,
    sender_identity: Any = None,
    threshold: float = 3.2,
) -> Dict[str, Any]:
    """
    Wrapper function that provides the enhanced analysis with all new features enabled.
    This is the recommended function for new implementations.

    Args:
        headers: Email headers dictionary
        subject: Email subject line
        body: Email body text
        html: Email HTML content
        sender_identity: Sender identity object
        threshold: Score threshold for phishing classification

    Returns:
        Comprehensive analysis with all advanced features
    """
    return advanced_analyze_with_rules(
        headers=headers,
        subject=subject,
        body=body,
        html=html,
        sender_identity=sender_identity,
        threshold=threshold,
        tuning_profile="default",
        enable_explanations=True,
    )
