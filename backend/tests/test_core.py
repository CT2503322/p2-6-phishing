import pytest
from backend.core.keywords import find
from backend.core.whitelist import normalize_domain, load_whitelist, is_whitelisted
from backend.core.scoring import (
    extract_domains,
    check_keywords,
    check_whitelist,
    analyze,
    analyze_with_rules,
)
from backend.utils.models import RuleScore, Label
import os
import tempfile


def test_find_keywords():
    """Test keyword detection."""
    text = "This is an urgent message about your account."
    result = find(text)
    assert len(result) > 0
    assert any(kw["keyword"] == "urgent" for kw in result)
    assert any(kw["keyword"] == "account" for kw in result)


def test_find_keywords_no_match():
    """Test keyword detection with no matches."""
    text = "This is a normal message."
    result = find(text)
    assert len(result) == 0


def test_normalize_domain():
    """Test domain normalization."""
    assert normalize_domain("www.example.com") == "example.com"
    assert normalize_domain("EXAMPLE.COM") == "example.com"
    assert normalize_domain("example.com") == "example.com"


def test_load_whitelist():
    """Test loading whitelist from file."""
    # Create a temporary whitelist file
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        f.write("example.com\ntrusted.org\n")
        temp_path = f.name

    try:
        wl = load_whitelist(temp_path)
        assert "example.com" in wl
        assert "trusted.org" in wl
        assert "untrusted.com" not in wl
    finally:
        os.unlink(temp_path)


def test_load_whitelist_nonexistent():
    """Test loading whitelist from nonexistent file."""
    wl = load_whitelist("/nonexistent/path.txt")
    assert wl == set()


def test_is_whitelisted():
    """Test whitelist checking."""
    wl = {"example.com", "trusted.org"}
    assert is_whitelisted("example.com", wl)
    assert is_whitelisted("www.example.com", wl)
    assert not is_whitelisted("untrusted.com", wl)


def test_extract_domains():
    """Test domain extraction from text."""
    text = "Visit https://example.com and http://trusted.org/page"
    domains = extract_domains(text)
    assert "example.com" in domains
    assert "trusted.org" in domains


def test_check_keywords():
    """Test keyword checking."""
    subject = "Urgent action required"
    body = "Your account needs verification."
    result = check_keywords(subject, body)
    assert "meta" in result


def test_check_whitelist():
    """Test whitelist checking."""
    from backend.core.scoring import wl as global_wl

    original_wl = global_wl.copy()
    global_wl.clear()
    global_wl.add("trusted.com")

    try:
        subject = ""
        body = "Check this link: https://trusted.com"
        html = ""
        result = check_whitelist(subject, body, html)
        assert result["whitelisted"] is True
        assert "WHITELISTED" in result["reasons"]
    finally:
        global_wl.clear()
        global_wl.update(original_wl)


def test_analyze():
    """Test full analysis."""
    headers = {"From": "test@example.com", "To": "user@domain.com"}
    subject = "Urgent account verification"
    body = "Please verify your account at https://trusted.com"
    html = ""

    result = analyze(headers, subject, body, html)
    assert "reasons" in result
    assert "meta" in result


def test_analyze_whitelisted():
    """Test analysis with whitelisted domain."""
    from backend.core.scoring import wl as global_wl

    original_wl = global_wl.copy()
    global_wl.clear()
    global_wl.add("trusted.com")

    try:
        headers = {"From": "test@trusted.com", "To": "user@domain.com"}
        subject = "Urgent account verification"
        body = "Please verify your account at https://trusted.com"
        html = ""

        result = analyze(headers, subject, body, html)
        assert "WHITELISTED" in result["reasons"]
    finally:
        global_wl.clear()
        global_wl.update(original_wl)


def test_analyze_html_preview_and_text():
    """Test that html_preview and html_text are properly generated."""
    headers = {"From": "test@example.com", "To": "user@domain.com"}
    subject = "Test subject"
    body = "Test body"
    html = "<html><body><h1>Test HTML</h1><p>This is a test with lots of content that should be truncated in preview but available in full text.</p></body></html>"

    result = analyze(headers, subject, body, html)

    # Check that both html_preview and html_text are present
    assert "html_preview" in result["meta"]
    assert "html_text" in result["meta"]

    # html_preview should be truncated (500 chars + "...")
    html_preview = result["meta"]["html_preview"]
    assert len(html_preview) <= 503  # 500 + "..."
    if len(result["meta"]["html_text"]) > 500:
        assert html_preview.endswith("...")

    # html_text should contain the full content
    html_text = result["meta"]["html_text"]
    assert (
        html_text
        == "Test HTMLThis is a test with lots of content that should be truncated in preview but available in full text."
    )

    # html_text should be longer than or equal to html_preview (excluding "...")
    assert len(html_text) >= len(html_preview.rstrip("..."))


def test_analyze_with_rules_basic():
    """Test the new rule-based scoring system."""
    headers = {"From": "test@example.com", "To": "user@domain.com"}
    subject = "Urgent account verification"
    body = "Please verify your account at https://trusted.com/urgent"
    html = "<html><body><script>alert('test')</script></body></html>"

    result = analyze_with_rules(headers, subject, body, html)
    assert "scored_analysis" in result
    assert "score_total" in result
    assert "label" in result
    assert isinstance(result["score_total"], float)
    assert result["label"] in ["SAFE", "PHISHING"]


def test_rule_score_creation():
    """Test RuleScore object creation and validation."""
    rule = RuleScore(
        rule="url_shortener", delta=1.0, evidence="Found bit.ly shortener URL"
    )
    assert rule.rule == "url_shortener"
    assert rule.delta == 1.0
    assert rule.evidence == "Found bit.ly shortener URL"


def test_punycode_url_rule():
    """Test punycode URL detection rule."""
    headers = {"From": "test@example.com"}
    subject = "Update required"
    body = "Check this: https://xn--paypal-secure.com"
    html = ""

    result = analyze_with_rules(headers, subject, body, html)
    breakdown = result["scored_analysis"]["score_breakdown"]

    # Should contain punycode rule
    punycode_rules = [r for r in breakdown if r["rule"] == "url_punycode"]
    assert len(punycode_rules) > 0
    assert punycode_rules[0]["delta"] == 2.0
    assert "xn--paypal-secure.com" in punycode_rules[0]["evidence"]


def test_ip_literal_url_rule():
    """Test IP literal URL detection rule."""
    headers = {"From": "test@example.com"}
    subject = "Important update"
    body = "Visit http://192.168.1.1/malicious"
    html = ""

    result = analyze_with_rules(headers, subject, body, html)
    breakdown = result["scored_analysis"]["score_breakdown"]

    # Should contain IP literal rule
    ip_rules = [r for r in breakdown if r["rule"] == "url_ip_literal"]
    assert len(ip_rules) > 0
    assert ip_rules[0]["delta"] == 1.5
    assert "192.168.1.1" in ip_rules[0]["evidence"]


def test_url_shortener_rule():
    """Test URL shortener detection rule."""
    headers = {"From": "test@example.com"}
    subject = "Click here"
    body = "Check this: https://bit.ly/123"
    html = ""

    result = analyze_with_rules(headers, subject, body, html)
    breakdown = result["scored_analysis"]["score_breakdown"]

    # Should contain URL shortener rule
    shortener_rules = [r for r in breakdown if r["rule"] == "url_shortener"]
    assert len(shortener_rules) > 0
    assert shortener_rules[0]["delta"] == 1.0
    assert "bit.ly" in shortener_rules[0]["evidence"]


def test_javascript_injection_rule():
    """Test JavaScript injection detection rule."""
    headers = {"From": "test@example.com"}
    subject = "Update your account"
    body = "Please login"
    html = "<html><head><script>alert('malicious')</script></head><body></body></html>"

    result = analyze_with_rules(headers, subject, body, html)
    breakdown = result["scored_analysis"]["score_breakdown"]

    # Should contain JavaScript injection rule
    js_rules = [r for r in breakdown if r["rule"] == "javascript_injection"]
    assert len(js_rules) > 0
    assert js_rules[0]["delta"] == 2.5
    assert "JavaScript code detected" in js_rules[0]["evidence"]


def test_high_urgency_rule():
    """Test high urgency keywords rule."""
    headers = {"From": "test@example.com"}
    subject = "URGENT ACTION REQUIRED NOW"
    body = "Your account needs immediate verification"
    html = ""

    result = analyze_with_rules(headers, subject, body, html)
    breakdown = result["scored_analysis"]["score_breakdown"]

    # Should contain high urgency rule
    urgency_rules = [r for r in breakdown if r["rule"] == "high_urgency"]
    assert len(urgency_rules) > 0
    assert urgency_rules[0]["delta"] == 1.5
    assert "High urgency pattern" in urgency_rules[0]["evidence"]


def test_excessive_exclamation_rule():
    """Test excessive exclamation marks rule."""
    headers = {"From": "test@example.com"}
    subject = "Alert!!!"
    body = "This is very important!!!! You need to act now!!!!!"
    html = ""

    result = analyze_with_rules(headers, subject, body, html)
    breakdown = result["scored_analysis"]["score_breakdown"]

    # Should contain excessive exclamation rule
    exclamation_rules = [r for r in breakdown if r["rule"] == "excessive_exclamation"]
    assert len(exclamation_rules) > 0
    assert exclamation_rules[0]["delta"] == 0.5


def test_keyword_frenzy_rule():
    """Test keyword frenzy rule aggregation."""
    headers = {"From": "test@example.com"}
    subject = "Urgent security warning"
    body = "Your bank account has been compromised"
    html = ""

    result = analyze_with_rules(headers, subject, body, html)
    breakdown = result["scored_analysis"]["score_breakdown"]

    # Should contain keyword frenzy rule
    keyword_rules = [r for r in breakdown if r["rule"] == "keyword_frenzy"]
    assert len(keyword_rules) > 0
    assert keyword_rules[0]["delta"] > 0
    assert "Keyword analysis score" in keyword_rules[0]["evidence"]


def test_phishing_score_calculation():
    """Test that phishing scores are calculated correctly."""
    headers = {"From": "test@bad-domain.com"}
    subject = "URGENT SECURITY ALERT!!!"
    body = "Your account has been hacked! Visit https://xn--badsite.com now!!!"
    html = "<script>document.location='https://xn--badsite.com'</script>"

    result = analyze_with_rules(headers, subject, body, html)
    score_total = result["score_total"]
    label = result["label"]

    # Score should be relatively high due to multiple violations
    assert score_total > 5.0  # Punycode + JS injection + high urgency + exclamation

    # Should be classified as phishing
    assert label == "PHISHING"

    # Check threshold logic
    assert result["scored_analysis"]["threshold_used"] == 3.2


def test_safe_email_scoring():
    """Test that safe emails get low scores."""
    headers = {"From": "support@trusted-company.com"}
    subject = "Regular newsletter"
    body = "Here's this month's update from our company."
    html = "<html><body><p>This is a legitimate email.</p></body></html>"

    result = analyze_with_rules(headers, subject, body, html)
    score_total = result["score_total"]
    label = result["label"]

    # Score should be low
    assert score_total < 3.0

    # Should be classified as safe
    assert label == "SAFE"


def test_scored_analysis_structure():
    """Test that ScoredAnalysis structure is correct."""
    headers = {"From": "test@example.com"}
    subject = "Test"
    body = "Visit https://test.com"
    html = ""

    result = analyze_with_rules(headers, subject, body, html)
    scored_analysis = result["scored_analysis"]

    # Check required fields are present
    required_fields = [
        "score_breakdown",
        "score_total",
        "label",
        "threshold_used",
        "tuning_profile",
    ]
    for field in required_fields:
        assert field in scored_analysis

    # Check score breakdown structure
    breakdown = scored_analysis["score_breakdown"]
    assert isinstance(breakdown, list)
    if len(breakdown) > 0:
        rule = breakdown[0]
        required_rule_fields = ["rule", "delta", "evidence"]
        for field in required_rule_fields:
            assert field in rule
