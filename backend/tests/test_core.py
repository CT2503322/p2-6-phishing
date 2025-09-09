import pytest
from backend.core.keywords import find
from backend.core.whitelist import normalize_domain, load_whitelist, is_whitelisted
from backend.core.score import extract_domains, check_keywords, check_whitelist, analyze
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
    assert "score" in result
    assert "reasons" in result
    assert "meta" in result
    assert result["score"] > 0
    assert "KEYWORDS" in result["reasons"]


def test_check_whitelist():
    """Test whitelist checking."""
    from backend.core.score import wl as global_wl

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
    assert "risk" in result
    assert "label" in result
    assert "reasons" in result
    assert "meta" in result
    assert isinstance(result["risk"], float)
    assert result["label"] in ["SAFE", "PHISHING", "UNSCORED"]


def test_analyze_whitelisted():
    """Test analysis with whitelisted domain."""
    from backend.core.score import wl as global_wl

    original_wl = global_wl.copy()
    global_wl.clear()
    global_wl.add("trusted.com")

    try:
        headers = {"From": "test@trusted.com", "To": "user@domain.com"}
        subject = "Urgent account verification"
        body = "Please verify your account at https://trusted.com"
        html = ""

        result = analyze(headers, subject, body, html)
        assert result["risk"] <= 0.3  # Should be reduced due to whitelist
    finally:
        global_wl.clear()
        global_wl.update(original_wl)
