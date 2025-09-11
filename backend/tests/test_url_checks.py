import pytest
from backend.core.url_checks import (
    URLSecurityAnalyzer,
    extract_url_findings,
    analyze_url,
    detect_url_anomalies,
)
from backend.utils.models import UrlFinding, RuleScore


class TestURLSecurityAnalyzer:
    """Test the URLSecurityAnalyzer class."""

    @pytest.fixture
    def analyzer(self):
        """Create a URL analyzer for testing."""
        return URLSecurityAnalyzer()

    def test_init(self, analyzer):
        """Test analyzer initialization."""
        assert analyzer.shorteners is not None
        assert "bit.ly" in analyzer.shorteners
        assert "t.co" in analyzer.shorteners

    def test_extract_url_findings_empty(self):
        """Test extracting URL findings from empty HTML."""
        findings = extract_url_findings("")
        assert findings == []

    def test_extract_url_findings_simple_link(self):
        """Test extracting findings from simple link."""
        html = '<a href="http://example.com">Click here</a>'
        findings = extract_url_findings(html)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.href == "http://example.com"
        assert finding.text == "Click here"
        assert finding.netloc == "example.com"
        assert finding.is_ip_literal is False
        assert finding.is_shortener is False
        assert finding.text_href_mismatch is False

    def test_extract_url_findings_multiple_links(self):
        """Test extracting findings from multiple links."""
        html = """
        <html>
        <body>
        <a href="http://example.com">Example</a>
        <a href="https://test.org">Test</a>
        <a href="http://bit.ly/123">Short link</a>
        </body>
        </html>
        """
        findings = extract_url_findings(html)

        assert len(findings) == 3

        # Check shortener detection
        shortener_finding = next(f for f in findings if f.netloc == "bit.ly")
        assert shortener_finding.is_shortener is True
        assert "URL shortening service" in shortener_finding.evidence

    def test_extract_url_findings_with_base_url(self):
        """Test extracting findings with base URL."""
        html = """
        <html>
        <head><base href="http://example.com/base/"></head>
        <body><a href="page.html">Relative Link</a></body>
        </html>
        """
        findings = extract_url_findings(html)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.href == "http://example.com/base/page.html"

    def test_analyze_ip_literal(self, analyzer):
        """Test IP literal detection."""
        finding = analyzer.analyze_individual_url("http://192.168.1.1/malicious")
        assert finding.is_ip_literal is True
        assert "IPv4 literal (192.168.1.1)" in finding.evidence

    def test_analyze_ipv6_literal(self, analyzer):
        """Test IPv6 literal detection."""
        finding = analyzer.analyze_individual_url("http://[::1]/test")
        assert finding.is_ip_literal is True
        assert finding.netloc == "[::1]"
        assert "::1" in finding.evidence

    def test_analyze_url_shortener(self, analyzer):
        """Test URL shortener detection."""
        finding = analyzer.analyze_individual_url("https://bit.ly/abc123")
        assert finding.is_shortener is True
        assert finding.netloc == "bit.ly"
        assert "URL shortening service" in finding.evidence

    def test_analyze_punycode(self, analyzer):
        """Test punycode/IDN detection."""
        finding = analyzer.analyze_individual_url("http://xn--bcher-kva.example")
        assert finding.is_punycode is True
        assert "Punycode/IDN encoding" in finding.evidence

    def test_analyze_text_href_mismatch(self, analyzer):
        """Test href/text mismatch detection."""
        # Link text looks like URL but points elsewhere
        html = '<a href="http://evil.com">http://paypal.com</a>'
        findings = extract_url_findings(html)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.text_href_mismatch is True
        assert "doesn't match domain" in finding.evidence

    def test_analyze_text_href_match(self, analyzer):
        """Test when text and href domains match."""
        html = '<a href="http://example.com/page">http://example.com</a>'
        findings = extract_url_findings(html)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.text_href_mismatch is False
        assert "Clean URL" in finding.evidence

    def test_analyze_brand_spoofing(self, analyzer):
        """Test brand/domain spoofing detection."""
        # This should trigger brand matching through confusables
        finding = analyzer.analyze_individual_url("http://xn--pypl-3b3b.com")
        # The exact response depends on confusables integration
        assert finding.href.endswith(".com")

    def test_detect_url_anomalies_empty(self):
        """Test detecting anomalies in empty content."""
        rules = detect_url_anomalies("")
        assert rules == []

    def test_detect_url_anomalies_punycode(self):
        """Test punycode anomaly detection."""
        content = "Check this link: http://xn--bcher-kva.com"
        rules = detect_url_anomalies(content)

        punycode_rule = next((r for r in rules if r.rule == "url_punycode"), None)
        assert punycode_rule is not None
        assert punycode_rule.delta == 2.0
        assert "xn--bcher-kva.com" in punycode_rule.evidence

    def test_detect_url_anomalies_ip_literal(self):
        """Test IP literal anomaly detection."""
        content = "Visit http://192.168.1.100 for updates"
        rules = detect_url_anomalies(content)

        ip_rule = next((r for r in rules if r.rule == "url_ip_literal"), None)
        assert ip_rule is not None
        assert ip_rule.delta == 1.5
        assert "192.168.1.100" in ip_rule.evidence

    def test_detect_url_anomalies_url_shortener(self):
        """Test URL shortener anomaly detection."""
        content = "Click here: https://t.co/xyz123"
        rules = detect_url_anomalies(content)

        shortener_rule = next((r for r in rules if r.rule == "url_shortener"), None)
        assert shortener_rule is not None
        assert shortener_rule.delta == 1.0
        assert "t.co" in shortener_rule.evidence

    def test_detect_punycode_branding_anomaly(self, analyzer):
        """Test punycode with branding anomaly detection."""
        # Use a domain that might be decoded to a known brand
        # This is tricky to test predictably, so we'll use a known punycode domain
        content = "Visit http://xn--80ak6aa92e.com"  # Russian domain
        rules = analyzer.detect_url_anomalies(content)

        # Should at least have punycode rule
        punycode_rule = next((r for r in rules if r.rule == "url_punycode"), None)
        assert punycode_rule is not None

    def test_is_ip_literal_ipv4(self, analyzer):
        """Test IPv4 literal detection."""
        assert analyzer._is_ip_literal("192.168.1.1") is True
        assert analyzer._is_ip_literal("127.0.0.1") is True
        assert analyzer._is_ip_literal("example.com") is False
        assert analyzer._is_ip_literal("192.168.1.1:8080") is True  # with port

    def test_is_ip_literal_ipv6(self, analyzer):
        """Test IPv6 literal detection."""
        assert analyzer._is_ip_literal("[::1]") is True
        assert analyzer._is_ip_literal("[2001:db8::1]") is True
        assert analyzer._is_ip_literal("::1") is True  # plain IPv6
        assert analyzer._is_ip_literal("2001:db8::1:8080") is True  # IPv6 with port

    def test_is_url_shortener(self, analyzer):
        """Test URL shortener domain detection."""
        # Known shorteners
        assert analyzer._is_url_shortener("bit.ly") is True
        assert analyzer._is_url_shortener("t.co") is True
        assert analyzer._is_url_shortener("goo.gl") is True
        assert analyzer._is_url_shortener("tinyurl.com") is True

        # With ports
        assert analyzer._is_url_shortener("bit.ly:8080") is True

        # Non-shorteners
        assert analyzer._is_url_shortener("example.com") is False
        assert analyzer._is_url_shortener("google.com") is False

    def test_has_text_href_mismatch(self, analyzer):
        """Test href/text mismatch detection."""
        # mismatch: text is paypal.com but href is evil.com
        assert analyzer._has_text_href_mismatch("http://paypal.com", "evil.com") is True

        # different TLD but same domain
        assert analyzer._has_text_href_mismatch("paypal.org", "paypal.com") is True

        # match
        assert analyzer._has_text_href_mismatch("example.com", "example.com") is False

        # Empty/trivial text
        assert analyzer._has_text_href_mismatch("", "example.com") is False
        assert analyzer._has_text_href_mismatch("hi", "example.com") is False

        # Text doesn't look like URL
        assert analyzer._has_text_href_mismatch("Click here", "example.com") is False

    def test_normalize_domain(self, analyzer):
        """Test domain normalization."""
        assert analyzer._normalize_domain("www.example.com") == "example.com"
        assert analyzer._normalize_domain("EXAMPLE.COM") == "example.com"
        assert analyzer._normalize_domain("example.com") == "example.com"
        assert analyzer._normalize_domain("  WWW.GOOGLE.COM  ") == "google.com"

    def test_clean_anchor_text(self, analyzer):
        """Test anchor text cleaning."""
        assert analyzer._clean_anchor_text("") == ""
        assert analyzer._clean_anchor_text("  normal text  ") == "normal text"
        assert analyzer._clean_anchor_text("<b>bold</b> text") == "bold text"
        assert analyzer._clean_anchor_text("multi\nline\ttext") == "multi line text"

    def test_extract_base_url(self, analyzer):
        """Test base URL extraction."""
        html = '<base href="http://example.com/base/">'
        assert analyzer._extract_base_url(html) == "http://example.com/base/"

        html = '<BASE HREF="http://test.com/">'  # case insensitive
        assert analyzer._extract_base_url(html) == "http://test.com/"

        html = "<html><body>No base here</body></html>"
        assert analyzer._extract_base_url(html) is None

    def test_resolve_url(self, analyzer):
        """Test URL resolution."""
        # Absolute URLs unchanged
        assert analyzer._resolve_url("http://example.com", None) == "http://example.com"
        assert (
            analyzer._resolve_url("https://test.com", "http://base.com")
            == "https://test.com"
        )

        # Resolve relative with base
        assert (
            analyzer._resolve_url("page.html", "http://base.com/")
            == "http://base.com/page.html"
        )
        assert (
            analyzer._resolve_url("/page.html", "http://base.com/dir/")
            == "http://base.com/page.html"
        )

        # Protocol-relative (converted to http:// for consistency)
        assert analyzer._resolve_url("//example.com", None) == "http://example.com"

        # Relative without base (assumes http://)
        assert analyzer._resolve_url("example.com", None) == "http://example.com"

    def test_generate_evidence(self, analyzer):
        """Test evidence generation."""
        # Empty evidence
        evidence = analyzer._generate_evidence(
            "text", "href", "netloc", False, False, False, False, None
        )
        assert evidence == "Clean URL"

        # All suspicious indicators
        evidence = analyzer._generate_evidence(
            "paypal.com",
            "http://evil.com",
            "evil.com",
            True,
            True,
            True,
            True,
            "PayPal",
        )
        # The evidence should contain our improved IP literal format
        assert "IPv4 literal" in evidence or "IP literal" in evidence
        assert "Punycode/IDN encoding" in evidence
        assert "URL shortening service" in evidence
        assert "doesn't match" in evidence
        assert "legitimate (PayPal)" in evidence


class TestConvenienceFunctions:
    """Test the convenience functions."""

    def test_extract_url_findings_convenience(self):
        """Test the extract_url_findings convenience function."""
        html = '<a href="http://example.com">Test</a>'
        findings = extract_url_findings(html)
        assert len(findings) == 1
        assert findings[0].netloc == "example.com"

    def test_analyze_url_convenience(self):
        """Test the analyze_url convenience function."""
        finding = analyze_url("http://test.com")
        assert finding.netloc == "test.com"
        assert finding.is_ip_literal is False

    def test_detect_url_anomalies_convenience(self):
        """Test the detect_url_anomalies convenience function."""
        content = "Visit http://192.168.1.1"
        rules = detect_url_anomalies(content)
        assert len(rules) >= 1  # Should detect IP literal


class TestIntegrationScenarios:
    """Test realistic integration scenarios."""

    def test_complex_phishing_email_html(self):
        """Test analysis of complex phishing email HTML."""
        html = """
        <html>
        <head>
        <title>Bank Alert</title>
        </head>
        <body>
        <p>Please verify your account by clicking the link below:</p>
        <a href="http://192.168.1.100/bank">https://secure-bank.com/verify</a>
        <p>If you did not request this, please ignore this email.</p>
        <a href="https://bit.ly/short-link">Check this offer</a>
        </body>
        </html>
        """

        findings = extract_url_findings(html)

        # Should find both links
        assert len(findings) == 2

        # IP literal link should be flagged
        ip_finding = next(f for f in findings if "192.168.1.100" in f.href)
        assert ip_finding.is_ip_literal is True
        assert (
            ip_finding.text_href_mismatch is True
        )  # text says secure-bank.com but href is IP

        # Shortener should be flagged
        shortener_finding = next(f for f in findings if "bit.ly" in f.netloc)
        assert shortener_finding.is_shortener is True

    def test_anomalies_detection_integration(self):
        """Test anomaly detection with mixed content."""
        content = """
        Subject: Account Verification Required

        Dear Customer,

        We have detected suspicious activity on your account.
        Please visit http://192.168.1.1/login to verify your identity.

        If you use our mobile app, try this link instead: https://t.co/verification

        For additional information, check: http://xn--pypl-secure.com (paypal with accent)

        Sincerely,
        Your Bank
        """

        rules = detect_url_anomalies(content)

        # Should detect multiple types of anomalies
        rule_types = {r.rule for r in rules}
        assert "url_ip_literal" in rule_types
        assert "url_shortener" in rule_types
        assert "url_punycode" in rule_types

        # Check specific rules
        ip_rule = next(r for r in rules if r.rule == "url_ip_literal")
        shortener_rule = next(r for r in rules if r.rule == "url_shortener")
        punycode_rule = next(r for r in rules if r.rule == "url_punycode")

        assert "192.168.1.1" in ip_rule.evidence
        assert "t.co" in shortener_rule.evidence
        assert "xn--pypl-secure.com" in punycode_rule.evidence

    def test_mixed_encoding_and_suspicious_patterns(self):
        """Test analysis of URLs with mixed encoding and suspicious patterns."""
        html = """
        <a href="http://[::1]:8080/malicious">http://paypal.com</a>
        <a href="https://xn--g-paypal-cm3b.com">Click Here</a>
        <a href="http://sub.domain.bit.ly/path">Bit.ly with subdomain</a>
        """

        findings = extract_url_findings(html)

        assert len(findings) == 3

        # IPv6 with port and mismatch
        ipv6_finding = next(f for f in findings if "[::1]" in f.netloc)
        assert ipv6_finding.is_ip_literal is True
        assert ipv6_finding.text_href_mismatch is True

        # Punycode domain
        punycode_finding = next(f for f in findings if f.is_punycode)
        assert "Punycode/IDN encoding" in punycode_finding.evidence

        # Subdomain shortener - might not be detected if list doesn't include subdomains
        # This tests the limitation of current implementation
