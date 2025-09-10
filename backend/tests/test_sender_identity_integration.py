"""Integration tests for sender identity functionality."""

import pytest
from pathlib import Path
from backend.ingestion.sender_identity import SenderIdentityAnalyzer
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage


class TestSenderIdentityIntegration:
    """Integration tests for sender identity analysis with real email fixtures."""

    def test_sendgrid_detection_with_tada_eml(self):
        """Test SendGrid detection using the real tada.eml fixture."""
        fixture_path = Path("backend/tests/fixtures/tada.eml")

        # Parse the email
        with open(fixture_path, "rb") as f:
            raw_content = f.read()

        parser = BytesParser(policy=policy.default)
        message = parser.parsebytes(raw_content)

        # Analyze sender identity
        analyzer = SenderIdentityAnalyzer(message)
        result = analyzer.analyze()

        # Verify SendGrid detection
        assert result.email_service_provider == "sendgrid"
        assert result.esp_confidence > 0.5  # Should have high confidence

        # Verify basic sender information
        assert result.from_address == "noreply@info.tada.global"
        assert result.from_name == "TADA"
        assert result.from_domain == "info.tada.global"

        # Verify organizational domain extraction
        assert result.organizational_domain == "tada.global"

        # Verify ESP indicators contain expected information
        indicators_str = " ".join(result.esp_indicators).lower()
        assert "sendgrid" in indicators_str or "x-sg-eid" in indicators_str

        # Verify return path domain
        assert result.return_path_domain == "em9863.info.tada.global"

    def test_auth_headers_eml_analysis(self):
        """Test analysis with auth_headers.eml fixture."""
        fixture_path = Path("backend/tests/fixtures/auth_headers.eml")

        # Parse the email
        with open(fixture_path, "rb") as f:
            raw_content = f.read()

        parser = BytesParser(policy=policy.default)
        message = parser.parsebytes(raw_content)

        # Analyze sender identity
        analyzer = SenderIdentityAnalyzer(message)
        result = analyzer.analyze()

        # Verify basic information
        assert result.from_address == "sender@example.com"
        assert result.from_domain == "example.com"
        assert result.organizational_domain == "example.com"

        # Should not detect any specific ESP (generic example.com)
        assert result.email_service_provider is None or result.esp_confidence < 0.5

        # Verify authentication results are included
        assert result.authentication_results is not None
        assert "dkim" in result.authentication_results
        assert "spf" in result.authentication_results
        assert "dmarc" in result.authentication_results

    def test_mismatch_detection_integration(self):
        """Test mismatch detection with various scenarios."""
        # Test with mismatched addresses
        from email.message import EmailMessage

        msg = EmailMessage()
        msg["From"] = "legitimate@example.com"
        msg["Reply-To"] = "phisher@evil.com"

        analyzer = SenderIdentityAnalyzer(msg)
        result = analyzer.analyze()

        assert result.has_from_reply_mismatch is True
        assert len(result.mismatch_details) > 0
        assert "Address mismatch" in " ".join(result.mismatch_details)

    def test_domain_extraction_edge_cases(self):
        """Test domain extraction with edge cases."""
        analyzer = SenderIdentityAnalyzer(EmailMessage())

        # Test domain extraction from email addresses
        email_test_cases = [
            ("user@example.com", "example.com"),
            ("test@sub.example.co.uk", "sub.example.co.uk"),
            ("admin@mail.example.org", "mail.example.org"),
            ("user@single.com", "single.com"),
        ]

        for email, expected_domain in email_test_cases:
            assert analyzer._extract_domain(email) == expected_domain

        # Test organizational domain extraction from domains
        org_cases = [
            ("mail.example.com", "example.com"),
            ("smtp.example.co.uk", "example.co.uk"),
            ("user.example.org", "example.org"),
            ("example.com", "example.com"),
            ("info.tada.global", "tada.global"),
        ]

        for domain, expected_org in org_cases:
            assert analyzer._extract_organizational_domain(domain) == expected_org


if __name__ == "__main__":
    pytest.main([__file__])
