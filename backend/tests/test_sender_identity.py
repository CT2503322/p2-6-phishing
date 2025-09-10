import pytest
from email.message import EmailMessage
from backend.ingestion.sender_identity import SenderIdentityAnalyzer, SenderIdentity


class TestSenderIdentityAnalyzer:
    """Test cases for SenderIdentityAnalyzer."""

    def test_basic_sender_extraction(self):
        """Test basic From and Reply-To extraction."""
        msg = EmailMessage()
        msg["From"] = "John Doe <john@example.com>"
        msg["Reply-To"] = "Jane Smith <jane@example.com>"

        analyzer = SenderIdentityAnalyzer(msg)
        result = analyzer.analyze()

        assert result.from_address == "john@example.com"
        assert result.from_name == "John Doe"
        assert result.reply_to_address == "jane@example.com"
        assert result.reply_to_name == "Jane Smith"

    def test_domain_extraction(self):
        """Test domain extraction from email addresses."""
        msg = EmailMessage()
        msg["From"] = "user@subdomain.example.com"
        msg["Reply-To"] = "reply@test.org"

        analyzer = SenderIdentityAnalyzer(msg)
        result = analyzer.analyze()

        assert result.from_domain == "subdomain.example.com"
        assert result.reply_to_domain == "test.org"

    def test_organizational_domain_extraction(self):
        """Test organizational domain extraction."""
        analyzer = SenderIdentityAnalyzer(EmailMessage())

        # Test .com domain
        assert (
            analyzer._extract_organizational_domain("mail.example.com") == "example.com"
        )
        assert (
            analyzer._extract_organizational_domain("sub.mail.example.com")
            == "example.com"
        )

        # Test .org domain
        assert analyzer._extract_organizational_domain("info.test.org") == "test.org"

        # Test country TLD
        assert (
            analyzer._extract_organizational_domain("user.example.co.uk")
            == "example.co.uk"
        )

        # Test single level domain
        assert analyzer._extract_organizational_domain("example.com") == "example.com"

    def test_sendgrid_detection(self):
        """Test SendGrid ESP detection."""
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["Return-Path"] = "<bounces+123@example.sendgrid.net>"
        msg["X-SG-EID"] = "some_value"
        msg["DKIM-Signature"] = "v=1; d=sendgrid.info; s=s1;"

        analyzer = SenderIdentityAnalyzer(msg)
        result = analyzer.analyze()

        assert result.email_service_provider == "sendgrid"
        assert result.esp_confidence > 0
        assert any("X-SG-EID" in indicator for indicator in result.esp_indicators)

    def test_gmail_detection(self):
        """Test Gmail ESP detection."""
        msg = EmailMessage()
        msg["From"] = "user@gmail.com"
        msg["X-Google-Smtp-Source"] = "some_value"

        analyzer = SenderIdentityAnalyzer(msg)
        result = analyzer.analyze()

        assert result.email_service_provider == "gmail"
        assert result.esp_confidence > 0

    def test_mismatch_detection_address(self):
        """Test From/Reply-To address mismatch detection."""
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["Reply-To"] = "different@other.com"

        analyzer = SenderIdentityAnalyzer(msg)
        result = analyzer.analyze()

        assert result.has_from_reply_mismatch is True
        assert any("Address mismatch" in detail for detail in result.mismatch_details)

    def test_mismatch_detection_domain(self):
        """Test From/Reply-To domain mismatch detection."""
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["Reply-To"] = "sender@other.com"

        analyzer = SenderIdentityAnalyzer(msg)
        result = analyzer.analyze()

        assert result.has_from_reply_mismatch is True
        assert any("Domain mismatch" in detail for detail in result.mismatch_details)
        assert any("Potential spoofing" in detail for detail in result.mismatch_details)

    def test_no_mismatch(self):
        """Test when From and Reply-To match."""
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["Reply-To"] = "sender@example.com"

        analyzer = SenderIdentityAnalyzer(msg)
        result = analyzer.analyze()

        assert result.has_from_reply_mismatch is False
        assert len(result.mismatch_details) == 0

    def test_sending_ip_extraction(self):
        """Test sending IP extraction from Received headers."""
        msg = EmailMessage()
        msg["Received"] = "from mail.example.com ([192.168.1.100]) by mx.google.com"

        analyzer = SenderIdentityAnalyzer(msg)
        result = analyzer.analyze()

        assert result.sending_ip == "192.168.1.100"

    def test_return_path_domain_extraction(self):
        """Test return path domain extraction."""
        msg = EmailMessage()
        msg["Return-Path"] = "<bounces@example.com>"

        analyzer = SenderIdentityAnalyzer(msg)
        result = analyzer.analyze()

        assert result.return_path_domain == "example.com"

    def test_empty_headers(self):
        """Test handling of missing headers."""
        msg = EmailMessage()

        analyzer = SenderIdentityAnalyzer(msg)
        result = analyzer.analyze()

        assert result.from_address is None
        assert result.from_domain is None
        assert result.email_service_provider is None
        assert result.esp_confidence == 0.0
        assert result.has_from_reply_mismatch is False

    def test_multiple_esp_headers(self):
        """Test handling multiple ESP indicators."""
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["X-SG-EID"] = "sendgrid_value"
        msg["X-SG-ID"] = "sendgrid_id"
        msg["DKIM-Signature"] = "v=1; d=sendgrid.info; s=s1;"

        analyzer = SenderIdentityAnalyzer(msg)
        result = analyzer.analyze()

        assert result.email_service_provider == "sendgrid"
        assert (
            result.esp_confidence > 0.5
        )  # Should have high confidence with multiple indicators

    def test_esp_confidence_scoring(self):
        """Test ESP confidence scoring."""
        msg = EmailMessage()
        msg["From"] = "sender@example.com"
        msg["X-SG-EID"] = "value"  # +3 points

        analyzer = SenderIdentityAnalyzer(msg)
        result = analyzer.analyze()

        # Single header should give moderate confidence
        assert 0.2 < result.esp_confidence < 0.5

    def test_malformed_email_addresses(self):
        """Test handling of malformed email addresses."""
        msg = EmailMessage()
        msg["From"] = "invalid-email-address"
        msg["Reply-To"] = "also@invalid"

        analyzer = SenderIdentityAnalyzer(msg)
        result = analyzer.analyze()

        # Should handle gracefully without crashing
        # Note: "invalid" is technically a valid domain part
        assert result.from_domain is None  # No @ in from address
        assert result.reply_to_domain == "invalid"  # Valid domain extraction

    def test_case_insensitive_domain_extraction(self):
        """Test that domain extraction is case insensitive."""
        msg = EmailMessage()
        msg["From"] = "User@Example.COM"

        analyzer = SenderIdentityAnalyzer(msg)
        result = analyzer.analyze()

        assert result.from_domain == "example.com"


class TestSenderIdentityDataClass:
    """Test cases for SenderIdentity dataclass."""

    def test_dataclass_initialization(self):
        """Test SenderIdentity dataclass initialization."""
        identity = SenderIdentity(
            from_address="test@example.com",
            from_name="Test User",
            email_service_provider="gmail",
            esp_confidence=0.8,
        )

        assert identity.from_address == "test@example.com"
        assert identity.from_name == "Test User"
        assert identity.email_service_provider == "gmail"
        assert identity.esp_confidence == 0.8
        assert identity.esp_indicators == []  # Should be initialized in __post_init__
        assert identity.mismatch_details == []

    def test_dataclass_defaults(self):
        """Test SenderIdentity default values."""
        identity = SenderIdentity()

        assert identity.from_address is None
        assert identity.email_service_provider is None
        assert identity.esp_confidence == 0.0
        assert identity.has_from_reply_mismatch is False
        assert identity.esp_indicators == []
        assert identity.mismatch_details == []
        assert identity.authentication_results == {}


if __name__ == "__main__":
    pytest.main([__file__])
