import pytest
from email.message import EmailMessage
from backend.ingestion.addresses import AddressUtils


class TestAddressUtils:
    """Test cases for AddressUtils class."""

    def test_get_from(self):
        """Test getting From header."""
        msg = EmailMessage()
        msg["From"] = "test@example.com"
        addr_utils = AddressUtils(msg)
        assert addr_utils.get_from() == "test@example.com"

    def test_get_from_with_name(self):
        """Test getting From header with name."""
        msg = EmailMessage()
        msg["From"] = "John Doe <john@example.com>"
        addr_utils = AddressUtils(msg)
        assert addr_utils.get_from() == "John Doe <john@example.com>"

    def test_get_from_none(self):
        """Test getting From header when not present."""
        msg = EmailMessage()
        addr_utils = AddressUtils(msg)
        assert addr_utils.get_from() is None

    def test_get_to_multiple(self):
        """Test getting To header with multiple addresses."""
        msg = EmailMessage()
        msg["To"] = "alice@example.com, Bob Smith <bob@example.com>"
        addr_utils = AddressUtils(msg)
        assert addr_utils.get_to() == "alice@example.com, Bob Smith <bob@example.com>"

    def test_get_cc(self):
        """Test getting Cc header."""
        msg = EmailMessage()
        msg["Cc"] = "cc@example.com"
        addr_utils = AddressUtils(msg)
        assert addr_utils.get_cc() == "cc@example.com"

    def test_get_bcc(self):
        """Test getting Bcc header."""
        msg = EmailMessage()
        msg["Bcc"] = "bcc@example.com"
        addr_utils = AddressUtils(msg)
        assert addr_utils.get_bcc() == "bcc@example.com"

    def test_get_reply_to(self):
        """Test getting Reply-To header."""
        msg = EmailMessage()
        msg["Reply-To"] = "reply@example.com"
        addr_utils = AddressUtils(msg)
        assert addr_utils.get_reply_to() == "reply@example.com"

    def test_get_from_emails_simple(self):
        """Test getting emails from From header."""
        msg = EmailMessage()
        msg["From"] = "test@example.com"
        addr_utils = AddressUtils(msg)
        assert addr_utils.get_from_emails() == ["test@example.com"]

    def test_get_from_emails_with_name(self):
        """Test getting emails from From header with name."""
        msg = EmailMessage()
        msg["From"] = "John Doe <john@example.com>"
        addr_utils = AddressUtils(msg)
        assert addr_utils.get_from_emails() == ["john@example.com"]

    def test_get_from_emails_multiple(self):
        """Test getting emails from multiple From addresses."""
        msg = EmailMessage()
        msg["From"] = '"Smith, John" <john@example.com>, jane@example.com'
        addr_utils = AddressUtils(msg)
        emails = addr_utils.get_from_emails()
        assert "john@example.com" in emails
        assert "jane@example.com" in emails
        assert len(emails) == 2

    def test_get_from_emails_empty(self):
        """Test getting emails from empty From header."""
        msg = EmailMessage()
        addr_utils = AddressUtils(msg)
        assert addr_utils.get_from_emails() == []

    def test_get_to_emails(self):
        """Test getting emails from To header."""
        msg = EmailMessage()
        msg["To"] = "alice@example.com, Bob Smith <bob@example.com>"
        addr_utils = AddressUtils(msg)
        emails = addr_utils.get_to_emails()
        assert "alice@example.com" in emails
        assert "bob@example.com" in emails
        assert len(emails) == 2

    def test_get_cc_emails(self):
        """Test getting emails from Cc header."""
        msg = EmailMessage()
        msg["Cc"] = "cc1@example.com, CC Two <cc2@example.com>"
        addr_utils = AddressUtils(msg)
        emails = addr_utils.get_cc_emails()
        assert "cc1@example.com" in emails
        assert "cc2@example.com" in emails
        assert len(emails) == 2

    def test_get_bcc_emails(self):
        """Test getting emails from Bcc header."""
        msg = EmailMessage()
        msg["Bcc"] = "bcc@example.com"
        addr_utils = AddressUtils(msg)
        assert addr_utils.get_bcc_emails() == ["bcc@example.com"]

    def test_get_reply_to_emails(self):
        """Test getting emails from Reply-To header."""
        msg = EmailMessage()
        msg["Reply-To"] = "reply@example.com"
        addr_utils = AddressUtils(msg)
        assert addr_utils.get_reply_to_emails() == ["reply@example.com"]

    def test_get_from_names(self):
        """Test getting names from From header."""
        msg = EmailMessage()
        msg["From"] = "John Doe <john@example.com>, Jane Smith <jane@example.com>"
        addr_utils = AddressUtils(msg)
        names = addr_utils.get_from_names()
        assert "John Doe" in names
        assert "Jane Smith" in names

    def test_get_to_names(self):
        """Test getting names from To header."""
        msg = EmailMessage()
        msg["To"] = "Alice <alice@example.com>, bob@example.com"
        addr_utils = AddressUtils(msg)
        names = addr_utils.get_to_names()
        assert "Alice" in names
        assert "" in names  # bob@example.com has no name

    def test_get_from_parsed(self):
        """Test getting parsed From header."""
        msg = EmailMessage()
        msg["From"] = "John Doe <john@example.com>"
        addr_utils = AddressUtils(msg)
        parsed = addr_utils.get_from_parsed()
        assert parsed == ("John Doe", "john@example.com")

    def test_get_from_parsed_simple(self):
        """Test getting parsed From header without name."""
        msg = EmailMessage()
        msg["From"] = "simple@example.com"
        addr_utils = AddressUtils(msg)
        parsed = addr_utils.get_from_parsed()
        assert parsed == ("", "simple@example.com")

    def test_get_from_parsed_empty(self):
        """Test getting parsed From header when empty."""
        msg = EmailMessage()
        addr_utils = AddressUtils(msg)
        assert addr_utils.get_from_parsed() is None

    def test_get_to_parsed(self):
        """Test getting parsed To header."""
        msg = EmailMessage()
        msg["To"] = "Alice <alice@example.com>, bob@example.com"
        addr_utils = AddressUtils(msg)
        parsed = addr_utils.get_to_parsed()
        assert ("Alice", "alice@example.com") in parsed
        assert ("", "bob@example.com") in parsed

    def test_get_cc_parsed(self):
        """Test getting parsed Cc header."""
        msg = EmailMessage()
        msg["Cc"] = "CC Person <cc@example.com>"
        addr_utils = AddressUtils(msg)
        parsed = addr_utils.get_cc_parsed()
        assert parsed == [("CC Person", "cc@example.com")]

    def test_get_bcc_parsed(self):
        """Test getting parsed Bcc header."""
        msg = EmailMessage()
        msg["Bcc"] = "bcc@example.com"
        addr_utils = AddressUtils(msg)
        parsed = addr_utils.get_bcc_parsed()
        assert parsed == [("", "bcc@example.com")]

    def test_get_reply_to_parsed(self):
        """Test getting parsed Reply-To header."""
        msg = EmailMessage()
        msg["Reply-To"] = "Reply <reply@example.com>"
        addr_utils = AddressUtils(msg)
        parsed = addr_utils.get_reply_to_parsed()
        assert parsed == ("Reply", "reply@example.com")

    def test_get_reply_to_parsed_empty(self):
        """Test getting parsed Reply-To header when empty."""
        msg = EmailMessage()
        addr_utils = AddressUtils(msg)
        assert addr_utils.get_reply_to_parsed() is None

    def test_malformed_address_handling(self):
        """Test handling of malformed addresses."""
        msg = EmailMessage()
        msg["From"] = "malformed address"
        addr_utils = AddressUtils(msg)
        # Note: Python's email utils is quite lenient and may parse unexpected strings
        emails = addr_utils.get_from_emails()
        names = addr_utils.get_from_names()
        parsed = addr_utils.get_from_parsed()
        # Just ensure no exceptions are raised, behavior may vary
        assert isinstance(emails, list)
        assert isinstance(names, list)
        assert parsed is None or isinstance(parsed, tuple)
