import pytest
from backend.ingestion.addresses import AddressUtils
from email.message import EmailMessage


def test_address_utils_get_from():
    """Test getting raw From header."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    utils = AddressUtils(msg)
    assert utils.get_from() == "sender@example.com"


def test_address_utils_get_to_multiple():
    """Test getting raw To header with multiple recipients."""
    msg = EmailMessage()
    msg["To"] = "recipient1@example.com, recipient2@example.com"
    utils = AddressUtils(msg)
    assert utils.get_to() == "recipient1@example.com, recipient2@example.com"


def test_address_utils_get_from_emails():
    """Test extracting emails from From header."""
    msg = EmailMessage()
    msg["From"] = "John Doe <john@example.com>"
    utils = AddressUtils(msg)
    assert utils.get_from_emails() == ["john@example.com"]


def test_address_utils_get_to_emails_multiple():
    """Test extracting emails from To header with multiple recipients."""
    msg = EmailMessage()
    msg["To"] = "John Doe <john@example.com>, Jane Smith <jane@example.com>"
    utils = AddressUtils(msg)
    assert utils.get_to_emails() == ["john@example.com", "jane@example.com"]


def test_address_utils_get_cc_emails():
    """Test extracting emails from Cc header."""
    msg = EmailMessage()
    msg["Cc"] = "cc@example.com"
    utils = AddressUtils(msg)
    assert utils.get_cc_emails() == ["cc@example.com"]


def test_address_utils_get_bcc_emails():
    """Test extracting emails from Bcc header."""
    msg = EmailMessage()
    msg["Bcc"] = "bcc@example.com"
    utils = AddressUtils(msg)
    assert utils.get_bcc_emails() == ["bcc@example.com"]


def test_address_utils_get_reply_to_emails():
    """Test extracting emails from Reply-To header."""
    msg = EmailMessage()
    msg["Reply-To"] = "reply@example.com"
    utils = AddressUtils(msg)
    assert utils.get_reply_to_emails() == ["reply@example.com"]


def test_address_utils_get_from_names():
    """Test extracting names from From header."""
    msg = EmailMessage()
    msg["From"] = "John Doe <john@example.com>"
    utils = AddressUtils(msg)
    assert utils.get_from_names() == ["John Doe"]


def test_address_utils_get_to_names_multiple():
    """Test extracting names from To header with multiple recipients."""
    msg = EmailMessage()
    msg["To"] = "John Doe <john@example.com>, Jane Smith <jane@example.com>"
    utils = AddressUtils(msg)
    assert utils.get_to_names() == ["John Doe", "Jane Smith"]


def test_address_utils_get_from_parsed():
    """Test parsing From header."""
    msg = EmailMessage()
    msg["From"] = "John Doe <john@example.com>"
    utils = AddressUtils(msg)
    assert utils.get_from_parsed() == ("John Doe", "john@example.com")


def test_address_utils_get_to_parsed_multiple():
    """Test parsing To header with multiple recipients."""
    msg = EmailMessage()
    msg["To"] = "John Doe <john@example.com>, Jane Smith <jane@example.com>"
    utils = AddressUtils(msg)
    expected = [("John Doe", "john@example.com"), ("Jane Smith", "jane@example.com")]
    assert utils.get_to_parsed() == expected


def test_address_utils_get_cc_parsed():
    """Test parsing Cc header."""
    msg = EmailMessage()
    msg["Cc"] = "CC Person <cc@example.com>"
    utils = AddressUtils(msg)
    assert utils.get_cc_parsed() == [("CC Person", "cc@example.com")]


def test_address_utils_get_reply_to_parsed():
    """Test parsing Reply-To header."""
    msg = EmailMessage()
    msg["Reply-To"] = "Reply To <reply@example.com>"
    utils = AddressUtils(msg)
    assert utils.get_reply_to_parsed() == ("Reply To", "reply@example.com")


def test_address_utils_quoted_names():
    """Test handling quoted names."""
    msg = EmailMessage()
    msg["From"] = '"Doe, John" <john@example.com>'
    utils = AddressUtils(msg)
    assert utils.get_from_parsed() == ("Doe, John", "john@example.com")


def test_address_utils_utf8_names():
    """Test handling UTF-8 names."""
    msg = EmailMessage()
    msg["From"] = "José María <jose@example.com>"
    utils = AddressUtils(msg)
    assert utils.get_from_parsed() == ("José María", "jose@example.com")


def test_address_utils_empty_headers():
    """Test handling empty headers."""
    msg = EmailMessage()
    utils = AddressUtils(msg)
    assert utils.get_from() is None
    assert utils.get_from_emails() == []
    assert utils.get_from_names() == []
    assert utils.get_from_parsed() is None


def test_address_utils_with_corrupted_eml():
    """Test AddressUtils with corrupted EML file."""
    from email.parser import BytesParser
    from email import policy

    with open("backend/tests/fixtures/tada-corrupted.eml", "rb") as f:
        raw_eml = f.read()
    parser = BytesParser(policy=policy.default)
    msg = parser.parsebytes(raw_eml)

    utils = AddressUtils(msg)
    # Should not raise exceptions
    from_emails = utils.get_from_emails()
    to_emails = utils.get_to_emails()
    cc_emails = utils.get_cc_emails()
    from_parsed = utils.get_from_parsed()

    # Values should be empty lists or None, but no exceptions
    assert isinstance(from_emails, list)
    assert isinstance(to_emails, list)
    assert isinstance(cc_emails, list)
    assert from_parsed is None or isinstance(from_parsed, tuple)


def test_address_utils_malformed_addresses():
    """Test AddressUtils with malformed address strings."""
    msg = EmailMessage()
    msg["From"] = "invalid@"
    msg["To"] = "@domain.com"
    msg["Cc"] = "name@"

    utils = AddressUtils(msg)
    # Should not raise exceptions
    from_emails = utils.get_from_emails()
    to_emails = utils.get_to_emails()
    cc_emails = utils.get_cc_emails()

    # Should return empty lists for malformed addresses
    assert from_emails == []
    assert to_emails == []
    assert cc_emails == []
