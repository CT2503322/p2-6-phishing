import pytest
from backend.ingestion.headers import HeaderNormalizer, get_date
from backend.ingestion.models import SubscriptionMetadata, ListUnsubscribe
from email.message import EmailMessage
from email import policy
from email.parser import BytesParser


def test_header_normalizer_case_insensitive():
    """Test case-insensitive header access."""
    msg = EmailMessage()
    msg["Subject"] = "Test Subject"
    msg["FROM"] = "sender@example.com"

    normalizer = HeaderNormalizer(msg)
    assert normalizer.get_header("subject") == "Test Subject"
    assert normalizer.get_header("from") == "sender@example.com"


def test_header_normalizer_unfold():
    """Test header unfolding."""
    # Create a raw email with folded header
    raw_email = b"Subject: This is a\n folded\n subject\n\nBody"
    parser = BytesParser(policy=policy.default)
    msg = parser.parsebytes(raw_email)

    normalizer = HeaderNormalizer(msg)
    assert normalizer.get_header("Subject") == "This is a folded subject"


def test_header_normalizer_decode_rfc2047():
    """Test decoding RFC 2047 encoded headers."""
    msg = EmailMessage()
    msg["Subject"] = "=?utf-8?q?T=C3=B6st_Subject?="  # Töst Subject

    normalizer = HeaderNormalizer(msg)
    assert normalizer.get_header("Subject") == "Töst Subject"


def test_header_normalizer_multi_value_received():
    """Test multi-value Received headers."""
    msg = EmailMessage()
    msg["Received"] = "from mail.example.com by smtp.example.com"
    msg["Received"] = "from client by mail.example.com"

    normalizer = HeaderNormalizer(msg)
    received = normalizer.get_multi_value_header("received")
    assert len(received) == 2
    assert "from mail.example.com by smtp.example.com" in received
    assert "from client by mail.example.com" in received


def test_header_normalizer_non_ascii_names():
    """Test decoding non-ASCII names in headers."""
    msg = EmailMessage()
    msg["From"] = "=?utf-8?q?J=C3=B6hn_Doe?= <john@example.com>"

    normalizer = HeaderNormalizer(msg)
    assert normalizer.get_header("From") == "Jöhn Doe <john@example.com>"


# Tests for Date Parsing (T6)
def test_get_date_valid():
    """Test parsing valid RFC date strings."""
    date_str = "Wed, 21 Oct 2015 07:28:00 -0700"
    dt = get_date(date_str)
    assert dt is not None
    assert dt.year == 2015
    assert dt.month == 10
    assert dt.day == 21
    assert dt.tzinfo is not None


def test_get_date_invalid():
    """Test parsing invalid date strings."""
    date_str = "Invalid date"
    dt = get_date(date_str)
    assert dt is None


def test_get_date_timezone_aware():
    """Test that parsed dates are timezone aware."""
    date_str = "Thu, 01 Jan 2020 12:00:00 +0000"
    dt = get_date(date_str)
    assert dt is not None
    assert dt.tzinfo is not None
    assert dt.utcoffset() is not None


def test_header_normalizer_with_corrupted_eml():
    """Test HeaderNormalizer with corrupted EML file."""
    with open("backend/tests/fixtures/tada-corrupted.eml", "rb") as f:
        raw_eml = f.read()
    parser = BytesParser(policy=policy.default)
    msg = parser.parsebytes(raw_eml)

    normalizer = HeaderNormalizer(msg)
    # Should not raise exceptions
    subject = normalizer.get_header("Subject")
    from_header = normalizer.get_header("From")
    date_header = normalizer.get_header("Date")

    # Values may be None or malformed, but no exceptions
    assert subject is not None or subject is None  # Just check no exception
    assert from_header is not None or from_header is None
    assert date_header is not None or date_header is None


def test_get_date_with_malformed_date():
    """Test get_date with malformed date strings."""
    malformed_dates = [
        "Invalid date string",
        "",
        None,
        "Wed, 21 Oct 2015 07:28:00",  # Missing timezone
        "Not a date at all",
    ]
    for date_str in malformed_dates:
        dt = get_date(date_str)
        assert dt is None  # Should return None without exception


# Tests for Subscription Metadata
def test_subscription_metadata_no_headers():
    """Test subscription metadata extraction when no relevant headers exist."""
    msg = EmailMessage()
    msg["Subject"] = "Test Subject"

    normalizer = HeaderNormalizer(msg)
    metadata = normalizer.get_subscription_metadata()

    assert metadata.list_unsubscribe is None
    assert metadata.list_unsubscribe_post is None
    assert metadata.feedback_id is None
    assert metadata.precedence is None


def test_subscription_metadata_with_list_unsubscribe():
    """Test parsing List-Unsubscribe header."""
    msg = EmailMessage()
    msg["List-Unsubscribe"] = (
        "<https://example.com/unsubscribe>, <mailto:unsubscribe@example.com?subject=Unsubscribe>"
    )
    msg["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"

    normalizer = HeaderNormalizer(msg)
    metadata = normalizer.get_subscription_metadata()

    assert metadata.list_unsubscribe is not None
    assert metadata.list_unsubscribe.one_click is True
    assert metadata.list_unsubscribe.http == "https://example.com/unsubscribe"
    assert metadata.list_unsubscribe.mailto == "unsubscribe@example.com"
    assert metadata.list_unsubscribe.mailto_subject == "Unsubscribe"
    assert metadata.list_unsubscribe_post == "List-Unsubscribe=One-Click"


def test_subscription_metadata_sendgrid():
    """Test parsing SendGrid List-Unsubscribe header."""
    msg = EmailMessage()
    msg["List-Unsubscribe"] = (
        "<https://sendgrid.com/unsubscribe?oc=123>, <mailto:unsubscribe@em9863.info.tada.global>"
    )
    msg["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
    msg["Feedback-ID"] = "test-feedback-id"
    msg["Precedence"] = "bulk"

    normalizer = HeaderNormalizer(msg)
    metadata = normalizer.get_subscription_metadata()

    assert metadata.list_unsubscribe is not None
    assert metadata.list_unsubscribe.one_click is True
    assert metadata.list_unsubscribe.http == "https://sendgrid.com/unsubscribe?oc=123"
    assert metadata.list_unsubscribe.mailto == "unsubscribe@em9863.info.tada.global"
    assert metadata.list_unsubscribe.provider == "sendgrid"
    assert metadata.feedback_id == "test-feedback-id"
    assert metadata.precedence == "bulk"


def test_subscription_metadata_no_one_click():
    """Test parsing List-Unsubscribe without one-click."""
    msg = EmailMessage()
    msg["List-Unsubscribe"] = "<mailto:unsubscribe@example.com>"

    normalizer = HeaderNormalizer(msg)
    metadata = normalizer.get_subscription_metadata()

    assert metadata.list_unsubscribe is not None
    assert metadata.list_unsubscribe.one_click is False
    assert metadata.list_unsubscribe.mailto == "unsubscribe@example.com"


def test_subscription_metadata_complex_mailto():
    """Test parsing complex mailto with encoded subject."""
    msg = EmailMessage()
    msg["List-Unsubscribe"] = (
        "<mailto:unsubscribe@example.com?subject=Unsubscribe%20Me&body=Please%20remove>"
    )

    normalizer = HeaderNormalizer(msg)
    metadata = normalizer.get_subscription_metadata()

    assert metadata.list_unsubscribe is not None
    assert metadata.list_unsubscribe.mailto == "unsubscribe@example.com"
    assert metadata.list_unsubscribe.mailto_subject == "Unsubscribe Me"
