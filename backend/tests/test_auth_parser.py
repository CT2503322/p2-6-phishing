import pytest
from backend.ingestion.auth_parser import (
    parse_authentication_results,
    get_auth_data,
    _parse_spf,
    _parse_dkim,
    _parse_dmarc,
    _parse_arc,
)


def test_parse_spf_pass():
    """Test parsing SPF pass result."""
    spf_str = 'spf=pass (google.com: domain of bounces+43663810-be39-randysee69=gmail.com@em9863.info.tada.global designates 149.72.47.107 as permitted sender) smtp.mailfrom="bounces+43663810-be39-randysee69=gmail.com@em9863.info.tada.global"'
    result = _parse_spf(spf_str)

    assert result is not None
    assert result["result"] == "pass"
    assert result["domain"] == "em9863.info.tada.global"
    assert result["ip"] == "149.72.47.107"
    assert result["aligned"] is True


def test_parse_spf_fail():
    """Test parsing SPF fail result."""
    spf_str = "spf=fail (mail.example.com: domain of badsender@example.com does not designate 192.168.1.100 as permitted sender) smtp.mailfrom=badsender@example.com"
    result = _parse_spf(spf_str)

    assert result is not None
    assert result["result"] == "fail"
    assert result["domain"] == "example.com"
    assert result["ip"] == "192.168.1.100"
    assert result["aligned"] is False


def test_parse_dkim_pass():
    """Test parsing DKIM pass result."""
    dkim_str = "dkim=pass header.i=@info.tada.global header.s=s1 header.b=a0G8X53f"
    result = _parse_dkim(dkim_str)

    assert result is not None
    assert result["result"] == "pass"
    assert result["d"] == "info.tada.global"
    assert result["s"] == "s1"
    assert result["aligned"] is True


def test_parse_dkim_fail():
    """Test parsing DKIM fail result."""
    dkim_str = "dkim=fail header.i=@baddomain.com header.s=default header.b=bad"
    result = _parse_dkim(dkim_str)

    assert result is not None
    assert result["result"] == "fail"
    assert result["d"] == "baddomain.com"
    assert result["s"] == "default"
    assert result["aligned"] is False


def test_parse_dmarc_pass():
    """Test parsing DMARC pass result."""
    dmarc_str = "dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=info.tada.global"
    result = _parse_dmarc(dmarc_str)

    assert result is not None
    assert result["result"] == "pass"
    assert result["policy"] == "none"
    assert result["org_domain"] == "info.tada.global"
    assert result["aligned"] is True


def test_parse_dmarc_quarantine():
    """Test parsing DMARC quarantine result."""
    dmarc_str = "dmarc=pass (p=quarantine dis=none) header.from=sender@example.com"
    result = _parse_dmarc(dmarc_str)

    assert result is not None
    assert result["result"] == "pass"
    assert result["policy"] == "quarantine"
    assert result["org_domain"] == "sender@example.com"
    assert result["aligned"] is True


def test_parse_arc():
    """Test parsing ARC result."""
    arc_str = "arc=pass i=1 cv=none"
    result = _parse_arc(arc_str)

    assert result is not None
    assert result["instance"] == 1
    assert result["seal"] == "pass"
    assert result["cv"] == "none"
    assert result["chain_count"] == 1


def test_parse_authentication_results_full():
    """Test parsing full Authentication-Results header."""
    auth_header = """mail.example.com;
	dkim=pass header.i=@example.com header.s=default header.b=abc123;
	spf=pass (mail.example.com: domain of sender@example.com designates 192.168.1.1 as permitted sender) smtp.mailfrom=sender@example.com;
	dmarc=pass (p=quarantine dis=none) header.from=sender@example.com"""

    result = parse_authentication_results(auth_header)

    assert result["spf"] is not None
    assert result["spf"]["result"] == "pass"
    assert result["spf"]["domain"] == "example.com"
    assert result["spf"]["ip"] == "192.168.1.1"

    assert len(result["dkim"]) == 1
    assert result["dkim"][0]["result"] == "pass"
    assert result["dkim"][0]["d"] == "example.com"
    assert result["dkim"][0]["s"] == "default"

    assert result["dmarc"] is not None
    assert result["dmarc"]["result"] == "pass"
    assert result["dmarc"]["policy"] == "quarantine"
    assert result["dmarc"]["org_domain"] == "sender@example.com"

    assert result["arc"] is None


def test_parse_authentication_results_empty():
    """Test parsing empty Authentication-Results header."""
    result = parse_authentication_results("")

    assert result["spf"] is None
    assert result["dkim"] == []
    assert result["dmarc"] is None
    assert result["arc"] is None


def test_get_auth_data_with_headers():
    """Test get_auth_data with email headers."""
    headers = {
        "Authentication-Results": "mail.example.com; dkim=pass header.i=@example.com header.s=default header.b=abc123; spf=pass smtp.mailfrom=sender@example.com; dmarc=pass header.from=sender@example.com",
        "ARC-Authentication-Results": "mail.example.com; dkim=pass header.i=@example.com header.s=default header.b=abc123",
        "ARC-Seal": "i=1; a=rsa-sha256; t=1234567890; cv=none; d=example.com; s=arc-20160816; b=seal_here",
    }

    result = get_auth_data(headers)

    assert result["spf"] is not None
    assert result["spf"]["result"] == "pass"
    assert len(result["dkim"]) == 1
    assert result["dmarc"] is not None
    assert result["arc"] is not None
    assert result["arc"]["instance"] == 1
    assert result["arc"]["cv"] == "none"


def test_get_auth_data_no_auth_headers():
    """Test get_auth_data with no authentication headers."""
    headers = {
        "From": "sender@example.com",
        "To": "recipient@example.com",
        "Subject": "Test email",
    }

    result = get_auth_data(headers)

    assert result["spf"] is None
    assert result["dkim"] == []
    assert result["dmarc"] is None
    assert result["arc"] is None


def test_parse_multiple_dkim():
    """Test parsing multiple DKIM results."""
    auth_header = """mail.example.com;
	dkim=pass header.i=@info.tada.global header.s=s1 header.b=a0G8X53f;
	dkim=pass header.i=@sendgrid.info header.s=smtpapi header.b=XxbJb1js;
	spf=pass smtp.mailfrom="sender@example.com";
	dmarc=pass header.from=info.tada.global"""

    result = parse_authentication_results(auth_header)

    assert len(result["dkim"]) == 2

    # First DKIM
    assert result["dkim"][0]["result"] == "pass"
    assert result["dkim"][0]["d"] == "info.tada.global"
    assert result["dkim"][0]["s"] == "s1"

    # Second DKIM
    assert result["dkim"][1]["result"] == "pass"
    assert result["dkim"][1]["d"] == "sendgrid.info"
    assert result["dkim"][1]["s"] == "smtpapi"
