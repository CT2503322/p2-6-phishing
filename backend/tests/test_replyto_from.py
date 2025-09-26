from backend.core.replyto_from import analyze_reply_to


def test_analyze_reply_to_domains_match_returns_no_score():
    result = analyze_reply_to("Alerts <alerts@example.com>", "support@example.com")

    assert result.score == 0
    assert result.reasons == []
    assert result.from_domain == "example.com"
    assert result.reply_to_domain == "example.com"


def test_analyze_reply_to_flags_domain_mismatch():
    result = analyze_reply_to("alerts@example.com", "help@phish.co")

    assert result.score == 3
    assert result.reasons == ["+3 points: Reply-to domain differs from From domain (phish.co)"]
    assert result.from_domain == "example.com"
    assert result.reply_to_domain == "phish.co"


def test_analyze_reply_to_handles_missing_reply_to():
    result = analyze_reply_to("alerts@example.com", None)

    assert result.score == 0
    assert result.reasons == []
    assert result.reply_to_domain is None


def test_analyze_reply_to_parses_display_name_addresses():
    result = analyze_reply_to("\"Alerts Team\" <alerts@example.com>", "\"Support\" <reply@evil.biz>")

    assert result.score == 3
    assert result.reasons[0].endswith("(evil.biz)")
