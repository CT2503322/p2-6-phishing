import re

from fastapi.testclient import TestClient

from backend.api.index import app
from backend.core.scoring import score_email
from backend.core.url_checks import extract_urls
from backend.ingestion.parse_eml import parse_eml

PHISHING_EML = """From: \"PayPal Security\" <service@paypol.com>
Reply-To: \"Investigation\" <alerts@fraudster.net>
To: customer@example.com
Subject: Urgent account update required
Message-ID: <1234@paypol.com>
Date: Tue, 14 Oct 2025 10:00:00 -0000
Mime-Version: 1.0
Content-Type: text/plain; charset=\"utf-8\"
Return-Path: <alerts@fraudster.net>
Received: from attacker.net (attacker.net [203.0.113.5])

Security alert: We detected suspicious activity in your account.
Please confirm identity to avoid suspension and complete the account update now.
Click here http://evil.test/login to update billing information immediately.
"""

BENIGN_EML = """From: "Colleague" <teammate@example.com>
To: you@example.com
Subject: Meeting follow-up
Message-ID: <abcd@example.com>
Date: Wed, 15 Oct 2025 12:00:00 -0000
Mime-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Return-Path: <teammate@example.com>
Received: from mail.example.com (mail.example.com [198.51.100.10])

Thanks for the productive meeting earlier today.
I have attached the minutes and will share the slide deck tomorrow.
Let me know if you have any questions in the meantime.
"""

_POINTS_PATTERN = re.compile(r"(\d+)-(?:point|points) (indicator|mitigation):")


def _prepare_parsed_email(tmp_path, filename: str, content: str):
    eml_path = tmp_path / filename
    eml_path.write_text(content, encoding="utf-8")
    parsed = parse_eml(str(eml_path))

    headers = {
        "from": parsed.get("from", ""),
        "reply-to": parsed.get("reply_to", ""),
        "return-path": parsed.get("return_path", ""),
        "subject": parsed.get("subject", ""),
        "message-id": parsed.get("message_id", ""),
        "received": parsed.get("received", ""),
    }

    urls = extract_urls(parsed.get("body", ""))
    attachments = parsed.get("attachment_names", [])
    return parsed, headers, urls, attachments


def _sum_explanation_points(explanations):
    total = 0
    for line in explanations:
        match = _POINTS_PATTERN.match(line)
        if not match:
            continue
        points = int(match.group(1))
        if match.group(2) == "mitigation":
            points *= -1
        total += points
    return total


def test_end_to_end_scoring_flags_phishing(tmp_path):
    parsed, headers, urls, attachments = _prepare_parsed_email(
        tmp_path, "phishing_sample.eml", PHISHING_EML
    )

    label, score, explanations, matched_keywords, suspicious_urls = score_email(
        headers,
        parsed.get("body", ""),
        urls,
        attachments,
    )

    assert label == "HIGH"
    assert score >= 20
    for keyword in ("security alert", "confirm identity", "click here"):
        assert keyword in matched_keywords
    assert suspicious_urls and suspicious_urls[0][0].geturl() == "http://evil.test/login"
    assert explanations and explanations[0].startswith("High risk phishing alert")


def test_scoring_accuracy_matches_explanations(tmp_path):
    parsed, headers, urls, attachments = _prepare_parsed_email(
        tmp_path, "phishing_sample.eml", PHISHING_EML
    )

    _, score, explanations, *_ = score_email(
        headers,
        parsed.get("body", ""),
        urls,
        attachments,
    )

    assert _sum_explanation_points(explanations) == score


def test_algorithmic_endpoint_returns_high_label(tmp_path):
    parsed, _, _, _ = _prepare_parsed_email(
        tmp_path, "phishing_sample.eml", PHISHING_EML
    )

    client = TestClient(app)
    response = client.post("/analyze/algorithmic", json={"parsed": parsed})

    assert response.status_code == 200
    payload = response.json()
    assert payload["label"] == "HIGH"
    assert payload["detection_method"] == "algorithmic"
    assert payload["score"] >= 10
    assert "<mark" in payload["highlighted_body"]
    assert any("security alert" in exp.lower() for exp in payload["explanations"])


def test_end_to_end_pipeline_handles_benign_email(tmp_path):
    parsed, headers, urls, attachments = _prepare_parsed_email(
        tmp_path, "benign_sample.eml", BENIGN_EML
    )

    label, score, explanations, matched_keywords, suspicious_urls = score_email(
        headers,
        parsed.get("body", ""),
        urls,
        attachments,
    )

    assert label == "LOW"
    assert score == 0
    assert matched_keywords == []
    assert suspicious_urls == []
    assert any("no strong phishing indicators" in exp.lower() for exp in explanations)

    client = TestClient(app)
    response = client.post("/analyze/algorithmic", json={"parsed": parsed})
    assert response.status_code == 200
    payload = response.json()
    assert payload["label"] == "LOW"
    assert payload["score"] == score
    assert "<mark" not in payload["highlighted_body"]
