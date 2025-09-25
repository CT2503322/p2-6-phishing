from urllib.parse import urlparse

from backend.core.explain import build_explanations


def test_build_explanations_translates_raw_reasons_into_actions():
    reasons = [
        "+3 points: Reply-to domain differs from From domain (bad.com)",
        "+2 points: Suspicious archive attachment invoice.zip",
        "+3 points: Keyword 'urgent' in subject",
    ]

    lines = build_explanations(
        label="HIGH",
        score=11,
        raw_reasons=reasons,
        matched_keywords=["urgent"],
        suspicious_urls=[],
        attachments=["invoice.zip"],
    )

    assert lines[0].startswith("High risk phishing alert: composite score 11")
    assert "Flagged keywords: urgent." in lines[0]
    assert any("reply-to address routes responses to bad.com" in line.lower() for line in lines)
    assert any("archive invoice.zip" in line.lower() for line in lines)
    assert any("trigger word 'urgent'" in line for line in lines)


def test_general_actions_cover_urls_attachments_and_reporting():
    reasons = [
        "+3 points: Keyword 'verify account' in early body",
        "+4 points: Dangerous attachment extension in malware.exe",
        "+3 points: Suspicious URL http://evil.test/login (high-risk tld; looks credential harvest)",
    ]

    suspicious_url = urlparse("http://evil.test/login")

    lines = build_explanations(
        label="HIGH",
        score=12,
        raw_reasons=reasons,
        matched_keywords=["verify"],
        suspicious_urls=[(suspicious_url, ["high-risk tld", "looks credential harvest"])],
        attachments=["malware.exe"],
    )

    assert any("Verify the sender using a trusted contact method" in line for line in lines)
    assert any("Do not visit http://evil.test/login" in line for line in lines)
    assert any("Delete or quarantine attachments (malware.exe)" in line for line in lines)
    assert any("Report this message to your security" in line for line in lines)


def test_low_label_without_reasons_uses_default_guidance():
    lines = build_explanations(
        label="LOW",
        score=0,
        raw_reasons=[],
        matched_keywords=[],
        suspicious_urls=[],
        attachments=[],
    )

    assert lines[0].startswith("Low phishing risk: composite score 0")
    assert any("stay alert" in line.lower() for line in lines[1:])
