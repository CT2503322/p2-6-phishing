from backend.core.lexical_score import _default_keywords, lexical_score


def test_default_keywords_loaded_from_suspicious_terms_file():
    keywords = _default_keywords()
    assert 'security alert' in keywords
    assert 'verify now' in keywords


def test_lexical_score_matches_terms_from_file():
    score, matched, hits = lexical_score(
        subject='Security Alert',
        body='Please confirm identity and complete the account update now.',
        keywords=None,
    )

    assert score >= 4
    assert 'security alert' in matched
    assert 'account update' in matched
    assert any(hit.keyword == 'security alert' for hit in hits)
