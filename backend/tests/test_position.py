
from backend.core.position import EARLY_BODY_WINDOW, KeywordHit, score_keyword_positions
from backend.core.lexical_score import lexical_score
from backend.core.scoring import score_email


def test_subject_hit_weighting():
    total, matched, hits = score_keyword_positions('URGENT action needed', '', ['urgent'])

    assert total == 3
    assert matched == ['urgent']
    assert hits == [KeywordHit(keyword='urgent', location='subject', points=3, offset=0)]


def test_early_body_hit_weighting():
    body = 'Please CLICK HERE to reset your password immediately.'
    total, matched, hits = score_keyword_positions('', body, ['click here'])

    assert total == 2
    assert matched == ['click here']
    assert hits[0].location == 'early_body'
    assert hits[0].points == 2
    assert hits[0].offset >= 0


def test_late_body_hit_receives_base_points():
    padding = 'A' * (EARLY_BODY_WINDOW + 5)
    body = padding + ' login '
    total, matched, hits = score_keyword_positions('', body, ['login'])

    assert total == 1
    assert matched == ['login']
    assert hits[0].location == 'body'
    assert hits[0].points == 1
    assert hits[0].offset >= EARLY_BODY_WINDOW


def test_lexical_score_returns_breakdown():
    score, matched, hits = lexical_score('Account Notice', 'Please verify your account details')

    assert score >= 3
    assert set(matched) == {'account', 'verify'}
    assert all(isinstance(h, KeywordHit) for h in hits)


def test_score_email_includes_positional_explanations():
    headers = {
        'from': 'alerts@example.com',
        'subject': 'Urgent billing update',
    }

    label, total, explanations, matched_keywords, suspicious_urls = score_email(headers, 'Hello', [], [])

    assert total == 3
    assert label == 'LOW'
    assert any("trigger word 'urgent'" in exp for exp in explanations)
    assert matched_keywords == ['urgent']
    assert suspicious_urls == []
