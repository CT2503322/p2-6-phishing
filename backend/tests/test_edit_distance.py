from backend.core.edit_distance import (
    banded_levenshtein,
    fuzzy_brand_mentions,
    fuzzy_domain_matches,
)


def test_banded_levenshtein_respects_cutoff():
    assert banded_levenshtein('paypal', 'paypa1', max_distance=1) == 1
    assert banded_levenshtein('paypal', 'paypa1', max_distance=0) is None
    assert banded_levenshtein('short', 'a much longer string', max_distance=2) is None


def test_fuzzy_domain_matches_returns_known_targets():
    matches = fuzzy_domain_matches('paypol.com', ['paypal.com', 'amazon.com'], max_distance=2)
    assert matches == ['paypal.com']


def test_fuzzy_brand_mentions_detects_near_miss_tokens():
    text = 'Your PAYPAL account has been locked due to unusual logins. Visit paypa1 immediately.'
    matches = fuzzy_brand_mentions(text, ['paypal', 'amazon'], max_distance=1)
    assert matches == ['paypal']
