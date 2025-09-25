from backend.core.identity_checks import domain_similar_to_brand, mentions_brand


def test_mentions_brand_uses_known_brands_from_file():
    matches = mentions_brand('PAYPAL account alert', '')
    assert matches and 'paypal' in [m.lower() for m in matches]


def test_domain_similar_to_brand_detects_typosquat():
    matches = domain_similar_to_brand('paypol.com')
    assert matches and 'paypal.com' in matches
