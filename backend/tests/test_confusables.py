
from backend.core.confusables import (
    detect_confusable,
    normalize_unicode,
    unicode_skeleton,
)


def test_normalize_unicode_strips_zero_width_and_casefolds():
    value = "Pay\u200bPal"
    assert normalize_unicode(value) == "paypal"


def test_unicode_skeleton_maps_cyrillic_domain_to_ascii():
    hostile = "\u0440\u0430\u0443\u0440\u0430l.com"
    assert unicode_skeleton(hostile) == "paypal.com"


def test_detect_confusable_matches_known_brand():
    reason = detect_confusable("\u0440\u0430\u0443\u0440\u0430l.com", ["paypal.com"])
    assert reason == "confusable match for paypal.com"


def test_detect_confusable_flags_punycode_labels():
    assert detect_confusable("xn--pple-43d.com") == "punycode label"


def test_detect_confusable_handles_zero_width_characters():
    reason = detect_confusable("pay\u200bpal.com")
    assert reason == "zero-width characters"


def test_detect_confusable_returns_none_for_ascii_domain():
    assert detect_confusable("example.com") is None

