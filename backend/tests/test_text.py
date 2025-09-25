from backend.core.text import clean_text, normalize_text, tokenize_words


def test_normalize_text_strips_accents_controls_and_whitespace():
    value = "  P\u00c1Y\u200bPal\t Services  "
    assert normalize_text(value) == "paypal services"


def test_clean_text_is_lowercase_and_collapses_spaces():
    assert clean_text(" Pay-Now! \n") == "pay-now!"


def test_tokenize_words_handles_multiword_phrases():
    text = "Verify your PayPal account immediately"
    tokens = tokenize_words(text)
    assert tokens == ["verify", "your", "paypal", "account", "immediately"]


def test_tokenize_words_respects_min_length():
    tokens = tokenize_words("A B CDE", min_length=2)
    assert tokens == ["cde"]


def test_tokenize_words_rejects_invalid_min_length():
    try:
        tokenize_words("text", min_length=0)
    except ValueError as exc:
        assert "min_length" in str(exc)
    else:
        raise AssertionError("Expected ValueError for min_length < 1")
