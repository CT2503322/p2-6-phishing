import pytest
from backend.core.keywords import (
    KeywordConfig,
    analyze_keywords,
    analyze_keywords_with_context,
    keyword_config,
)
from backend.utils.models import KeywordHit
import tempfile
import json
import os


class TestKeywordConfig:
    """Test KeywordConfig class functionality."""

    def test_load_config_success(self):
        """Test loading keywords from config file."""
        # Uses the global keyword_config that should be loaded from keywords.json
        assert len(keyword_config.keywords) > 0
        assert keyword_config.boosting_multiplier > 1.0
        assert isinstance(keyword_config.negation_words, list)

    def test_config_has_required_keywords(self):
        """Test that config contains expected keywords."""
        required_keywords = ["urgent", "password", "account", "verify"]
        for keyword in required_keywords:
            assert keyword in keyword_config.keywords
            assert "weight" in keyword_config.keywords[keyword]
            assert "variants" in keyword_config.keywords[keyword]

    def test_compile_patterns(self):
        """Test that regex patterns are compiled correctly."""
        assert len(keyword_config.keyword_patterns) > 0

        # Test word boundary in patterns
        urgent_pattern = keyword_config.keyword_patterns["urgent"]
        assert "\\b" in urgent_pattern.pattern  # Should have word boundaries


class TestContextAwareness:
    """Test context-aware keyword detection."""

    def test_context_boost_positive(self):
        """Test that keywords get boosted when context words are present."""
        # "verify" should get boosted when "account" is nearby
        subject = "Account verification required"
        body = ""

        result = analyze_keywords_with_context(subject, body)
        verify_hit = None
        account_hit = None

        for hit in result["keyword_hits"]:
            if hit.term == "verify":
                verify_hit = hit
            elif hit.term == "account":
                account_hit = hit

        assert verify_hit is not None
        assert account_hit is not None

        # "verify" should have its weight boosted due to context
        base_verify_weight = keyword_config.keywords["verify"]["weight"]
        assert verify_hit.weight > base_verify_weight

    def test_negation_reduction(self):
        """Test that negated keywords get reduced weight."""
        subject = "This is not urgent"
        body = ""

        result = analyze_keywords_with_context(subject, body, use_positions=False)
        urgent_hit = None

        for hit in result["keyword_hits"]:
            if hit.term == "urgent":
                urgent_hit = hit

        assert urgent_hit is not None

        # "urgent" should have reduced weight due to negation (disable position weighting to test pure negation)
        base_urgent_weight = keyword_config.keywords["urgent"]["weight"]
        expected_reduced_weight = base_urgent_weight * 0.2
        assert abs(urgent_hit.weight - expected_reduced_weight) < 0.01

    def test_negation_window_detection(self):
        """Test that negation detection works within word windows."""
        # Negation before keyword (within 50 characters)
        subject = "This request does not require urgent action"
        body = ""

        result = analyze_keywords_with_context(subject, body)
        total_score = result["total_score"]

        # Should be significantly lower due to negation
        assert total_score < 2.0

    def test_context_window_respected(self):
        """Test that context boosting only applies within window."""
        # Very long text - "verify" at beginning, "account" at end (beyond window)
        subject = ""
        body = "We need to verify " + "x" * 200 + " your account"

        result = analyze_keywords_with_context(subject, body, use_positions=False)

        # Find verify hit
        verify_hit = None
        for hit in result["keyword_hits"]:
            if hit.term == "verify":
                verify_hit = hit
                break

        if verify_hit:
            # Should not get boosted since "account" is too far away (disable position weighting)
            base_verify_weight = keyword_config.keywords["verify"]["weight"]
            assert abs(verify_hit.weight - base_verify_weight) < 0.01


class TestAnalyzeKeywords:
    """Test the main analyze_keywords function."""

    def test_backward_compatibility(self):
        """Test that default behavior maintains backward compatibility."""
        subject = "Urgent action required"
        body = "Please verify your account"

        # Default behavior (should be position-based)
        result_default = analyze_keywords(subject, body)

        # Explicit position-based
        result_position = analyze_keywords(subject, body, use_positions=True)
        result_context = analyze_keywords(subject, body, use_context=True)

        # They should be different
        assert result_default["total_score"] != result_context["total_score"]

    def test_context_mode_enabled(self):
        """Test that use_context=True enables context-aware analysis."""
        subject = "Verify your account"
        body = "Not urgent request"

        # Without context (position-based only)
        result_no_context = analyze_keywords(subject, body, use_context=False)
        # With context
        result_with_context = analyze_keywords(subject, body, use_context=True)

        # Results should be different due to negation and context
        assert result_no_context["total_score"] != result_with_context["total_score"]


class TestKeywordVariants:
    """Test that keyword variants work correctly."""

    def test_multiple_variants_detected(self):
        """Test that different variants of the same keyword are detected."""
        subject = "You need to sign in to your account immediately"
        body = ""

        result = analyze_keywords_with_context(subject, body)

        # Should find both "login" variants and "account"
        found_terms = {hit.term for hit in result["keyword_hits"]}
        assert "account" in found_terms
        assert "login" in found_terms  # Should be matched from "sign in"

        # Should only have one entry per main keyword
        login_count = sum(1 for hit in result["keyword_hits"] if hit.term == "login")
        assert login_count == 1


class TestWordBoundaries:
    """Test that word boundaries prevent partial matches."""

    def test_no_partial_matches(self):
        """Test that keywords aren't matched as partial words."""
        # "account" should not match in "accountant" or "subaccount"
        subject = "Hello accountant, please check your subaccount"
        body = ""

        result = analyze_keywords_with_context(subject, body)

        # Should not find "account" matches
        account_hits = [hit for hit in result["keyword_hits"] if hit.term == "account"]
        assert len(account_hits) == 0

    def test_boundary_matches(self):
        """Test that keywords are properly matched with boundaries."""
        subject = "Your account is secure"
        body = ""

        result = analyze_keywords_with_context(subject, body)

        # Should find exactly one "account" match
        account_hits = [hit for hit in result["keyword_hits"] if hit.term == "account"]
        assert len(account_hits) == 1


class TestConfigurability:
    """Test that the keyword configuration is easily modifiable."""

    def test_custom_config_load(self):
        """Test loading custom keyword configuration."""
        custom_config = {
            "keywords": {
                "custom_urgent": {
                    "weight": 2.0,
                    "variants": ["custom urgent", "super urgent"],
                    "context": ["action"],
                }
            },
            "negation_words": ["not", "currently"],
            "boosting_multiplier": 2.0,
        }

        # Create temporary config file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            json.dump(custom_config, f)
            temp_path = f.name

        try:
            # Load custom config
            custom_kw_config = KeywordConfig(temp_path)

            # Verify custom config loaded
            assert "custom_urgent" in custom_kw_config.keywords
            assert custom_kw_config.keywords["custom_urgent"]["weight"] == 2.0
            assert (
                "custom urgent"
                in custom_kw_config.keywords["custom_urgent"]["variants"]
            )
            assert "action" in custom_kw_config.keywords["custom_urgent"]["context"]
            assert custom_kw_config.boosting_multiplier == 2.0
            assert "currently" in custom_kw_config.negation_words

        finally:
            os.unlink(temp_path)


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_input(self):
        """Test behavior with empty input."""
        result = analyze_keywords_with_context("", "")
        assert result["total_score"] == 0.0
        assert len(result["keyword_hits"]) == 0

    def test_no_matches(self):
        """Test with text that has no keyword matches."""
        subject = "This is just a normal email about regular business"
        body = "Nothing suspicious here"

        result = analyze_keywords_with_context(subject, body)
        assert result["total_score"] == 0
        assert len(result["keyword_hits"]) == 0

    def test_case_insensitivity(self):
        """Test that keyword matching is case insensitive."""
        subject = "URGENT ACTION REQUIRED"
        body = "Password Verification Needed"

        result = analyze_keywords_with_context(subject, body)

        found_terms = {hit.term for hit in result["keyword_hits"]}
        assert "urgent" in found_terms
        assert "password" in found_terms
        assert "verify" in found_terms

    def test_multiple_keyword_occurrences(self):
        """Test handling of multiple occurrences of the same keyword."""
        subject = "Urgent urgent action required"
        body = ""

        result = analyze_keywords_with_context(subject, body)

        urgent_hits = [hit for hit in result["keyword_hits"] if hit.term == "urgent"]
        assert len(urgent_hits) == 2  # Should detect both occurrences

        # Check term_stats aggregation
        urgent_stats = result["term_stats"]["urgent"]
        assert urgent_stats["count"] == 2
        assert (
            urgent_stats["total_score"] == urgent_hits[0].weight + urgent_hits[1].weight
        )


if __name__ == "__main__":
    pytest.main([__file__])
