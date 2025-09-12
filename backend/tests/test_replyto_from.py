import pytest
from backend.core.replyto_from import (
    ReplyToAnalyzer,
    analyze_replyto_from_mismatch,
    check_replyto_from_rules,
)
from backend.utils.models import RuleScore, ReplyToFinding


class TestReplyToAnalyzer:
    """Test cases for ReplyToAnalyzer class."""

    def setup_method(self):
        self.analyzer = ReplyToAnalyzer()

    def test_no_mismatch_same_addresses(self):
        """Test when From and Reply-To addresses are identical."""
        finding = self.analyzer.analyze_mismatch(
            from_address="user@example.com",
            from_domain="example.com",
            reply_to_address="user@example.com",
            reply_to_domain="example.com",
        )

        assert not finding.has_mismatch
        assert finding.severity == 0.0
        assert finding.reasons == []

    def test_address_mismatch_same_domain(self):
        """Test when addresses differ but domains are the same."""
        finding = self.analyzer.analyze_mismatch(
            from_address="sender@example.com",
            from_domain="example.com",
            reply_to_address="support@example.com",
            reply_to_domain="example.com",
        )

        assert finding.has_mismatch
        assert finding.severity == 1.0
        assert "Address mismatch" in finding.reasons

    def test_domain_mismatch_different_domains(self):
        """Test when domains differ."""
        finding = self.analyzer.analyze_mismatch(
            from_address="user@legit.com",
            from_domain="legit.com",
            reply_to_address="user@evil.com",
            reply_to_domain="evil.com",
        )

        assert finding.has_mismatch
        assert finding.severity >= 2.0  # Address + suspicious domain mismatch
        assert "Address mismatch" in finding.reasons
        assert "Suspicious domain mismatch" in finding.reasons

    def test_potential_spoofing_same_username(self):
        """Test potential spoofing when username is same but domain differs."""
        finding = self.analyzer.analyze_mismatch(
            from_address="john@banksafe.com",
            from_domain="banksafe.com",
            reply_to_address="john@bankevil.com",
            reply_to_domain="bankevil.com",
        )

        assert finding.has_mismatch
        assert finding.severity >= 3.5  # Address + suspicious + spoofing
        assert "Potential username spoofing" in finding.reasons

    def test_similar_domains_typosquatting(self):
        """Test similar domains that look like typosquatting."""
        finding = self.analyzer.analyze_mismatch(
            from_address="user@g00gle.com",
            from_domain="g00gle.com",
            reply_to_address="user@google.com",
            reply_to_domain="google.com",
        )

        assert finding.has_mismatch
        assert finding.severity >= 3.0  # Domain mismatch + suspicious due to similarity

    def test_organization_domain_change(self):
        """Test organizational domain change (e.g., mail.google.com to gmail.com)."""
        finding = self.analyzer.analyze_mismatch(
            from_address="user@mail.google.com",
            from_domain="mail.google.com",
            reply_to_address="user@gmail.com",
            reply_to_domain="gmail.com",
        )

        assert finding.has_mismatch
        # While organizations change, for this specific case it might not be flagged as suspicious
        # Depending on the _extract_organization_domain logic

    def test_generate_rule_scores_high_severity(self):
        """Test rule score generation for high severity findings."""
        finding = ReplyToFinding(
            has_mismatch=True,
            severity=3.5,
            reasons=[
                "Address mismatch",
                "Suspicious domain mismatch",
                "Potential username spoofing",
            ],
            from_address="user@legit.com",
            reply_to_address="user@evil.com",
        )

        rules = self.analyzer.generate_rule_scores(finding)
        assert len(rules) == 1
        assert rules[0].rule == "replyto_mismatch_high"
        assert rules[0].delta <= 3.0
        assert "Reply-To mismatch detected" in rules[0].evidence

    def test_generate_rule_scores_low_severity(self):
        """Test rule score generation for low severity findings."""
        finding = ReplyToFinding(
            has_mismatch=True,
            severity=1.2,
            reasons=["Domain mismatch"],
            from_address="user@domain1.com",
            reply_to_address="user@domain2.com",
        )

        rules = self.analyzer.generate_rule_scores(finding)
        assert len(rules) == 0  # Below threshold

    def test_generate_rule_scores_above_threshold(self):
        """Test rule score generation when severity is above threshold."""
        finding = ReplyToFinding(
            has_mismatch=True,
            severity=2.0,
            reasons=["Domain mismatch"],
            from_address="user@domain1.com",
            reply_to_address="user@domain2.com",
        )

        rules = self.analyzer.generate_rule_scores(finding)
        assert len(rules) == 1
        assert rules[0].rule == "replyto_mismatch_high"

    def test_convenience_function_analysis(self):
        """Test convenience function for mismatch analysis."""
        finding = analyze_replyto_from_mismatch(
            from_address="test@legit.com",
            from_domain="legit.com",
            reply_to_address="test@evil.com",
            reply_to_domain="evil.com",
        )

        assert finding.has_mismatch
        assert isinstance(finding, ReplyToFinding)

    def test_convenience_function_rules(self):
        """Test convenience function for rule generation."""
        rules = check_replyto_from_rules(
            from_address="test@legit.com",
            from_domain="legit.com",
            reply_to_address="test@evil.com",
            reply_to_domain="evil.com",
        )

        assert isinstance(rules, list)
        assert len(rules) >= 1
        assert isinstance(rules[0], RuleScore)

    def test_none_values_handling(self):
        """Test handling of None values."""
        finding = self.analyzer.analyze_mismatch(
            from_address=None,
            from_domain=None,
            reply_to_address="user@example.com",
            reply_to_domain="example.com",
        )

        assert not finding.has_mismatch
        assert finding.severity == 0.0

    def test_empty_strings_handling(self):
        """Test handling of empty strings."""
        finding = self.analyzer.analyze_mismatch(
            from_address="",
            from_domain="",
            reply_to_address="user@example.com",
            reply_to_domain="example.com",
        )

        assert not finding.has_mismatch
        assert finding.severity == 0.0

    def test_domains_similarity_no_match(self):
        """Test domains similarity when they are not similar."""
        assert not self.analyzer._domains_similar("google.com", "microsoft.com")

    def test_domains_similarity_character_swap(self):
        """Test domains similarity for single character swap."""
        # This would be more accurate with Levenshtein distance
        # For now, our implementation checks exact length and diff <= 2
        assert self.analyzer._domains_similar("google.com", "g00gle.com")
        assert not self.analyzer._domains_similar(
            "google.com", "abcd.com"
        )  # Different lengths

    def test_extract_organization_domain(self):
        """Test extraction of organizational domain."""
        assert (
            self.analyzer._extract_organization_domain("mail.google.com")
            == "google.com"
        )
        assert self.analyzer._extract_organization_domain("example.co.uk") == "co.uk"
        assert (
            self.analyzer._extract_organization_domain("example.com") == "example.com"
        )

    def test_suspicious_domain_change(self):
        """Test suspicious domain change detection."""
        assert self.analyzer._is_suspicious_domain_change("google.com", "g00gle.com")
        assert self.analyzer._is_suspicious_domain_change(
            "example.com", "different.com"
        )
