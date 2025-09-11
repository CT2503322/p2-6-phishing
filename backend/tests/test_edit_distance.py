"""
Tests for edit-distance lookalike detection functionality.
"""

import pytest
from backend.core.edit_distance import EditDistanceDetector, DETECTOR
from backend.utils.models import LookalikeFinding


class TestEditDistanceDetector:
    """Test cases for the EditDistanceDetector class."""

    def setup_method(self):
        """Set up test detector."""
        self.detector = EditDistanceDetector()

    def test_empty_domains_list(self):
        """Test behavior with empty domains list."""
        findings = self.detector.analyze_domains([])
        assert findings == []

    def test_no_lookalikes_found(self):
        """Test with domains that have no lookalikes."""
        domains = ["example.com", "test.org", "random-site.net"]
        findings = self.detector.analyze_domains(domains)
        assert findings == []

    def test_single_character_difference(self):
        """Test detection of single character difference (typo)."""
        domains = ["paypa1.com"]  # Missing 'l' in PayPal
        findings = self.detector.analyze_domains(domains)

        assert len(findings) == 1
        finding = findings[0]

        assert finding.suspect_domain == "paypa1.com"
        assert finding.target_domain == "paypal.com"
        assert finding.distance == 1
        assert finding.within_cutoff is True
        assert "Single character difference" in finding.evidence
        assert "Imitates brand: PayPal" in finding.evidence

    def test_character_swap_detection(self):
        """Test detection of character swaps (common typos)."""
        domains = ["payapl.com"]  # 'pp' swapped to 'ap'
        findings = self.detector.analyze_domains(domains)

        assert len(findings) == 1
        finding = findings[0]

        assert finding.suspect_domain == "payapl.com"
        assert finding.target_domain == "paypal.com"
        assert finding.distance == 2
        assert finding.within_cutoff is True
        assert "Possible character swap" in finding.evidence

    def test_missing_character(self):
        """Test detection of missing characters."""
        domains = ["payal.com"]  # Missing 'p'
        findings = self.detector.analyze_domains(domains)

        assert len(findings) == 1
        finding = findings[0]

        assert finding.suspect_domain == "payal.com"
        assert finding.target_domain == "paypal.com"
        assert finding.distance == 1
        assert finding.within_cutoff is True
        assert "Possible missing character" in finding.evidence

    def test_extra_character(self):
        """Test detection of extra characters."""
        domains = ["paypall.com"]  # Extra 'l'
        findings = self.detector.analyze_domains(domains)

        assert len(findings) == 1
        finding = findings[0]

        assert finding.suspect_domain == "paypall.com"
        assert finding.target_domain == "paypal.com"
        assert finding.distance == 1
        assert finding.within_cutoff is True
        assert "Possible extra character" in finding.evidence

    def test_exact_brand_match_excluded(self):
        """Test that exact brand matches are excluded from results."""
        domains = ["paypal.com"]
        findings = self.detector.analyze_domains(domains)
        assert findings == []

    def test_multiple_lookalikes(self):
        """Test analysis with multiple suspicious domains."""
        domains = ["paypa1.com", "goog1e.com", "amaz0n.com"]
        findings = self.detector.analyze_domains(domains)

        assert len(findings) == 3

        # Check each finding
        paypal_finding = next(f for f in findings if "paypal" in f.target_domain)
        google_finding = next(f for f in findings if "google" in f.target_domain)
        amazon_finding = next(f for f in findings if "amazon" in f.target_domain)

        assert paypal_finding.suspect_domain == "paypa1.com"
        assert google_finding.suspect_domain == "goog1e.com"
        assert amazon_finding.suspect_domain == "amaz0n.com"

        assert all(f.within_cutoff for f in findings)
        assert all(f.distance <= 2 for f in findings)

    def test_above_cutoff_threshold(self):
        """Test domains with distance above the cutoff are not flagged."""
        domains = ["paypalll.com"]  # 2 extra 'l's - distance 2
        findings = self.detector.analyze_domains(domains)

        # This should be detected since distance <= 2
        assert len(findings) == 1

        # Test distance 3
        domains = ["paypallll.com"]  # 3 extra 'l's - distance 3
        findings = self.detector.analyze_domains(domains)

        # This should not be detected since distance > 2
        assert len(findings) == 0

    def test_custom_brand_list(self):
        """Test analysis with custom brand list."""
        domains = ["mybrand.com"]
        custom_brands = ["mybrand.com", "legitbrand.org"]
        findings = self.detector.analyze_domains(domains, custom_brands)

        assert len(findings) == 0  # Exact match should be excluded

        # Test with different domain
        domains = ["mybrnd.com"]  # Missing 'a'
        findings = self.detector.analyze_domains(domains, custom_brands)

        assert len(findings) == 1
        assert findings[0].target_domain == "mybrand.com"

    def test_recipient_org_parameter(self):
        """Test inclusion of recipient organization domain."""
        domains = ["myorg.com"]
        recipient_org = "recipient-org.com"
        findings = self.detector.analyze_domains(domains, recipient_org=recipient_org)

        assert len(findings) == 0  # Should not match since different

        # Test with similar domain
        domains = ["recipientorg.com"]  # Missing hyphen
        findings = self.detector.analyze_domains(domains, recipient_org=recipient_org)

        assert len(findings) == 1
        assert findings[0].target_domain == "recipient-org.com"

    def test_levenshtein_distance_calculation(self):
        """Test the Levenshtein distance algorithm implementation."""
        # Test basic cases
        assert self.detector._levenshtein_distance("cat", "cat") == 0
        assert self.detector._levenshtein_distance("cat", "bat") == 1
        assert self.detector._levenshtein_distance("cat", "cats") == 1
        assert self.detector._levenshtein_distance("cat", "catss") == 2
        assert self.detector._levenshtein_distance("kitten", "sitting") == 3

        # Test edge cases
        assert self.detector._levenshtein_distance("", "") == 0
        assert self.detector._levenshtein_distance("a", "") == 1
        assert self.detector._levenshtein_distance("", "b") == 1

    def test_character_pattern_detection(self):
        """Test detection of different character modification patterns."""
        # Test character substitution
        assert self.detector._is_wrong_character("payl", "payp") is True
        assert self.detector._is_wrong_character("paypp", "paypx") is True
        assert (
            self.detector._is_wrong_character("paypal", "paypzl") is True
        )  # Same length, one substitution
        assert (
            self.detector._is_wrong_character("paypal", "paypzlx") is False
        )  # Length difference

        # Test missing character
        assert self.detector._is_missing_character("payl", "paypl") is True
        assert self.detector._is_missing_character("aypl", "paypl") is True
        assert self.detector._is_missing_character("paypal", "paypal") is False

        # Test character swap
        assert self.detector._is_character_swap("ab", "ba") is True
        assert self.detector._is_character_swap("abc", "acb") is True
        assert self.detector._is_character_swap("paypal", "pypaal") is False  # No swap

    def test_lookalike_finding_structure(self):
        """Test the structure of LookalikeFinding objects."""
        domains = ["paypa1.com"]
        findings = self.detector.analyze_domains(domains)

        assert len(findings) == 1
        finding = findings[0]

        # Check required fields are present
        assert hasattr(finding, "suspect_domain")
        assert hasattr(finding, "target_domain")
        assert hasattr(finding, "distance")
        assert hasattr(finding, "within_cutoff")
        assert hasattr(finding, "evidence")

        # Check types
        assert isinstance(finding.suspect_domain, str)
        assert isinstance(finding.target_domain, str)
        assert isinstance(finding.distance, int)
        assert isinstance(finding.within_cutoff, bool)
        assert isinstance(finding.evidence, str)

    def test_evidence_generation(self):
        """Test evidence string generation for different scenarios."""
        domains = ["paypa1.com"]
        findings = self.detector.analyze_domains(domains)

        assert len(findings) == 1
        evidence = findings[0].evidence

        # Should contain key information
        assert "Single character difference" in evidence
        assert "Target: paypal.com" in evidence
        assert "Imitates brand: PayPal" in evidence

    def test_various_brand_lookalikes(self):
        """Test lookalike detection for various known brands."""
        test_cases = [
            ("goog1e.com", "google.com"),
            ("facebok.com", "facebook.com"),
            ("amazn.com", "amazon.com"),
            ("githubb.com", "github.com"),
            ("twiter.com", "twitter.com"),
        ]

        for suspect, target in test_cases:
            findings = self.detector.analyze_domains([suspect])
            assert len(findings) == 1, f"Failed to detect lookalike for {suspect}"
            assert findings[0].target_domain == target
            assert findings[0].within_cutoff is True


class TestGlobalDetector:
    """Test cases for the global DETECTOR instance."""

    def test_global_detector_existence(self):
        """Test that the global DETECTOR instance exists."""
        assert DETECTOR is not None
        assert isinstance(DETECTOR, EditDistanceDetector)

    def test_global_detector_functionality(self):
        """Test that the global DETECTOR works correctly."""
        findings = DETECTOR.analyze_domains(["paypa1.com"])
        assert len(findings) == 1
        assert findings[0].suspect_domain == "paypa1.com"
        assert findings[0].target_domain == "paypal.com"


class TestBrandRecognition:
    """Test brand recognition and classification."""

    def setup_method(self):
        """Set up test detector."""
        self.detector = EditDistanceDetector()

    def test_brand_recognition_in_evidence(self):
        """Test that evidence correctly identifies brand imitation."""
        # Test all known brands
        brand_domains = [
            "paypal.com",
            "google.com",
            "amazon.com",
            "microsoft.com",
            "apple.com",
        ]

        for brand_domain in brand_domains:
            # Create a minimal variant (change one character in .com)
            if brand_domain.endswith(".com"):
                suspect_domain = brand_domain[:-1] + "cm"  # .com -> .cm

            findings = self.detector.analyze_domains([suspect_domain])

            # Should find a match
            brand_findings = [f for f in findings if f.target_domain == brand_domain]
            assert (
                len(brand_findings) >= 1
            ), f"No match found for {suspect_domain} -> {brand_domain}"

    def test_non_brand_domain(self):
        """Test that non-brand domains don't trigger false positives."""
        domains = ["example.com", "test.org", "random-domain.net"]
        findings = self.detector.analyze_domains(domains)

        # These common domains should not match any known brands at close distance
        assert len(findings) == 0
