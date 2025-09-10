"""
Edit-distance lookalike detection for domain analysis.

This module implements detection of similar domains using edit distance
algorithms (Levenshtein distance) to identify potential phishing attempts
that rely on typosquatting or small modifications to legitimate domains.
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Set
from .models import LookalikeFinding


class EditDistanceDetector:
    """Detects domain lookalikes using edit distance algorithms."""

    # Known brands and their domain patterns (for comparison)
    BRANDS = {
        "paypal.com": "PayPal",
        "google.com": "Google",
        "amazon.com": "Amazon",
        "microsoft.com": "Microsoft",
        "apple.com": "Apple",
        "facebook.com": "Facebook",
        "github.com": "GitHub",
        "twitter.com": "Twitter",
        "instagram.com": "Instagram",
        "linkedin.com": "LinkedIn",
        "youtube.com": "YouTube",
        "netflix.com": "Netflix",
        "spotify.com": "Spotify",
        "whatsapp.com": "WhatsApp",
        "zoom.us": "Zoom",
        "slack.com": "Slack",
        "discord.com": "Discord",
        "uber.com": "Uber",
        "airbnb.com": "Airbnb",
    }

    # Edit distance cutoff for considering domains as lookalikes
    DISTANCE_CUTOFF = 2

    def analyze_domains(
        self,
        domains: List[str],
        known_brands: Optional[List[str]] = None,
        recipient_org: Optional[str] = None,
    ) -> List[LookalikeFinding]:
        """
        Analyze a list of domains for lookalike detection.

        Args:
            domains: List of domains to analyze as suspect domains
            known_brands: Optional list of known brand domains to compare against
            recipient_org: Optional recipient organization domain

        Returns:
            List of LookalikeFinding objects for detected lookalikes
        """
        if not domains:
            return []

        findings = []

        # Get comparison targets
        comparison_targets = set()

        # Add known brands if provided, otherwise use default brands
        if known_brands:
            comparison_targets.update(known_brands)
        else:
            comparison_targets.update(self.BRANDS.keys())

        # Add recipient organization domain if provided
        if recipient_org:
            comparison_targets.add(recipient_org)

        # Convert set to list for processing
        target_list = list(comparison_targets)

        # Analyze each suspect domain
        for suspect_domain in domains:
            if not suspect_domain:
                continue

            # Skip if it's already in the known brands (exact match)
            if suspect_domain.lower() in [d.lower() for d in target_list]:
                continue

            lookalikes = self._find_lookalikes(suspect_domain, target_list)
            findings.extend(lookalikes)

        return findings

    def _find_lookalikes(
        self, suspect_domain: str, target_domains: List[str]
    ) -> List[LookalikeFinding]:
        """Find lookalikes for a single suspect domain."""
        findings = []

        for target_domain in target_domains:
            distance = self._levenshtein_distance(
                suspect_domain.lower(), target_domain.lower()
            )

            within_cutoff = distance <= self.DISTANCE_CUTOFF

            if within_cutoff:
                evidence = self._generate_evidence(
                    suspect_domain, target_domain, distance
                )

                finding = LookalikeFinding(
                    suspect_domain=suspect_domain,
                    target_domain=target_domain,
                    distance=distance,
                    within_cutoff=within_cutoff,
                    evidence=evidence,
                )
                findings.append(finding)

        return findings

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """
        Calculate Levenshtein distance between two strings.

        Args:
            s1: First string
            s2: Second string

        Returns:
            Edit distance between the strings
        """
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = list(range(len(s2) + 1))

        for i, c1 in enumerate(s1):
            current_row = [i + 1]

            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)

                current_row.append(min(insertions, deletions, substitutions))

            previous_row = current_row

        return previous_row[-1]

    def _generate_evidence(
        self, suspect_domain: str, target_domain: str, distance: int
    ) -> str:
        """Generate explanation for why this is considered a lookalike."""

        reasons = []

        if distance == 1:
            reasons.append("Single character difference")
        else:
            reasons.append(f"{distance} characters difference")

        # Check for common typosquatting patterns
        if self._is_character_swap(suspect_domain, target_domain):
            reasons.append("Possible character swap")
        elif self._is_missing_character(suspect_domain, target_domain):
            reasons.append("Possible missing character")
        elif self._is_extra_character(suspect_domain, target_domain):
            reasons.append("Possible extra character")
        elif self._is_wrong_character(suspect_domain, target_domain):
            reasons.append("Possible character substitution")

        reasons.append(f"Target: {target_domain}")

        if target_domain in self.BRANDS:
            reasons.append(f"Imitates brand: {self.BRANDS[target_domain]}")

        return "; ".join(reasons)

    def _is_character_swap(self, suspect: str, target: str) -> bool:
        """Check if domains differ by a single character swap."""
        if abs(len(suspect) - len(target)) != 0:
            return False

        differences = []
        for i in range(min(len(suspect), len(target))):
            if suspect[i] != target[i]:
                differences.append((i, suspect[i], target[i]))

        return (
            len(differences) == 2
            and differences[0][1] == differences[1][2]
            and differences[1][1] == differences[0][2]
        )

    def _is_missing_character(self, suspect: str, target: str) -> bool:
        """Check if suspect is missing a character from target."""
        if abs(len(suspect) - len(target)) != 1:
            return False

        # If suspect is longer, then suspect has extra character, not missing
        if len(suspect) > len(target):
            return False

        # suspect is shorter than target, so suspect might be missing a character
        for i in range(len(target)):
            if target[:i] + target[i + 1 :] == suspect:
                return True

        return False

    def _is_extra_character(self, suspect: str, target: str) -> bool:
        """Check if suspect has an extra character compared to target."""
        return self._is_missing_character(target, suspect)

    def _is_wrong_character(self, suspect: str, target: str) -> bool:
        """Check if domains differ by exactly one character substitution."""
        if len(suspect) != len(target):
            return False

        difference_count = 0
        for i in range(len(suspect)):
            if suspect[i] != target[i]:
                difference_count += 1
                if difference_count > 1:
                    return False

        return difference_count == 1


# Global instance for reuse
DETECTOR = EditDistanceDetector()
