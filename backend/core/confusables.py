"""
Confusable character and IDN detection for phishing domain analysis.

This module implements detection of homoglyph attacks where attackers use
similar-looking characters from different scripts to spoof legitimate brands.
"""

from dataclasses import dataclass
from typing import Optional, List, Dict, Set
import unicodedata
import re
from urllib.parse import urlparse


@dataclass
class ConfusableFinding:
    """Data structure for confusable character detection findings."""

    domain: str
    original_domain: str  # The domain being analyzed
    matched_brand: Optional[str] = None
    unicode_replacements: List[str] = None  # List of altered characters
    skeleton_match: bool = False  # True if domain skeleton matches a brand
    brand_similarity_score: float = 0.0  # 0.0 to 1.0 similarity score
    evidence: str = ""  # Detailed explanation of findings

    def __post_init__(self):
        if self.unicode_replacements is None:
            self.unicode_replacements = []


class ConfusableDetector:
    """Detects confusable characters and IDN-based phishing attempts."""

    # Known brands and their domain patterns (for skeleton matching)
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

    # Similar-looking characters (homoglyphs)
    CONFUSABLES = {
        # Latin vs Cyrillic
        "a": ["а", "а", "ɑ", "\u0430"],  # a, cyrillic a, latin alpha, etc.
        "b": ["Ь", "Ь", "ƅ"],  # b vs cyrillic soft sign
        "c": ["с", "с"],  # c vs cyrillic es
        "d": ["ԁ", "ԁ"],  # d vs cyrillic d
        "e": ["е", "е"],  # e vs cyrillic e
        "f": ["f", "ƒ"],  # f vs florin sign
        "g": ["ɢ", "ɢ"],  # g vs latin gamma
        "h": ["һ", "һ"],  # h vs cyrillic h
        "i": ["і", "і", "ɪ"],  # i vs cyrillic i, latin iota
        "j": ["ј", "ј"],  # j vs cyrillic j
        "k": ["κ", "κ"],  # k vs greek kappa
        "l": ["l", "ı"],  # l vs turkish i
        "m": ["м", "м"],  # m vs cyrillic m
        "n": ["n", "η"],  # n vs greek eta
        "o": ["o", "ο", "о"],  # o vs greek omicron, cyrillic o
        "p": ["р", "р"],  # p vs cyrillic er
        "q": ["q", "գ"],  # q vs armenian q
        "r": ["г", "г"],  # r vs cyrillic g
        "s": ["s", "ѕ", "ƽ"],  # s vs cyrillic s, latin s with stroke
        "t": ["t", "τ"],  # t vs greek tau
        "u": ["u", "υ"],  # u vs greek upsilon
        "v": ["v", "ν"],  # v vs greek nu
        "w": ["w", "ω"],  # w vs greek omega
        "x": ["x", "х", "×"],  # x vs cyrillic kh, multiplication sign
        "y": ["y", "у", "γ"],  # y vs cyrillic u, greek gamma
        "z": ["z", "Ƶ"],  # z vs latin z with stroke
        # Numbers vs letters
        "0": ["o", "Ο", "о"],  # 0 vs o
        "1": ["l", "I", "ı"],  # 1 vs l, I
        "2": ["2"],  # No common confusables
        "3": ["3"],  # No common confusables
        "4": ["4"],  # No common confusables
        "5": ["s", "ƽ"],  # 5 vs s
        "6": ["6"],  # No common confusables
        "7": ["7"],  # No common confusables
        "8": ["8"],  # No common confusables
        "9": ["9"],  # No common confusables
    }

    def __init__(self):
        # Pre-compile reverse mapping for faster lookups
        self.reverse_confusables = self._build_reverse_mapping()

    def _build_reverse_mapping(self) -> Dict[str, str]:
        """Build reverse mapping from confusable char to original."""
        mapping = {}
        for original, confusables in self.CONFUSABLES.items():
            for confusable in confusables:
                mapping[confusable] = original
        return mapping

    def analyze_domain(self, domain: str) -> ConfusableFinding:
        """
        Analyze a domain for confusable characters and brand spoofing.

        Args:
            domain: The domain name to analyze

        Returns:
            ConfusableFinding with analysis results
        """
        if not domain:
            return ConfusableFinding(domain, "")

        finding = ConfusableFinding(domain, domain)

        # Detect Unicode/non-ASCII characters
        unicode_chars = self._detect_unicode_chars(domain)
        finding.unicode_replacements = unicode_chars

        # Check for punycode/IDN
        if domain.startswith("xn--"):
            finding.evidence = "Uses punycode IDN encoding"

        # Build ASCII skeleton by mapping confusables back to original
        skeleton = self._build_skeleton(domain)

        # Check for brand matches
        brand_match = self._check_brand_match(domain, skeleton)
        if brand_match:
            finding.matched_brand = brand_match["brand"]
            finding.brand_similarity_score = brand_match["score"]
            finding.skeleton_match = brand_match["skeleton_match"]
            finding.evidence += f"; Potential spoofing of {brand_match['brand']}"

        return finding

    def _detect_unicode_chars(self, domain: str) -> List[str]:
        """Detect non-ASCII/Unicode characters in domain."""
        unicode_chars = []
        for char in domain:
            if ord(char) > 127:  # Non-ASCII
                unicode_chars.append(char)
        return unicode_chars

    def _build_skeleton(self, domain: str) -> str:
        """Build ASCII skeleton by mapping confusables to original chars."""
        if domain.startswith("xn--"):
            # Convert punycode to ASCII
            try:
                ascii_domain = domain.encode("ascii").decode("idna")
                domain = ascii_domain
            except:
                pass  # Keep original if punycode decode fails

        skeleton = []
        for char in domain.lower():
            if char in self.reverse_confusables:
                skeleton.append(self.reverse_confusables[char])
            elif ord(char) > 127:
                # For other Unicode chars, try to find a base equivalent
                decomposed = unicodedata.normalize("NFD", char)
                base_char = decomposed[0] if len(decomposed) > 1 else char
                if base_char in self.reverse_confusables:
                    skeleton.append(self.reverse_confusables[base_char])
                else:
                    skeleton.append(char)
            else:
                skeleton.append(char)
        return "".join(skeleton)

    def _check_brand_match(self, domain: str, skeleton: str) -> Optional[Dict]:
        """Check if domain resembles a known brand."""
        # Calculate similarity scores for both original and skeleton
        matches = []

        for brand_domain, brand_name in self.BRANDS.items():
            original_score = self._calculate_domain_similarity(domain, brand_domain)
            skeleton_score = self._calculate_domain_similarity(skeleton, brand_domain)

            if original_score > 0.8 or skeleton_score > 0.8:
                best_score = max(original_score, skeleton_score)
                skeleton_match = skeleton_score > original_score
                matches.append(
                    {
                        "brand": brand_name,
                        "brand_domain": brand_domain,
                        "score": best_score,
                        "skeleton_match": skeleton_match,
                    }
                )

        # Return the best match if any found
        if matches:
            best_match = max(matches, key=lambda x: x["score"])
            return best_match

        return None

    def _calculate_domain_similarity(self, domain1: str, domain2: str) -> float:
        """Calculate similarity score between two domains."""
        if not domain1 or not domain2:
            return 0.0

        # Exact match
        if domain1.lower() == domain2.lower():
            return 1.0

        # Remove tld and compare base domains
        domain1_base = self._extract_domain_base(domain1)
        domain2_base = self._extract_domain_base(domain2)

        if not domain1_base or not domain2_base:
            return 0.0

        # Calculate character-level similarity
        return self._string_similarity(domain1_base, domain2_base)

    def _extract_domain_base(self, domain: str) -> str:
        """Extract the base domain without TLD."""
        if "." not in domain:
            return domain.lower()

        parts = domain.lower().split(".")

        # Handle country code TLDs (e.g., .co.uk, .com.au)
        # Check if we have at least 3 parts and the last two might form a country TLD
        if len(parts) >= 3:
            # Common country TLD patterns: ccTLD with second level domain
            potential_tld = f"{parts[-2]}.{parts[-1]}"
            known_country_tlds = {
                "co.uk",
                "co.jp",
                "co.kr",
                "co.in",
                "co.za",
                "co.nz",
                "com.au",
                "com.sg",
                "com.tw",
                "com.br",
                "com.mx",
                "com.tr",
                "ac.uk",
                "gov.uk",
                "org.uk",
                "ltd.uk",
                "me.uk",
                "net.uk",
                "com.cn",
                "com.hk",
                "com.my",
                "com.ph",
                "com.vn",
            }

            if potential_tld in known_country_tlds:
                # Use the country TLD pattern - take all parts except the last two
                return ".".join(parts[:-2]) if len(parts) > 2 else parts[0]

        # Regular case: take all parts except the last one
        if len(parts) >= 2:
            return ".".join(parts[:-1])

        return domain.lower()

    def _string_similarity(self, str1: str, str2: str) -> float:
        """Calculate string similarity using simple ratio."""
        if not str1 and not str2:
            return 1.0
        if not str1 or not str2:
            return 0.0

        # Simple length-based similarity
        min_len = min(len(str1), len(str2))
        max_len = max(len(str1), len(str2))

        if max_len == 0:
            return 1.0

        # Count matching characters in positions
        matches = sum(1 for i in range(min_len) if str1[i] == str2[i])
        return matches / max_len

    def should_apply_brand_boost(self, finding: ConfusableFinding) -> bool:
        """Check if finding qualifies for scoring boost."""
        return (
            finding.matched_brand is not None and finding.brand_similarity_score > 0.8
        )


# Global instance for reuse
DETECTOR = ConfusableDetector()
