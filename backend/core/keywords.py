import re
import json
from typing import List, Dict, Tuple, Optional
from pathlib import Path

from backend.core.position import (
    find_keywords_with_positions,
    calculate_positioned_score,
)
from backend.utils.models import KeywordHit

# Configuration file path
CONFIG_PATH = Path(__file__).parent.parent / "data" / "keywords.json"


class KeywordConfig:
    """Manages keyword configuration with weights, variants, and context awareness."""

    def __init__(self, config_path=CONFIG_PATH):
        if isinstance(config_path, str):
            config_path = Path(config_path)
        self.config_path = config_path
        self.keywords = {}
        self.negation_words = []
        self.boosting_multiplier = 1.5
        self.negation_pattern = None

        self._load_config()
        self._compile_patterns()
        self._compile_negation_pattern()

    def _load_config(self):
        """Load keywords configuration from JSON file."""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Keywords config not found: {self.config_path}")

        with open(self.config_path, "r") as f:
            data = json.load(f)

        self.keywords = data.get("keywords", {})
        self.negation_words = data.get("negation_words", [])
        self.boosting_multiplier = data.get("boosting_multiplier", 1.5)

    def _compile_patterns(self):
        """Compile regex patterns for all keyword variants with word boundaries."""
        self.keyword_patterns = {}
        self.variants_map = {}

        for main_keyword, config in self.keywords.items():
            weight = config["weight"]
            variants = config["variants"]
            contexts = config["context"]

            # Create pattern for each variant with word boundaries
            patterns = []
            for variant in variants:
                # Word boundary pattern - handles punctuation and spaces
                pattern = r"\b" + re.escape(variant) + r"\b"
                patterns.append(pattern)

            # Combine all variants for this keyword
            combined_pattern = "|".join(patterns)
            self.keyword_patterns[main_keyword] = re.compile(
                combined_pattern, re.IGNORECASE | re.MULTILINE
            )

            # Map each variant to its primary keyword for later lookup
            for variant in variants:
                self.variants_map[variant] = main_keyword

            # Store original data
            self.keywords[main_keyword]["compiled_pattern"] = self.keyword_patterns[
                main_keyword
            ]

    def _compile_negation_pattern(self):
        """Compile pattern for negation words."""
        if self.negation_words:
            negation_patterns = [
                r"\b" + re.escape(word) + r"\b" for word in self.negation_words
            ]
            self.negation_pattern = re.compile(
                "|".join(negation_patterns), re.IGNORECASE | re.MULTILINE
            )
        else:
            self.negation_pattern = None

    def _has_context_near_match(
        self,
        main_keyword: str,
        text: str,
        match_start: int,
        match_end: int,
        window: int = 100,
    ) -> bool:
        """Check if required context words are present near a keyword match."""
        config = self.keywords[main_keyword]
        required_contexts = config.get("context", [])

        if not required_contexts:
            return False

        # Extend window around the match
        context_start = max(0, match_start - window)
        context_end = min(len(text), match_end + window)
        context_text = text[context_start:context_end]

        # Check if any required context words are present in the context window
        for required_context in required_contexts:
            if required_context.lower() in context_text.lower():
                return True

        return False

    def _is_negated(
        self, text: str, match_start: int, match_end: int, window: int = 50
    ) -> bool:
        """Check if a keyword is negated within a window around it."""
        if not self.negation_pattern:
            return False

        # Check window before match
        before_start = max(0, match_start - window)
        before_text = text[before_start:match_start]
        if self.negation_pattern.search(before_text):
            return True

        # Check window after match (smaller window)
        after_end = min(len(text), match_end + 20)
        after_text = text[match_end:after_end]
        if self.negation_pattern.search(after_text):
            return True

        return False

    def find_keywords_with_context(self, text: str, where: str) -> List[KeywordHit]:
        """Find keywords with context awareness, negations, and position weighting."""
        hits = []

        for main_keyword, config in self.keywords.items():
            pattern = self.keyword_patterns[main_keyword]
            weight = config["weight"]

            for match in pattern.finditer(text):
                match_start = match.start()
                match_end = match.end()

                # Check if keyword is negated
                if self._is_negated(text, match_start, match_end):
                    # Reduce weight for negated keywords (but don't completely eliminate)
                    adjusted_weight = weight * 0.2
                elif self._has_context_near_match(
                    main_keyword, text, match_start, match_end
                ):
                    # Boost weight if context words are near the keyword
                    adjusted_weight = weight * self.boosting_multiplier
                else:
                    # Default weight
                    adjusted_weight = weight

                hits.append(
                    KeywordHit(
                        term=main_keyword,
                        weight=adjusted_weight,
                        where=where,
                        pos=match_start,
                        window=where,
                    )
                )

        return hits

    def reload_config(self):
        """Reload configuration from file (useful for dynamic updates)."""
        self._load_config()
        self._compile_patterns()
        if hasattr(self, "_compile_negation_pattern"):
            self._compile_negation_pattern()


# Global keyword configuration instance
keyword_config = KeywordConfig()

# Maintain backward compatibility
WORDS = list(keyword_config.keyword_patterns.keys())
KEYWORD_WEIGHTS = {k: v["weight"] for k, v in keyword_config.keywords.items()}
WORD_PATTERNS = keyword_config.keyword_patterns


def find(text: str) -> List[Dict[str, int]]:
    """
    Legacy function - Find occurrences of phishing keywords in the given text.

    Args:
        text: Input text to search

    Returns:
        List of dicts with keyword and count (deprecated - use find_keywords_with_positions)
    """
    if not text:
        return []

    out = []
    for word, pattern in WORD_PATTERNS.items():
        count = len(pattern.findall(text))
        if count > 0:
            out.append({"keyword": word, "count": count})
    return out


def analyze_keywords(
    subject: str, body_text: str, use_positions: bool = True, use_context: bool = False
) -> Dict[str, any]:
    """
    Analyze keywords in subject and body with optional position weighting and context awareness.

    Args:
        subject: Email subject line
        body_text: Cleaned email body text
        use_positions: Whether to use position-based weighting
        use_context: Whether to use context-aware keyword detection

    Returns:
        Dictionary with keyword analysis results
    """
    if use_context:
        # Use new context-aware keyword detection
        return analyze_keywords_with_context(subject, body_text, use_positions)
    elif use_positions:
        return calculate_positioned_score(subject, body_text, KEYWORD_WEIGHTS)
    else:
        # Legacy simple count-based approach
        subject_hits = find(subject) if subject else []
        body_hits = find(body_text) if body_text else []

        # Convert to new format for consistency
        keyword_hits = []
        total_score = 0.0

        # Process subject hits
        for hit in subject_hits:
            keyword = hit["keyword"]
            count = hit["count"]
            base_weight = KEYWORD_WEIGHTS.get(keyword, 1.0)

            for i in range(count):
                keyword_hits.append(
                    KeywordHit(
                        term=keyword,
                        weight=base_weight,
                        where="subject",
                        pos=0,  # Not tracking positions in legacy mode
                        window="subject",
                    )
                )
                total_score += base_weight

        # Process body hits
        for hit in body_hits:
            keyword = hit["keyword"]
            count = hit["count"]
            base_weight = KEYWORD_WEIGHTS.get(keyword, 1.0)

            for i in range(count):
                keyword_hits.append(
                    KeywordHit(
                        term=keyword,
                        weight=base_weight,
                        where="body",
                        pos=0,  # Not tracking positions in legacy mode
                        window="body",
                    )
                )
                total_score += base_weight

        return {
            "keyword_hits": keyword_hits,
            "term_stats": _build_term_stats(keyword_hits),
            "total_score": total_score,
        }


def analyze_keywords_with_context(
    subject: str, body_text: str, use_positions: bool = True
) -> Dict[str, any]:
    """
    Analyze keywords with context awareness - detects negations and context-based boosting.

    Args:
        subject: Email subject line
        body_text: Cleaned email body text
        use_positions: Whether to apply position-based weighting on top of context detection

    Returns:
        Dictionary with keyword analysis results
    """
    keyword_hits = []

    # Analyze subject
    if subject:
        subject_hits = keyword_config.find_keywords_with_context(subject, "subject")
        keyword_hits.extend(subject_hits)

    # Analyze body
    if body_text:
        body_hits = keyword_config.find_keywords_with_context(body_text, "body")
        keyword_hits.extend(body_hits)

    if use_positions:
        # Apply position weighting on top of context-aware weights
        from backend.core.position import PositionScorer

        scorer = PositionScorer()
        for hit in keyword_hits:
            original_weight = hit.weight
            context_weight = (
                original_weight  # This already includes context adjustments
            )
            position_weight = scorer.score_hit(hit)
            hit.weight = position_weight  # Update with position-adjusted weight

    total_score = sum(hit.weight for hit in keyword_hits)
    term_stats = _build_term_stats(keyword_hits)

    return {
        "keyword_hits": keyword_hits,
        "term_stats": term_stats,
        "total_score": total_score,
    }


def _build_term_stats(hits: List[KeywordHit]) -> Dict[str, Dict]:
    """Build term statistics from hits."""
    term_stats = {}
    for hit in hits:
        if hit.term not in term_stats:
            term_stats[hit.term] = {
                "count": 0,
                "total_score": 0.0,
                "positions": [],
                "windows": [],
            }

        term_stats[hit.term]["count"] += 1
        term_stats[hit.term]["total_score"] += hit.weight
        term_stats[hit.term]["positions"].append(hit.pos)
        term_stats[hit.term]["windows"].append(hit.window)

    return term_stats
