from typing import Dict, List, Optional, Tuple
from backend.utils.models import RuleScore, ReplyToFinding


class ReplyToAnalyzer:
    """Analyze Reply-To vs From header inconsistencies for phishing detection."""

    def __init__(self):
        pass

    def analyze_mismatch(
        self,
        from_address: Optional[str],
        from_domain: Optional[str],
        reply_to_address: Optional[str],
        reply_to_domain: Optional[str],
    ) -> ReplyToFinding:
        """
        Analyze Reply-To vs From header mismatch.

        Args:
            from_address: From email address
            from_domain: Domain extracted from From
            reply_to_address: Reply-To email address
            reply_to_domain: Domain extracted from Reply-To

        Returns:
            ReplyToFinding with mismatch details and severity
        """
        has_mismatch = False
        severity = 0.0
        reasons = []

        # Address level mismatch
        if from_address and reply_to_address and from_address != reply_to_address:
            has_mismatch = True
            reasons.append("Address mismatch")
            severity += 1.0

        # Domain level mismatch
        if from_domain and reply_to_domain and from_domain != reply_to_domain:
            has_mismatch = True
            if self._is_suspicious_domain_change(from_domain, reply_to_domain):
                severity += 2.0
                reasons.append("Suspicious domain mismatch")
            else:
                severity += 1.0
                reasons.append("Domain mismatch")

        # Same username, different domain (spoofing indicator)
        if from_address and reply_to_address and from_domain != reply_to_domain:
            from_user = from_address.split("@")[0] if "@" in from_address else ""
            reply_user = (
                reply_to_address.split("@")[0] if "@" in reply_to_address else ""
            )

            if from_user and reply_user and from_user == reply_user:
                has_mismatch = True
                severity += 2.5
                reasons.append("Potential username spoofing")

        return ReplyToFinding(
            has_mismatch=has_mismatch,
            severity=severity,
            reasons=reasons,
            from_address=from_address,
            reply_to_address=reply_to_address,
        )

    def _is_suspicious_domain_change(
        self, from_domain: str, reply_to_domain: str
    ) -> bool:
        """
        Determine if domain change is suspicious.

        Args:
            from_domain: Original domain
            reply_to_domain: Reply-To domain

        Returns:
            True if suspicious
        """
        suspicious_patterns = {
            "similarity": True,  # Domains that look similar
            "organization_change": True,  # Different organization
            "country_tld": True,  # Country-level change
        }

        # Check if domains are visually similar (potential typosquatting)
        if self._domains_similar(from_domain, reply_to_domain):
            return True

        # Check organization level change
        from_org = self._extract_organization_domain(from_domain)
        reply_org = self._extract_organization_domain(reply_to_domain)

        if from_org != reply_org:
            return True

        return False

    def _domains_similar(self, domain1: str, domain2: str) -> bool:
        """
        Check if two domains are visually similar (potential typosquatting).
        """
        if not domain1 or not domain2:
            return False

        # Simple edit distance (leveraging existing implementation if available)
        # For now, use basic string similarity
        domain1_clean = domain1.lower().replace("-", "").replace(".", "")
        domain2_clean = domain2.lower().replace("-", "").replace(".", "")

        # Exact match after cleaning
        if domain1_clean == domain2_clean:
            return True

        # Character swap (e.g., example.com vs exmaple.com)
        if len(domain1_clean) == len(domain2_clean):
            diff_count = sum(c1 != c2 for c1, c2 in zip(domain1_clean, domain2_clean))
            return diff_count <= 2 and diff_count > 0

        return False

    def _extract_organization_domain(self, domain: str) -> str:
        """
        Extract organizational domain (e.g., gmail.com from mail.google.com).
        """
        if not domain:
            return ""

        parts = domain.split(".")
        if len(parts) <= 2:
            return domain
        # For now, return last two parts for simplicity
        return ".".join(parts[-2:])

    def generate_rule_scores(
        self, finding: ReplyToFinding, threshold: float = 1.5
    ) -> List[RuleScore]:
        """
        Generate rule scores based on Reply-To finding.

        Args:
            finding: ReplyToFinding from analysis
            threshold: Minimum severity to generate rule

        Returns:
            List of RuleScore objects
        """
        rules = []

        if not finding.has_mismatch or finding.severity < threshold:
            return rules

        evidence = f"Reply-To mismatch detected ({finding.severity:.1f} severity): {', '.join(finding.reasons)}"
        if finding.severity >= 2.0:
            rules.append(
                RuleScore(
                    rule="replyto_mismatch_high",
                    delta=min(finding.severity, 3.0),
                    evidence=evidence,
                )
            )
        else:
            rules.append(
                RuleScore(
                    rule="replyto_mismatch_low",
                    delta=min(finding.severity, 2.0),
                    evidence=evidence,
                )
            )

        return rules


# Convenience functions
def analyze_replyto_from_mismatch(
    from_address: Optional[str],
    from_domain: Optional[str],
    reply_to_address: Optional[str],
    reply_to_domain: Optional[str],
) -> ReplyToFinding:
    """
    Convenience function to analyze Reply-To vs From mismatch.
    """
    analyzer = ReplyToAnalyzer()
    return analyzer.analyze_mismatch(
        from_address, from_domain, reply_to_address, reply_to_domain
    )


def check_replyto_from_rules(
    from_address: Optional[str],
    from_domain: Optional[str],
    reply_to_address: Optional[str],
    reply_to_domain: Optional[str],
    threshold: float = 1.5,
) -> List[RuleScore]:
    """
    Convenience function to get rule scores for Reply-To mismatch.
    """
    analyzer = ReplyToAnalyzer()
    finding = analyzer.analyze_mismatch(
        from_address, from_domain, reply_to_address, reply_to_domain
    )
    return analyzer.generate_rule_scores(finding, threshold)
