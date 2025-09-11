"""
URL security checks for phishing detection.

This module provides comprehensive URL analysis for detecting phishing attempts,
including href/text mismatches, IP literals, URL shorteners, and punycode/IDN attacks.
"""

import re
import ipaddress
from urllib.parse import urlparse, urljoin
from typing import List, Optional, Dict, Tuple
from .models import UrlFinding, RuleScore
from .confusables import DETECTOR


class URLSecurityAnalyzer:
    """Centralized analyzer for URL-based phishing detection."""

    def __init__(self):
        self.shorteners = self._get_url_shorteners()

    def _get_url_shorteners(self) -> set[str]:
        """Get comprehensive list of known URL shorteners."""
        return {
            "bit.ly",
            "t.co",
            "tinyurl.com",
            "goo.gl",
            "cutt.ly",
            "rebrand.ly",
            "lnkd.in",
            "ow.ly",
            "is.gd",
            "buff.ly",
            "adf.ly",
            "bl.ink",
            "linktr.ee",
            "tiny.cc",
            "s.id",
            "s7y.es",
            "shorte.st",
            "adfoc.us",
            "q.gs",
            "po.st",
            "j.mp",
            "fb.me",
            "wp.me",
            "ift.tt",
            "dlvr.it",
            "shar.es",
            "su.pr",
            "ht.ly",
            "cli.gs",
            "tr.im",
            "tiny.ly",
            "v.gd",
            "ur1.ca",
            "snipurl.com",
            "shorturl.at",
            "shorturl.com",
            "x.co",
            "youtu.be",
            "git.io",
        }

    def extract_url_findings(self, html_content: str) -> List[UrlFinding]:
        """
        Extract URLs from HTML content and analyze them for phishing indicators.

        Args:
            html_content: HTML content to analyze

        Returns:
            List of UrlFinding objects with detailed analysis
        """
        if not html_content:
            return []

        findings = []
        seen_urls = set()  # Track unique URLs to avoid duplicates

        # Extract base URL if present for relative link resolution
        base_url = self._extract_base_url(html_content)
        base_parsed = urlparse(base_url) if base_url else None

        # Find all anchor tags with href attributes
        link_pattern = r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>'
        matches = re.findall(link_pattern, html_content, re.IGNORECASE | re.DOTALL)

        for href, anchor_text in matches:
            # Resolve relative URLs to absolute
            absolute_href = self._resolve_url(href, base_url)

            if absolute_href in seen_urls:
                continue
            seen_urls.add(absolute_href)

            # Parse the URL
            parsed_url = urlparse(absolute_href)
            if not parsed_url.netloc:
                continue  # Skip invalid URLs

            # Clean anchor text
            clean_text = self._clean_anchor_text(anchor_text)

            # Analyze URL components
            finding = self.analyze_individual_url(
                absolute_href, clean_text, html_content.find(absolute_href)
            )
            findings.append(finding)

        return findings

    def analyze_individual_url(
        self, url: str, text: str = "", first_seen_pos: int = 0
    ) -> UrlFinding:
        """
        Analyze a single URL for security indicators.

        Args:
            url: The URL to analyze
            text: Associated anchor text
            first_seen_pos: Character position in original content

        Returns:
            UrlFinding with analysis results
        """
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            return UrlFinding(
                text=text,
                href=url,
                netloc="",
                is_ip_literal=False,
                is_punycode=False,
                is_shortener=False,
                text_href_mismatch=False,
                first_seen_pos=first_seen_pos,
                evidence="Invalid URL format",
            )

        # Domain analysis
        netloc = parsed_url.netloc
        is_ip_literal = self._is_ip_literal(netloc)
        is_punycode = netloc.startswith("xn--")
        is_shortener = self._is_url_shortener(netloc)

        # Check for text/href mismatch
        has_mismatch = self._has_text_href_mismatch(text, netloc)

        # Analyze domain for confusables and brand matching
        confusable_finding = DETECTOR.analyze_domain(netloc)

        # Generate evidence
        evidence = self._generate_evidence(
            text,
            url,
            netloc,
            is_ip_literal,
            is_punycode,
            is_shortener,
            has_mismatch,
            confusable_finding.matched_brand,
        )

        if confusable_finding.evidence:
            evidence += f"; {confusable_finding.evidence}"

        return UrlFinding(
            text=text,
            href=url,
            netloc=netloc,
            is_ip_literal=is_ip_literal,
            is_punycode=is_punycode,
            skeleton_match=confusable_finding.skeleton_match,
            is_shortener=is_shortener,
            text_href_mismatch=has_mismatch,
            brand_match=confusable_finding.matched_brand,
            first_seen_pos=first_seen_pos,
            evidence=evidence,
        )

    def detect_url_anomalies(self, content: str) -> List[RuleScore]:
        """
        Detect URL-related security anomalies for scoring.

        Args:
            content: Text content containing URLs

        Returns:
            List of RuleScore objects for detected anomalies
        """
        rules = []
        urls = self._extract_urls_from_content(content)

        for url in urls:
            try:
                parsed = urlparse(url)
                if not parsed.netloc:
                    continue

                # Check for punycode/unicode domains
                if parsed.netloc.startswith("xn--"):
                    rules.append(
                        RuleScore(
                            rule="url_punycode",
                            delta=2.0,
                            evidence=f"Punycode URL detected: {url}",
                        )
                    )

                # Check for IP literals
                if self._is_ip_literal(parsed.netloc):
                    rules.append(
                        RuleScore(
                            rule="url_ip_literal",
                            delta=1.5,
                            evidence=f"IP literal URL detected: {url}",
                        )
                    )

                # Check for URL shorteners
                if self._is_url_shortener(parsed.netloc):
                    rules.append(
                        RuleScore(
                            rule="url_shortener",
                            delta=1.0,
                            evidence=f"URL shortener detected: {url}",
                        )
                    )

                # Check for punycode with suspicious patterns
                if parsed.netloc.startswith("xn--"):
                    decoded_domain = self._decode_punycode_to_ascii(parsed.netloc)
                    if (
                        decoded_domain != parsed.netloc
                        and DETECTOR.analyze_domain(decoded_domain).matched_brand
                    ):
                        rules.append(
                            RuleScore(
                                rule="url_punycode_branding",
                                delta=2.5,
                                evidence=f"Punycode homograph attack suspected: {url} (decodes to {decoded_domain})",
                            )
                        )

            except Exception as e:
                # Log error but don't crash
                print(f"Error analyzing URL {url}: {e}")
                continue

        return rules

    def _extract_base_url(self, html_content: str) -> Optional[str]:
        """Extract base URL from <base href="..."> tag."""
        base_pattern = r'<base[^>]*href=["\']([^"\']+)["\']'
        match = re.search(base_pattern, html_content, re.IGNORECASE)
        return match.group(1) if match else None

    def _resolve_url(self, href: str, base_url: Optional[str]) -> str:
        """Resolve relative URLs to absolute URLs."""
        if not base_url:
            # If href starts with http:// or https://, it's already absolute
            if href.startswith(("http://", "https://")):
                return href
            # Handle protocol-relative URLs
            if href.startswith("//"):
                return f"http:{href}"
            # For other relative URLs without base, assume http://
            if "://" not in href:
                return f"http://{href}"
            return href
        else:
            return urljoin(base_url, href)

    def _clean_anchor_text(self, anchor_text: str) -> str:
        """Clean and normalize anchor text."""
        # Remove HTML tags and extra whitespace
        text = re.sub(r"<[^>]+>", "", anchor_text)
        # Normalize whitespace (convert tabs/newlines to spaces)
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    def _is_ip_literal(self, netloc: str) -> bool:
        """Check if netloc is an IP literal (IPv4 or IPv6)."""
        try:
            # Handle IPv6 addresses in brackets
            if netloc.startswith("[") and "]" in netloc:
                ip_part = netloc[1 : netloc.find("]")]
                ipaddress.IPv6Address(ip_part)
                return True
            else:
                # Handle IPv4 or plain IPv6
                if ":" in netloc:
                    # Check if it looks like IPv6 (multiple colons)
                    colon_count = netloc.count(":")
                    if colon_count > 1:
                        parts = netloc.split(":")
                        if len(parts) > 2:  # More than just host:port
                            ipaddress.IPv6Address(netloc)
                            return True
                    else:
                        # Just one colon - could be IPv4 with port
                        ip_part = netloc.split(":")[0]
                        ipaddress.IPv4Address(ip_part)
                        return True

                # Try IPv4 without port
                ipaddress.IPv4Address(netloc)
                return True
        except ValueError:
            return False

    def _is_url_shortener(self, netloc: str) -> bool:
        """Check if netloc is a known URL shortener service."""
        domain = netloc.lower().split(":")[0]  # Remove port if present
        return domain in self.shorteners

    def _has_text_href_mismatch(self, text: str, netloc: str) -> bool:
        """Check if anchor text looks like a URL/brand but points elsewhere."""
        if not text or not netloc:
            return False

        # Normalize both for comparison
        normalized_netloc = self._normalize_domain(netloc)
        normalized_text = text.lower().strip()

        # Skip trivial matches
        if not normalized_text or len(normalized_text) < 3:
            return False

        # Check if text looks like a URL
        url_like_patterns = [
            r"https?://[^\s]+",  # http:// or https://
            r"www\.[^\s]+",  # www.something
            r"[a-zA-Z0-9-]+\.[a-zA-Z]{2,}",  # domain-like pattern
        ]

        text_looks_like_url = any(
            re.search(pattern, normalized_text, re.IGNORECASE)
            for pattern in url_like_patterns
        )

        # If text looks like a URL, check if domains match
        if text_looks_like_url:
            text_domain = re.search(
                r"(?:https?://|www\.|)([^\s/\?#]+)", normalized_text, re.IGNORECASE
            )
            if text_domain:
                normalized_text_domain = self._normalize_domain(text_domain.group(1))
                return normalized_text_domain != normalized_netloc

        return False

    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain for comparison (remove www. prefix, convert to lowercase)."""
        domain = domain.lower().strip()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain

    def _extract_urls_from_content(self, content: str) -> List[str]:
        """Extract all URLs from content using regex."""
        url_pattern = re.compile(r"https?://[^\s]+")
        return url_pattern.findall(content)

    def _decode_punycode_to_ascii(self, netloc: str) -> str:
        """Decode punycode/IDN domain to ASCII for analysis."""
        if not netloc.startswith("xn--"):
            return netloc

        try:
            ascii_domain = netloc.encode("ascii").decode("idna")
            return ascii_domain
        except:
            return netloc  # Return original if decoding fails

    def _generate_evidence(
        self,
        text: str,
        href: str,
        netloc: str,
        is_ip: bool,
        is_puny: bool,
        is_shortener: bool,
        has_mismatch: bool,
        brand: Optional[str],
    ) -> str:
        """Generate explanation string for the URL finding."""
        reasons = []

        if is_ip:
            if netloc.startswith("[") and "]" in netloc:
                # IPv6 address
                ip_part = netloc[1 : netloc.find("]")]
                reasons.append(f"Uses IPv6 literal ({ip_part}) instead of domain name")
            else:
                # IPv4 address
                ip_part = netloc.split(":")[0] if ":" in netloc else netloc
                reasons.append(f"Uses IPv4 literal ({ip_part}) instead of domain name")
        if is_puny:
            reasons.append("Uses Punycode/IDN encoding")
        if is_shortener:
            reasons.append("Uses URL shortening service")
        if has_mismatch:
            reasons.append(f"Anchor text '{text}' doesn't match domain '{netloc}'")
        if brand:
            reasons.append(f"Domain appears legitimate ({brand})")

        if reasons:
            return "; ".join(reasons)
        else:
            return "Clean URL"


# Global instance for reuse
URL_ANALYZER = URLSecurityAnalyzer()


# Convenience functions for backward compatibility and easy access
def extract_url_findings(html_content: str) -> List[UrlFinding]:
    """Extract and analyze URLs from HTML content."""
    return URL_ANALYZER.extract_url_findings(html_content)


def analyze_url(url: str, text: str = "", first_seen_pos: int = 0) -> UrlFinding:
    """Analyze a single URL for security indicators."""
    return URL_ANALYZER.analyze_individual_url(url, text, first_seen_pos)


def detect_url_anomalies(content: str) -> List[RuleScore]:
    """Detect URL-related security anomalies."""
    return URL_ANALYZER.detect_url_anomalies(content)
