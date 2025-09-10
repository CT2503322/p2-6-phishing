from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from email.message import EmailMessage
import re
from backend.ingestion.addresses import AddressUtils
from backend.ingestion.auth_parser import get_auth_data
from backend.ingestion.headers import HeaderNormalizer


@dataclass
class SenderIdentity:
    """Unified sender identity information for phishing detection."""

    # Basic sender information
    from_address: Optional[str] = None
    from_name: Optional[str] = None
    reply_to_address: Optional[str] = None
    reply_to_name: Optional[str] = None

    # Domain analysis
    from_domain: Optional[str] = None
    reply_to_domain: Optional[str] = None
    organizational_domain: Optional[str] = None

    # ESP detection
    email_service_provider: Optional[str] = None
    esp_confidence: float = 0.0
    esp_indicators: List[str] = None

    # Mismatch detection
    has_from_reply_mismatch: bool = False
    mismatch_details: List[str] = None

    # Infrastructure details
    sending_ip: Optional[str] = None
    return_path_domain: Optional[str] = None

    def __post_init__(self):
        if self.esp_indicators is None:
            self.esp_indicators = []
        if self.mismatch_details is None:
            self.mismatch_details = []


class SenderIdentityAnalyzer:
    """Analyzes sender identity from email headers for phishing detection."""

    # Known ESP patterns
    ESP_PATTERNS = {
        "sendgrid": {
            "domains": ["sendgrid.info", "sendgrid.net", r"em\d+\..*\.global"],
            "headers": ["X-SG-EID", "X-SG-ID", "X-SendGrid-Message-ID"],
            "ips": ["149.72.0.0/16", "167.89.0.0/17", "208.117.48.0/20"],
            "return_path_patterns": [r"@.*\.sendgrid\.net", r"@em\d+\..*\.global"],
        },
        "mailchimp": {
            "domains": ["mailchimp.com", "mandrillapp.com"],
            "headers": ["X-MC-User", "X-Mandrill-User", "X-MC-Unique-ID"],
            "return_path_patterns": [r"@.*\.mailchimp\.com", r"@.*\.mandrillapp\.com"],
        },
        "amazon_ses": {
            "domains": ["amazonses.com", "amazonaws.com"],
            "headers": ["X-SES-Outgoing"],
            "return_path_patterns": [r"@.*\.amazonses\.com"],
        },
        "outlook": {
            "domains": ["outlook.com", "hotmail.com", "live.com"],
            "headers": ["X-Mailer"],
            "header_values": {"X-Mailer": "Microsoft Outlook"},
        },
        "gmail": {
            "domains": ["gmail.com", "googlemail.com"],
            "headers": ["X-Google-Smtp-Source"],
        },
        "constant_contact": {
            "domains": ["constantcontact.com", "rsgsv.net"],
            "headers": ["X-RSG-CT-Message-ID"],
            "return_path_patterns": [r"@.*\.rsgsv\.net"],
        },
        "mailgun": {
            "domains": ["mailgun.org", "mailgun.net"],
            "headers": ["X-Mailgun-Sid"],
            "return_path_patterns": [r"@.*\.mailgun\.(org|net)"],
        },
    }

    def __init__(self, msg: EmailMessage):
        self.msg = msg
        self.address_utils = AddressUtils(msg)
        self.header_normalizer = HeaderNormalizer(msg)

    def analyze(self) -> SenderIdentity:
        """Perform complete sender identity analysis."""
        # Get basic sender information
        from_parsed = self.address_utils.get_from_parsed()
        reply_to_parsed = self.address_utils.get_reply_to_parsed()

        from_address = from_parsed[1] if from_parsed else None
        from_name = from_parsed[0] if from_parsed else None
        reply_to_address = reply_to_parsed[1] if reply_to_parsed else None
        reply_to_name = reply_to_parsed[0] if reply_to_parsed else None

        # Extract domains
        from_domain = self._extract_domain(from_address) if from_address else None
        reply_to_domain = (
            self._extract_domain(reply_to_address) if reply_to_address else None
        )

        # Get organizational domains
        organizational_domain = self._extract_organizational_domain(from_domain)

        # Detect ESP
        esp_info = self._detect_esp()

        # Check for mismatches
        mismatch_info = self._check_mismatches(
            from_address, reply_to_address, from_domain, reply_to_domain
        )

        # Extract infrastructure details
        sending_ip = self._extract_sending_ip()
        return_path_domain = self._extract_return_path_domain()

        return SenderIdentity(
            from_address=from_address,
            from_name=from_name,
            reply_to_address=reply_to_address,
            reply_to_name=reply_to_name,
            from_domain=from_domain,
            reply_to_domain=reply_to_domain,
            organizational_domain=organizational_domain,
            email_service_provider=esp_info["provider"],
            esp_confidence=esp_info["confidence"],
            esp_indicators=esp_info["indicators"],
            has_from_reply_mismatch=mismatch_info["has_mismatch"],
            mismatch_details=mismatch_info["details"],
            sending_ip=sending_ip,
            return_path_domain=return_path_domain,
        )

    def _extract_domain(self, email: str) -> Optional[str]:
        """Extract domain from email address."""
        if not email or "@" not in email:
            return None
        return email.split("@")[-1].lower()

    def _extract_organizational_domain(self, domain: str) -> Optional[str]:
        """Extract organizational domain (remove subdomains)."""
        if not domain:
            return None

        parts = domain.split(".")

        # Handle country code TLDs (e.g., .co.uk, .com.au)
        if len(parts) >= 3 and len(parts[-1]) == 2 and len(parts[-2]) <= 3:
            # Country TLD with second level domain
            return ".".join(parts[-3:])
        elif len(parts) >= 2:
            # Regular TLD - take last 2 parts
            return ".".join(parts[-2:])

        return domain

    def _detect_esp(self) -> Dict[str, Any]:
        """Detect email service provider."""
        indicators = []
        confidence_scores = {}

        headers = self.header_normalizer.get_all_headers()

        # Check return path
        return_path = headers.get("Return-Path", "")
        if return_path:
            indicators.append(f"Return-Path: {return_path}")

        # Check for ESP-specific headers and patterns
        for esp_name, patterns in self.ESP_PATTERNS.items():
            score = 0
            esp_indicators = []

            # Check domains in DKIM signatures
            for header_name, header_value in headers.items():
                if "dkim" in header_name.lower() or "domainkey" in header_name.lower():
                    for domain in patterns.get("domains", []):
                        if domain in header_value.lower():
                            score += 2
                            esp_indicators.append(f"DKIM domain: {domain}")

            # Check specific headers
            for header in patterns.get("headers", []):
                if header in headers:
                    score += 3
                    esp_indicators.append(f"Header: {header}")

            # Check header values
            for header, expected_value in patterns.get("header_values", {}).items():
                if headers.get(header) == expected_value:
                    score += 2
                    esp_indicators.append(f"Header value: {header}={expected_value}")

            # Check return path patterns
            for pattern in patterns.get("return_path_patterns", []):
                if re.search(pattern, return_path, re.IGNORECASE):
                    score += 2
                    esp_indicators.append(f"Return-Path pattern: {pattern}")

            # Check IP ranges (simplified check)
            if "sending_ip" in headers.get("Received", ""):
                for ip_range in patterns.get("ips", []):
                    # Simple IP range check - in production, use proper IP range checking
                    if ip_range.split("/")[0] in headers.get("Received", ""):
                        score += 1
                        esp_indicators.append(f"IP range: {ip_range}")

            if score > 0:
                confidence_scores[esp_name] = min(score / 10, 1.0)  # Normalize to 0-1
                indicators.extend(esp_indicators)

        # Find the ESP with highest confidence
        if confidence_scores:
            best_esp = max(confidence_scores.items(), key=lambda x: x[1])
            return {
                "provider": best_esp[0],
                "confidence": best_esp[1],
                "indicators": indicators,
            }

        return {"provider": None, "confidence": 0.0, "indicators": indicators}

    def _check_mismatches(
        self, from_addr: str, reply_to_addr: str, from_domain: str, reply_to_domain: str
    ) -> Dict[str, Any]:
        """Check for From/Reply-To mismatches."""
        has_mismatch = False
        details = []

        if from_addr and reply_to_addr:
            if from_addr != reply_to_addr:
                has_mismatch = True
                details.append(
                    f"Address mismatch: From={from_addr}, Reply-To={reply_to_addr}"
                )

        if from_domain and reply_to_domain:
            if from_domain != reply_to_domain:
                has_mismatch = True
                details.append(
                    f"Domain mismatch: From={from_domain}, Reply-To={reply_to_domain}"
                )

        # Check for suspicious patterns
        if from_addr and reply_to_addr:
            # Different domains but similar local parts (potential spoofing)
            from_local = from_addr.split("@")[0] if "@" in from_addr else ""
            reply_local = reply_to_addr.split("@")[0] if "@" in reply_to_addr else ""

            if (
                from_local
                and reply_local
                and from_local == reply_local
                and from_domain != reply_to_domain
            ):
                has_mismatch = True
                details.append("Potential spoofing: same local part, different domains")

        return {"has_mismatch": has_mismatch, "details": details}

    def _extract_sending_ip(self) -> Optional[str]:
        """Extract sending IP from Received headers."""
        received_headers = self.header_normalizer.get_multi_value_header("Received")

        for received in received_headers:
            # Look for IP patterns in Received headers
            ip_match = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", received)
            if ip_match:
                return ip_match.group(1)

        return None

    def _extract_return_path_domain(self) -> Optional[str]:
        """Extract domain from Return-Path header."""
        return_path = self.header_normalizer.get_header("Return-Path")
        if return_path:
            # Remove angle brackets
            return_path = return_path.strip("<>")
            return self._extract_domain(return_path)
        return None
