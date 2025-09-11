"""
Authentication checks module for phishing detection.
Provides parsing and verification of email authentication headers (SPF, DKIM, DMARC).
"""

from .auth_headers import get_auth_data, get_raw_auth_headers

__all__ = ["get_auth_data", "get_raw_auth_headers"]
