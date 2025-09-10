import email.utils
from email.header import decode_header, make_header
from typing import Dict, List, Optional, Any
from datetime import datetime
from email.message import EmailMessage
import re
from backend.ingestion.models import SubscriptionMetadata, ListUnsubscribe


class HeaderNormalizer:
    def __init__(self, msg: EmailMessage):
        self.msg = msg

    def get_header(self, key: str, case_insensitive: bool = True) -> Optional[str]:
        """
        Get header value with case-insensitive access.
        """
        if case_insensitive:
            for k, v in self.msg.items():
                if k.lower() == key.lower():
                    return self._normalize_header_value(str(v))
        else:
            value = self.msg.get(key)
            if value:
                return self._normalize_header_value(str(value))
        return None

    def _normalize_header_value(self, value: str) -> str:
        """
        Unfold and decode header value.
        """
        try:
            # Unfold: replace line breaks with spaces
            unfolded = value.replace("\n", " ").replace("\r", " ")
            # Decode RFC 2047 tokens
            decoded_parts = decode_header(unfolded)
            decoded = make_header(decoded_parts)
            return str(decoded)
        except Exception:
            # Return original value if decoding fails
            return value

    def get_all_headers(self) -> Dict[str, str]:
        """
        Get all headers normalized.
        """
        headers = {}
        for key, value in self.msg.items():
            headers[key] = self._normalize_header_value(str(value))
        return headers

    def get_multi_value_header(self, key: str) -> List[str]:
        """
        Get multi-value headers like Received.
        """
        values = []
        for k, v in self.msg.items():
            if k.lower() == key.lower():
                values.append(self._normalize_header_value(str(v)))
        return values

    def get_subscription_metadata(self) -> SubscriptionMetadata:
        """
        Extract subscription metadata from email headers.
        """
        # Get List-Unsubscribe header
        list_unsubscribe_header = self.get_header("List-Unsubscribe")
        list_unsubscribe = None

        if list_unsubscribe_header:
            list_unsubscribe = self._parse_list_unsubscribe(list_unsubscribe_header)

        # Get List-Unsubscribe-Post header
        list_unsubscribe_post = self.get_header("List-Unsubscribe-Post")

        # Get Feedback-ID header
        feedback_id = self.get_header("Feedback-ID")

        # Get Precedence header
        precedence = self.get_header("Precedence")

        return SubscriptionMetadata(
            list_unsubscribe=list_unsubscribe,
            list_unsubscribe_post=list_unsubscribe_post,
            feedback_id=feedback_id,
            precedence=precedence,
        )

    def _parse_list_unsubscribe(self, header_value: str) -> ListUnsubscribe:
        """
        Parse List-Unsubscribe header value.
        Format: <https://example.com/unsubscribe>, <mailto:unsubscribe@example.com?subject=...>
        """
        one_click = False
        http_url = None
        mailto = None
        mailto_subject = None
        provider = None

        # Check if List-Unsubscribe-Post exists to determine one-click
        post_header = self.get_header("List-Unsubscribe-Post")
        if post_header and "One-Click" in post_header:
            one_click = True

        # Parse the header value for URLs and mailto
        # Remove angle brackets and split by comma
        parts = [part.strip().strip("<>").strip() for part in header_value.split(",")]

        for part in parts:
            if part.startswith("http"):
                http_url = part
                # Try to extract provider from URL
                if "sendgrid" in part.lower():
                    provider = "sendgrid"
                elif "mailchimp" in part.lower():
                    provider = "mailchimp"
                elif "constantcontact" in part.lower():
                    provider = "constantcontact"
            elif part.startswith("mailto:"):
                mailto = part[7:]  # Remove 'mailto:'
                # Parse subject from mailto
                if "?" in mailto:
                    mailto_parts = mailto.split("?", 1)
                    mailto = mailto_parts[0]
                    query = mailto_parts[1]
                    if "subject=" in query:
                        subject_match = re.search(r"subject=([^&]+)", query)
                        if subject_match:
                            mailto_subject = subject_match.group(1).replace("%20", " ")

        return ListUnsubscribe(
            one_click=one_click,
            http=http_url,
            mailto=mailto,
            mailto_subject=mailto_subject,
            provider=provider,
        )


def get_date(date_header: str) -> Optional[datetime]:
    """
    Parse Date header to timezone-aware datetime.
    """
    try:
        dt = email.utils.parsedate_to_datetime(date_header)
        if dt and dt.tzinfo is not None:
            return dt
        return None  # Return None if no timezone info
    except (ValueError, TypeError):
        return None
