from typing import List, Tuple, Optional
import email.utils
from email.message import EmailMessage


class AddressUtils:
    def __init__(self, msg: EmailMessage):
        self.msg = msg

    def get_from(self) -> Optional[str]:
        """Get raw From header."""
        return self.msg.get("From")

    def get_to(self) -> Optional[str]:
        """Get raw To header."""
        return self.msg.get("To")

    def get_cc(self) -> Optional[str]:
        """Get raw Cc header."""
        return self.msg.get("Cc")

    def get_bcc(self) -> Optional[str]:
        """Get raw Bcc header."""
        return self.msg.get("Bcc")

    def get_reply_to(self) -> Optional[str]:
        """Get raw Reply-To header."""
        return self.msg.get("Reply-To")

    def get_from_emails(self) -> List[str]:
        """Get list of email addresses from From header."""
        from_header = self.get_from()
        if not from_header:
            return []
        try:
            addresses = email.utils.getaddresses([from_header])
            return [email for name, email in addresses if email]
        except Exception:
            return []

    def get_to_emails(self) -> List[str]:
        """Get list of email addresses from To header."""
        to_header = self.get_to()
        if not to_header:
            return []
        try:
            addresses = email.utils.getaddresses([to_header])
            return [email for name, email in addresses if email]
        except Exception:
            return []

    def get_cc_emails(self) -> List[str]:
        """Get list of email addresses from Cc header."""
        cc_header = self.get_cc()
        if not cc_header:
            return []
        try:
            addresses = email.utils.getaddresses([cc_header])
            return [email for name, email in addresses if email]
        except Exception:
            return []

    def get_bcc_emails(self) -> List[str]:
        """Get list of email addresses from Bcc header."""
        bcc_header = self.get_bcc()
        if not bcc_header:
            return []
        try:
            addresses = email.utils.getaddresses([bcc_header])
            return [email for name, email in addresses if email]
        except Exception:
            return []

    def get_reply_to_emails(self) -> List[str]:
        """Get list of email addresses from Reply-To header."""
        reply_to_header = self.get_reply_to()
        if not reply_to_header:
            return []
        try:
            addresses = email.utils.getaddresses([reply_to_header])
            return [email for name, email in addresses if email]
        except Exception:
            return []

    def get_from_names(self) -> List[str]:
        """Get list of names from From header."""
        from_header = self.get_from()
        if not from_header:
            return []
        try:
            addresses = email.utils.getaddresses([from_header])
            return [name for name, email in addresses]
        except Exception:
            return []

    def get_to_names(self) -> List[str]:
        """Get list of names from To header."""
        to_header = self.get_to()
        if not to_header:
            return []
        try:
            addresses = email.utils.getaddresses([to_header])
            return [name for name, email in addresses]
        except Exception:
            return []

    def get_cc_names(self) -> List[str]:
        """Get list of names from Cc header."""
        cc_header = self.get_cc()
        if not cc_header:
            return []
        try:
            addresses = email.utils.getaddresses([cc_header])
            return [name for name, email in addresses]
        except Exception:
            return []

    def get_bcc_names(self) -> List[str]:
        """Get list of names from Bcc header."""
        bcc_header = self.get_bcc()
        if not bcc_header:
            return []
        try:
            addresses = email.utils.getaddresses([bcc_header])
            return [name for name, email in addresses]
        except Exception:
            return []

    def get_reply_to_names(self) -> List[str]:
        """Get list of names from Reply-To header."""
        reply_to_header = self.get_reply_to()
        if not reply_to_header:
            return []
        try:
            addresses = email.utils.getaddresses([reply_to_header])
            return [name for name, email in addresses]
        except Exception:
            return []

    def get_from_parsed(self) -> Optional[Tuple[str, str]]:
        """Get parsed From header as (name, email) tuple."""
        from_header = self.get_from()
        if not from_header:
            return None
        try:
            addresses = email.utils.getaddresses([from_header])
            if addresses:
                return addresses[0]
        except Exception:
            pass
        return None

    def get_to_parsed(self) -> List[Tuple[str, str]]:
        """Get parsed To header as list of (name, email) tuples."""
        to_header = self.get_to()
        if not to_header:
            return []
        try:
            return email.utils.getaddresses([to_header])
        except Exception:
            return []

    def get_cc_parsed(self) -> List[Tuple[str, str]]:
        """Get parsed Cc header as list of (name, email) tuples."""
        cc_header = self.get_cc()
        if not cc_header:
            return []
        try:
            return email.utils.getaddresses([cc_header])
        except Exception:
            return []

    def get_bcc_parsed(self) -> List[Tuple[str, str]]:
        """Get parsed Bcc header as list of (name, email) tuples."""
        bcc_header = self.get_bcc()
        if not bcc_header:
            return []
        try:
            return email.utils.getaddresses([bcc_header])
        except Exception:
            return []

    def get_reply_to_parsed(self) -> Optional[Tuple[str, str]]:
        """Get parsed Reply-To header as (name, email) tuple."""
        reply_to_header = self.get_reply_to()
        if not reply_to_header:
            return None
        try:
            addresses = email.utils.getaddresses([reply_to_header])
            if addresses:
                return addresses[0]
        except Exception:
            pass
        return None
