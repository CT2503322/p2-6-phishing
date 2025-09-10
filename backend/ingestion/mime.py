import email
from email import policy
from email.parser import BytesParser
from email.header import decode_header, make_header
from typing import List, Dict, Optional, Any, Union
from email.message import EmailMessage
from io import BytesIO
from email.generator import BytesGenerator
import hashlib
import re
from .models import Attachment, InlineImage, MimePart


class MultiPartParser:
    """
    Parser for MIME email parts with support for attachments and inline images.
    """

    def __init__(
        self,
        raw_eml_bytes: Optional[bytes] = None,
        message: Optional[EmailMessage] = None,
    ):
        """
        Initialize parser with raw bytes or pre-parsed message.

        Args:
            raw_eml_bytes: Raw email bytes to parse
            message: Pre-parsed EmailMessage (for subparts)
        """
        if message is not None:
            self.message = message
        elif raw_eml_bytes is not None:
            self.parser = BytesParser(policy=policy.default)
            try:
                self.message = self.parser.parsebytes(raw_eml_bytes)
            except Exception as e:
                # If parsing fails, create an empty message
                self.message = EmailMessage()
        else:
            self.message = EmailMessage()

        self._content_type = self._parse_content_type()
        self.is_attachment = self._is_attachment()
        self.is_inline_image = self._is_inline_image()

    def _parse_content_type(self) -> Dict[str, Optional[str]]:
        try:
            ctype = self.message.get_content_type()
            if ctype:
                maintype, subtype = (
                    ctype.split("/", 1) if "/" in ctype else (ctype, None)
                )
                charset = self.message.get_param("charset")
                boundary = self.message.get_param("boundary")
                return {
                    "media_type": maintype,
                    "sub_type": subtype,
                    "charset": charset,
                    "boundary": boundary,
                }
        except Exception:
            pass
        return {"media_type": None, "sub_type": None, "charset": None, "boundary": None}

    def _is_attachment(self) -> bool:
        disposition = self.message.get("Content-Disposition", "").lower()
        return "attachment" in disposition

    def _is_inline_image(self) -> bool:
        try:
            disposition = self.message.get("Content-Disposition", "").lower()
            ctype = self.message.get_content_type()
            cid = self.get_content_id()
            return (
                "inline" in disposition
                and ctype
                and ctype.startswith("image/")
                and cid is not None
            )
        except Exception:
            return False

    def get_header(
        self, key: str, decode: bool = False, remove_line_breaks: bool = False
    ) -> Optional[str]:
        value = self.message.get(key)
        if value is None:
            return None

        value_str = str(value)

        if decode:
            try:
                # Decode RFC 2047 encoded headers
                decoded_parts = decode_header(value_str)
                decoded = make_header(decoded_parts)
                value_str = str(decoded)
            except Exception:
                # Return original value if decoding fails
                pass

        if remove_line_breaks:
            value_str = value_str.replace("\n", " ").replace("\r", "")

        return value_str

    def get_body(self) -> Optional[str]:
        if self.message.is_multipart():
            return (
                None  # Or handle differently, but per task, probably for non-multipart
            )
        try:
            content = self.message.get_content()
            if isinstance(content, str):
                return content.rstrip("\n")
            return content
        except:
            return None

    def get_content_type(self) -> Dict[str, Optional[str]]:
        return self._content_type

    def get_multi_parts(self) -> List["MultiPartParser"]:
        """
        Get list of sub-part parsers for multipart messages.

        Returns:
            List of MultiPartParser instances for each subpart
        """
        if not self.message.is_multipart():
            return []

        parts = []
        try:
            for part in self.message.get_payload():
                if isinstance(part, EmailMessage):
                    # Use optimized constructor with pre-parsed message
                    parts.append(MultiPartParser(message=part))
        except Exception as e:
            # Log error but continue processing
            pass
        return parts

    def get_filename(self) -> Optional[str]:
        try:
            filename = self.message.get_filename()
            return filename
        except Exception:
            return None

    def get_content_id(self) -> Optional[str]:
        cid = self.message.get("Content-ID")
        if cid:
            # Remove angle brackets if present
            cid = cid.strip("<>")
        return cid

    @property
    def content_type(self) -> Optional[str]:
        try:
            return self.message.get_content_type()
        except Exception:
            return None

    def get_content_bytes(self) -> Optional[bytes]:
        """
        Get the raw bytes content of the message part.

        Returns:
            Bytes content if available, None otherwise
        """
        if self.message.is_multipart():
            return None

        try:
            content = self.message.get_payload(decode=True)
            if isinstance(content, bytes):
                return content
            elif isinstance(content, str):
                # Encode string to bytes if needed
                return content.encode("utf-8", errors="replace")
            return None
        except (AttributeError, TypeError, UnicodeEncodeError):
            return None

    def get_attachments(self) -> List[Attachment]:
        attachments = []
        if not self.message.is_multipart():
            # Check if it's an attachment: Content-Disposition: attachment OR filename present (and not cid-referenced inline)
            disposition = self.message.get("Content-Disposition", "").lower()
            filename = self.get_filename()
            cid = self.get_content_id()
            is_inline_with_cid = "inline" in disposition and cid is not None
            if "attachment" in disposition or (filename and not is_inline_with_cid):
                content = self.get_content_bytes()
                if content:
                    filename = filename or "unknown"
                    ctype = self.content_type or "application/octet-stream"
                    attachments.append(
                        Attachment(
                            filename=filename,
                            content_type=ctype,
                            content=content,
                            filesize=len(content),
                            content_id=cid,
                            content_disposition=self.message.get("Content-Disposition"),
                        )
                    )
        else:
            for part in self.get_multi_parts():
                attachments.extend(part.get_attachments())
        return attachments

    def get_inline_images(self) -> List[InlineImage]:
        images = []
        if not self.message.is_multipart():
            if self._is_inline_image():
                content = self.get_content_bytes()
                if content:
                    filename = self.get_filename() or "unknown"
                    ctype = self.content_type or "image/unknown"
                    images.append(
                        InlineImage(
                            filename=filename,
                            content_type=ctype,
                            content=content,
                            filesize=len(content),
                            content_id=self.get_content_id(),
                            content_disposition=self.message.get("Content-Disposition"),
                        )
                    )
        else:
            for part in self.get_multi_parts():
                images.extend(part.get_inline_images())
        return images

    def get_mime_part_metadata(self) -> MimePart:
        """
        Get metadata for this MIME part.

        Returns:
            MimePart object with part metadata
        """
        content_bytes = self.get_content_bytes()
        size = len(content_bytes) if content_bytes else 0

        # Compute hash if content exists
        hash_value = None
        if content_bytes:
            hash_value = hashlib.sha256(content_bytes).hexdigest()

        # Get transfer encoding
        transfer_encoding = self.message.get("Content-Transfer-Encoding")

        return MimePart(
            content_type=self.content_type or "text/plain",
            charset=self._content_type.get("charset"),
            transfer_encoding=transfer_encoding,
            disposition=self.message.get("Content-Disposition"),
            filename=self.get_filename(),
            size=size,
            hash=hash_value,
            is_attachment=self.is_attachment,
            is_inline_image=self.is_inline_image,
        )

    def get_all_mime_parts(self) -> List[MimePart]:
        """
        Get metadata for all MIME parts in the message.

        Returns:
            List of MimePart objects for all parts
        """
        parts = []

        # Add metadata for this part
        parts.append(self.get_mime_part_metadata())

        # Recursively add metadata for subparts
        if self.message.is_multipart():
            for part in self.get_multi_parts():
                parts.extend(part.get_all_mime_parts())

        return parts
