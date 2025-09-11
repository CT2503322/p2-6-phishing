import os
import mimetypes
from pathlib import Path
from typing import List, Optional, Tuple
import re
from backend.utils.models import Attachment, AttachmentFinding


class AttachmentAnalyzer:
    """
    Analyzer for email attachments to detect suspicious or malicious patterns.
    """

    # Dangerous file extensions that should never be in emails
    DANGEROUS_EXTENSIONS = {
        ".exe",
        ".bat",
        ".cmd",
        ".scr",
        ".pif",
        ".com",
        ".vbs",
        ".js",
        ".jar",
        ".hta",
        ".wsf",
        ".wsh",
        ".ps1",
        ".scr",
        ".msi",
        ".app",
        ".deb",
        ".rpm",
    }

    # Archive extensions that need further inspection
    ARCHIVE_EXTENSIONS = {
        ".zip",
        ".rar",
        ".7z",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".cab",
        ".iso",
    }

    # File types that commonly contain macros
    MACRO_ENABLED_TYPES = {
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-excel.sheet.macroenabled.12",
        "application/vnd.ms-excel.template.macroenabled.12",
        "application/vnd.ms-word",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/msword",
        "application/vnd.ms-word.document.macroenabled.12",
        "application/vnd.ms-word.template.macroenabled.12",
        "application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.ms-powerpoint.presentation.macroenabled.12",
        "application/vnd.ms-powerpoint.template.macroenabled.12",
    }

    @classmethod
    def analyze_attachment(cls, attachment: Attachment) -> AttachmentFinding:
        """
        Analyze a single attachment for suspicious patterns.

        Args:
            attachment: The attachment to analyze

        Returns:
            AttachmentFinding with analysis results
        """
        filename = attachment.filename
        content = attachment.content
        declared_mime = attachment.content_type

        # Extract primary extension
        ext_primary = cls._get_primary_extension(filename)

        # Check for double extensions
        double_ext = cls._has_double_extension(filename)

        # Try to sniff MIME type
        sniffed_mime = cls._sniff_mime_type(content, filename)

        # Check if macros are potentially enabled
        is_macro_enabled = cls._check_macro_enabled(filename, declared_mime, content)

        # Check if it's a dangerous file type
        is_dangerous_type = cls._is_dangerous_type(ext_primary, declared_mime)

        # Check if it's an archive
        is_archive = ext_primary.lower() in cls.ARCHIVE_EXTENSIONS

        # Check archive contents if it's an archive
        archive_contains_dangerous = None
        if is_archive:
            archive_contains_dangerous = cls._check_archive_contents(content, filename)

        # Generate evidence string
        evidence = cls._generate_evidence(
            filename,
            ext_primary,
            double_ext,
            declared_mime,
            sniffed_mime,
            is_macro_enabled,
            is_dangerous_type,
            is_archive,
            archive_contains_dangerous,
        )

        return AttachmentFinding(
            filename=filename,
            ext_primary=ext_primary,
            double_ext=double_ext,
            declared_mime=declared_mime,
            is_macro_enabled=is_macro_enabled,
            is_dangerous_type=is_dangerous_type,
            is_archive=is_archive,
            evidence=evidence,
            sniffed_mime=sniffed_mime,
            archive_contains_dangerous=archive_contains_dangerous,
        )

    @classmethod
    def analyze_attachments(
        cls, attachments: List[Attachment]
    ) -> List[AttachmentFinding]:
        """
        Analyze multiple attachments.

        Args:
            attachments: List of attachments to analyze

        Returns:
            List of AttachmentFinding objects
        """
        return [cls.analyze_attachment(att) for att in attachments]

    @staticmethod
    def _get_primary_extension(filename: str) -> str:
        """
        Get the primary file extension from filename.
        Returns empty string if no extension found.
        """
        if not filename:
            return ""
        path = Path(filename)
        return path.suffix.lower()

    @staticmethod
    def _has_double_extension(filename: str) -> bool:
        """
        Check if filename has double extensions (e.g., document.pdf.exe).
        """
        if not filename:
            return False

        path = Path(filename)
        name_without_ext = path.stem

        # Check if the name without extension has another extension
        if "." in name_without_ext:
            return True

        return False

    @staticmethod
    def _sniff_mime_type(content: bytes, filename: str) -> Optional[str]:
        """
        Attempt to sniff the MIME type from file content and filename.
        """
        try:
            # Try mimetypes first
            mime_type, _ = mimetypes.guess_type(filename)
            if mime_type:
                return mime_type

            # Basic content-based detection
            if content.startswith(b"PK\x03\x04"):  # ZIP file signature
                return "application/zip"
            elif content.startswith(b"Rar!\x1a\x07"):  # RAR file signature
                return "application/x-rar-compressed"
            elif content.startswith(b"PK"):  # Could be XLSX, DOCX, etc.
                # Check for Office document signatures
                if len(content) > 50:
                    if b"xl/workbook.xml" in content or b"xl/worksheets/" in content:
                        return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    elif b"word/document.xml" in content:
                        return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                    elif b"ppt/presentation.xml" in content:
                        return "application/vnd.openxmlformats-officedocument.presentationml.presentation"

        except Exception:
            pass

        return None

    @classmethod
    def _check_macro_enabled(
        cls, filename: str, declared_mime: str, content: bytes
    ) -> bool:
        """
        Check if the attachment potentially contains macros.
        """
        # Check MIME type
        if declared_mime.lower() in cls.MACRO_ENABLED_TYPES:
            return True

        # Check filename extensions
        ext = cls._get_primary_extension(filename)
        if ext in [".xlsm", ".xltm", ".docm", ".dotm", ".pptm", ".potm"]:
            return True

        # Check for VBA content in Office documents
        try:
            if "xl/" in content.decode(
                "utf-8", errors="ignore"
            ) or "word/" in content.decode("utf-8", errors="ignore"):
                if b"vba" in content.lower() or b"macro" in content.lower():
                    return True
        except Exception:
            pass

        return False

    @classmethod
    def _is_dangerous_type(cls, ext_primary: str, declared_mime: str) -> bool:
        """
        Check if the attachment is of a dangerous type.
        """
        return (
            ext_primary.lower() in cls.DANGEROUS_EXTENSIONS
            or declared_mime.lower().startswith("application/x-msdownload")
            or declared_mime.lower() == "application/javascript"
            or declared_mime.lower() == "application/x-vbscript"
        )

    @classmethod
    def _check_archive_contents(cls, content: bytes, filename: str) -> Optional[bool]:
        """
        Check if archive contains dangerous files.
        Returns True if dangerous files found, False if safe, None if inspection failed.
        """
        try:
            # For ZIP files
            if filename.lower().endswith(".zip"):
                return cls._check_zip_contents(content)
            # For RAR files
            elif filename.lower().endswith(".rar"):
                # Would need unrar library - for now return None
                return None
            # For other archives, can't inspect without additional libraries
            else:
                return None
        except Exception:
            return None

    @staticmethod
    def _check_zip_contents(content: bytes) -> Optional[bool]:
        """
        Check ZIP archive contents for dangerous files.
        """
        try:
            from io import BytesIO
            import zipfile

            with zipfile.ZipFile(BytesIO(content)) as zf:
                for filename in zf.namelist():
                    ext = Path(filename).suffix.lower()
                    if ext in {
                        ".exe",
                        ".bat",
                        ".cmd",
                        ".scr",
                        ".pif",
                        ".com",
                        ".vbs",
                        ".js",
                    }:
                        return True
            return False
        except Exception:
            return None

    @staticmethod
    def _generate_evidence(
        filename: str,
        ext_primary: str,
        double_ext: bool,
        declared_mime: str,
        sniffed_mime: Optional[str],
        is_macro_enabled: bool,
        is_dangerous_type: bool,
        is_archive: bool,
        archive_contains_dangerous: Optional[bool],
    ) -> str:
        """
        Generate evidence string summarizing the analysis findings.
        """
        evidence_parts = []

        if double_ext:
            evidence_parts.append("Double extension detected")

        if sniffed_mime and sniffed_mime != declared_mime:
            evidence_parts.append(
                f"MIME type mismatch: declared={declared_mime}, sniffed={sniffed_mime}"
            )

        if is_macro_enabled:
            evidence_parts.append("Potential macro-enabled content")

        if is_dangerous_type:
            evidence_parts.append(f"Dangerous file type: {ext_primary}")

        if is_archive:
            evidence_parts.append(f"Archive file detected: {ext_primary}")
            if archive_contains_dangerous is True:
                evidence_parts.append("Archive contains dangerous files")
            elif archive_contains_dangerous is False:
                evidence_parts.append("Archive appears safe")

        if not evidence_parts:
            evidence_parts.append("No suspicious patterns detected")

        return "; ".join(evidence_parts)
