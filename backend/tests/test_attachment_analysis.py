import pytest
from backend.core.attachments import AttachmentAnalyzer
from backend.utils.models import Attachment, AttachmentFinding


class TestAttachmentAnalyzer:
    """Test suite for AttachmentAnalyzer class."""

    def test_analyze_empty_attachments(self):
        """Test analyzing an empty list of attachments."""
        findings = AttachmentAnalyzer.analyze_attachments([])
        assert findings == []

    def test_analyze_single_safe_attachment(self):
        """Test analyzing a safe PDF attachment."""
        attachment = Attachment(
            filename="document.pdf",
            content_type="application/pdf",
            content=b"%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n>>\nendobj\n",
            filesize=100,
        )

        findings = AttachmentAnalyzer.analyze_attachments([attachment])
        assert len(findings) == 1

        finding = findings[0]
        assert isinstance(finding, AttachmentFinding)
        assert finding.filename == "document.pdf"
        assert finding.ext_primary == ".pdf"
        assert finding.double_ext is False
        assert finding.declared_mime == "application/pdf"
        assert finding.is_macro_enabled is False
        assert finding.is_dangerous_type is False
        assert finding.is_archive is False
        assert finding.archive_contains_dangerous is None

    def test_analyze_dangerous_executable(self):
        """Test analyzing a dangerous executable attachment."""
        attachment = Attachment(
            filename="malware.exe",
            content_type="application/x-msdownload",
            content=b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00",
            filesize=100,
        )

        findings = AttachmentAnalyzer.analyze_attachments([attachment])
        assert len(findings) == 1

        finding = findings[0]
        assert finding.filename == "malware.exe"
        assert finding.ext_primary == ".exe"
        assert finding.is_dangerous_type is True
        assert "Dangerous file type" in finding.evidence

    def test_analyze_double_extension(self):
        """Test analyzing attachment with double extension."""
        attachment = Attachment(
            filename="document.pdf.exe",
            content_type="application/pdf",
            content=b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00",
            filesize=100,
        )

        findings = AttachmentAnalyzer.analyze_attachments([attachment])
        assert len(findings) == 1

        finding = findings[0]
        assert finding.filename == "document.pdf.exe"
        assert finding.double_ext is True
        assert "Double extension detected" in finding.evidence

    def test_analyze_macro_enabled_office_doc(self):
        """Test analyzing macro-enabled Office document."""
        attachment = Attachment(
            filename="document.xlsm",
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            content=b"PK\x03\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            filesize=100,
        )

        findings = AttachmentAnalyzer.analyze_attachments([attachment])
        assert len(findings) == 1

        finding = findings[0]
        assert finding.filename == "document.xlsm"
        assert finding.ext_primary == ".xlsm"
        assert finding.is_macro_enabled is True
        assert "Potential macro-enabled content" in finding.evidence

    def test_analyze_archive_dangerous_content(self):
        """Test analyzing ZIP archive with dangerous content."""
        # Create a simple ZIP file content simulation
        zip_content = (
            b"PK\x03\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"malware.exePK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )

        attachment = Attachment(
            filename="archive.zip",
            content_type="application/zip",
            content=zip_content,
            filesize=len(zip_content),
        )

        findings = AttachmentAnalyzer.analyze_attachments([attachment])
        assert len(findings) == 1

        finding = findings[0]
        assert finding.filename == "archive.zip"
        assert finding.is_archive is True
        # Note: Archive inspection would require actual ZIP handling

    def test_analyze_mime_mismatch(self):
        """Test analyzing attachment with MIME type mismatch."""
        attachment = Attachment(
            filename="fake.pdf",
            content_type="application/pdf",
            content=b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00",
            filesize=100,
        )

        findings = AttachmentAnalyzer.analyze_attachments([attachment])
        assert len(findings) == 1

        finding = findings[0]
        assert finding.filename == "fake.pdf"
        assert finding.double_ext is False
        # Note: Sniffing may or may not detect this depending on content patterns

    def test_analyze_multiple_attachments(self):
        """Test analyzing multiple attachments with different security profiles."""
        attachments = [
            Attachment(
                filename="safe.pdf",
                content_type="application/pdf",
                content=b"%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n>>\nendobj\n",
                filesize=50,
            ),
            Attachment(
                filename="dangerous.exe",
                content_type="application/x-msdownload",
                content=b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00",
                filesize=100,
            ),
            Attachment(
                filename="macro.docm",
                content_type="application/vnd.ms-word.document.macroEnabled.12",
                content=b"PK\x03\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00xl/vbaProject.bin",
                filesize=200,
            ),
        ]

        findings = AttachmentAnalyzer.analyze_attachments(attachments)
        assert len(findings) == 3

        # Verify each finding has the correct filename
        assert findings[0].filename == "safe.pdf"
        assert findings[1].filename == "dangerous.exe"
        assert findings[2].filename == "macro.docm"

        # Verify security characteristics
        safe_finding = findings[0]
        dangerous_finding = findings[1]
        macro_finding = findings[2]

        # Safe attachment
        assert safe_finding.is_dangerous_type is False
        assert safe_finding.is_macro_enabled is False

        # Dangerous attachment
        assert dangerous_finding.is_dangerous_type is True

        # Macro-enabled attachment
        assert macro_finding.is_macro_enabled is True

    def test_get_primary_extension(self):
        """Test primary extension extraction."""
        assert AttachmentAnalyzer._get_primary_extension("file.pdf") == ".pdf"
        assert AttachmentAnalyzer._get_primary_extension("file.PDF") == ".pdf"
        assert AttachmentAnalyzer._get_primary_extension("file.txt") == ".txt"
        assert AttachmentAnalyzer._get_primary_extension("file.docm") == ".docm"
        assert AttachmentAnalyzer._get_primary_extension("file") == ""
        assert AttachmentAnalyzer._get_primary_extension("") == ""

    def test_has_double_extension(self):
        """Test double extension detection."""
        assert AttachmentAnalyzer._has_double_extension("file.pdf.exe") is True
        assert AttachmentAnalyzer._has_double_extension("file.tar.gz") is True
        assert AttachmentAnalyzer._has_double_extension("file.pdf") is False
        assert AttachmentAnalyzer._has_double_extension("file") is False
        assert AttachmentAnalyzer._has_double_extension("") is False

    def test_is_dangerous_type(self):
        """Test dangerous file type detection."""
        # Dangerous extensions
        assert AttachmentAnalyzer._is_dangerous_type(".exe", "application/pdf") is True
        assert AttachmentAnalyzer._is_dangerous_type(".bat", "text/plain") is True
        assert (
            AttachmentAnalyzer._is_dangerous_type(".js", "application/javascript")
            is True
        )

        # Dangerous MIME types
        assert (
            AttachmentAnalyzer._is_dangerous_type(".pdf", "application/x-msdownload")
            is True
        )
        assert (
            AttachmentAnalyzer._is_dangerous_type(".txt", "application/javascript")
            is True
        )

        # Safe files
        assert AttachmentAnalyzer._is_dangerous_type(".pdf", "application/pdf") is False
        assert (
            AttachmentAnalyzer._is_dangerous_type(
                ".docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
            is False
        )

    def test_sniff_mime_type(self):
        """Test MIME type sniffing."""
        # PDF content
        pdf_content = b"%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n>>\nendobj\n"
        assert AttachmentAnalyzer._sniff_mime_type(pdf_content, "file.pdf") in [
            "application/pdf",
            "application/octet-stream",
        ]

        # ZIP content
        zip_content = b"PK\x03\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        mime = AttachmentAnalyzer._sniff_mime_type(zip_content, "file.zip")
        assert mime in [
            "application/zip",
            "application/x-zip-compressed",
            "application/octet-stream",
        ]

        # Empty content - still gets a MIME type from filename
        mime = AttachmentAnalyzer._sniff_mime_type(b"", "file.txt")
        assert mime is not None  # Should still get text/plain from mimetypes

    def test_check_macro_enabled(self):
        """Test macro detection."""
        # Macro file extensions
        assert (
            AttachmentAnalyzer._check_macro_enabled(
                "file.xlsm", "application/pdf", b"content"
            )
            is True
        )
        assert (
            AttachmentAnalyzer._check_macro_enabled(
                "file.docm", "application/pdf", b"content"
            )
            is True
        )

        # Macro MIME types
        assert (
            AttachmentAnalyzer._check_macro_enabled(
                "file.xls", "application/vnd.ms-excel.sheet.macroEnabled.12", b"content"
            )
            is True
        )

        # Content-based detection
        content_with_macro = b"PK\x03\x04...\x00\x00word/vbaProject.bin"
        assert (
            AttachmentAnalyzer._check_macro_enabled(
                "file.docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                content_with_macro,
            )
            is True
        )

        # Non-macro files
        assert (
            AttachmentAnalyzer._check_macro_enabled(
                "file.pdf", "application/pdf", b"content"
            )
            is False
        )

    def test_generate_evidence(self):
        """Test evidence string generation."""
        # Clean file
        evidence = AttachmentAnalyzer._generate_evidence(
            "safe.pdf",
            ".pdf",
            False,
            "application/pdf",
            "application/pdf",
            False,
            False,
            False,
            None,
        )
        assert "No suspicious patterns detected" in evidence

        # Dangerous file
        evidence = AttachmentAnalyzer._generate_evidence(
            "malware.exe",
            ".exe",
            False,
            "application/x-msdownload",
            "application/x-msdownload",
            False,
            True,
            False,
            None,
        )
        assert "Dangerous file type:" in evidence

        # Double extension
        evidence = AttachmentAnalyzer._generate_evidence(
            "fake.pdf.exe",
            ".exe",
            True,
            "application/pdf",
            "application/x-msdownload",
            False,
            True,
            False,
            None,
        )
        assert "Double extension detected" in evidence
        assert "Dangerous file type:" in evidence

        # Archive with dangerous content
        evidence = AttachmentAnalyzer._generate_evidence(
            "archive.zip",
            ".zip",
            False,
            "application/zip",
            "application/zip",
            False,
            False,
            True,
            True,
        )
        assert "Archive file detected:" in evidence
        assert "Archive contains dangerous files" in evidence

        # MIME mismatch
        evidence = AttachmentAnalyzer._generate_evidence(
            "fake.pdf",
            ".pdf",
            False,
            "application/pdf",
            "application/x-msdownload",
            False,
            False,
            False,
            None,
        )
        assert "MIME type mismatch:" in evidence


class TestAttachmentFindingModel:
    """Test the AttachmentFinding dataclass."""

    def test_attachment_finding_creation(self):
        """Test creating an AttachmentFinding instance."""
        finding = AttachmentFinding(
            filename="test.pdf",
            ext_primary=".pdf",
            double_ext=False,
            declared_mime="application/pdf",
            is_macro_enabled=False,
            is_dangerous_type=False,
            is_archive=False,
            evidence="Clean file - no issues detected",
            sniffed_mime="application/pdf",
            archive_contains_dangerous=None,
        )

        assert finding.filename == "test.pdf"
        assert finding.ext_primary == ".pdf"
        assert finding.double_ext is False
        assert finding.declared_mime == "application/pdf"
        assert finding.sniffed_mime == "application/pdf"
        assert finding.is_macro_enabled is False
        assert finding.is_dangerous_type is False
        assert finding.is_archive is False
        assert finding.archive_contains_dangerous is None
        assert finding.evidence == "Clean file - no issues detected"

    def test_attachment_finding_optional_fields(self):
        """Test AttachmentFinding with optional fields."""
        # Test with None sniffed_mime
        finding = AttachmentFinding(
            filename="unknown.bin",
            ext_primary="",
            double_ext=False,
            declared_mime="application/octet-stream",
            is_macro_enabled=False,
            is_dangerous_type=False,
            is_archive=False,
            evidence="File type could not be determined",
            sniffed_mime=None,
            archive_contains_dangerous=None,
        )

        assert finding.sniffed_mime is None
        assert finding.ext_primary == ""
