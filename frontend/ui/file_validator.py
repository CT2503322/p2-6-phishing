"""
File validation utilities for email file uploads.
"""

from typing import Tuple

from .config import MAX_FILE_SIZE_MB, SUPPORTED_EXTENSIONS


def validate_email_file(file) -> Tuple[bool, str]:
    """
    Validate the uploaded email file.

    Args:
        file: Uploaded file object

    Returns:
        Tuple of (is_valid, message)
    """
    if file is None:
        return False, "No file selected. Please choose an .eml file to analyze."

    # Check filename
    if not file.name:
        return False, "Invalid file: No filename provided."

    if not file.name.lower().endswith(".eml"):
        return (
            False,
            f"Invalid file type: '{file.name}'. Please select a valid .eml file.",
        )

    # Check file size (match API limit)
    file_size = len(file.getvalue())
    max_size_bytes = MAX_FILE_SIZE_MB * 1024 * 1024

    if file_size == 0:
        return False, "File is empty. Please select a valid .eml file."

    if file_size > max_size_bytes:
        return (
            False,
            f"File too large: {file_size / (1024*1024):.1f}MB. Maximum allowed size is {MAX_FILE_SIZE_MB}MB.",
        )

    # Basic content validation
    try:
        content = file.getvalue()
        if b"\n" not in content and b"\r" not in content:
            return (
                False,
                "File may not be a valid email format (no line breaks detected).",
            )
    except Exception as e:
        return False, f"Error reading file: {str(e)}"

    return (
        True,
        f"File uploaded: **{file.name}**\n\nFile size: {file_size:,} bytes\n\nFile '{file.name}' is valid ({file_size:,} bytes)",
    )
