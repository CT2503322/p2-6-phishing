"""
File uploader UI components.
"""

import streamlit as st
from typing import Optional


def render_file_uploader() -> Optional[st.runtime.uploaded_file_manager.UploadedFile]:
    """
    Render the file uploader component for .eml files.

    Returns:
        Uploaded file object or None if no file selected
    """
    st.subheader("Upload Email File")

    uploaded_file = st.file_uploader(
        "Choose an .eml file",
        type=["eml"],
        help="Select an email file (.eml) to analyze for phishing indicators",
        accept_multiple_files=False,
    )

    return uploaded_file
