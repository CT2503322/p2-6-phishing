import streamlit as st
import requests
import tempfile
import os
from typing import Dict, Any, Optional

# API Configuration
API_BASE_URL = "http://localhost:8000"
ANALYZE_ENDPOINT = f"{API_BASE_URL}/analyze/eml"


def analyze_email_file(file) -> Optional[Dict[str, Any]]:
    """
    Send email file to backend API for analysis.

    Args:
        file: Streamlit uploaded file object

    Returns:
        Dict containing analysis results or None if failed
    """
    # Create temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp_file:
        tmp_file.write(file.getvalue())
        tmp_file_path = tmp_file.name

    try:
        # Send file to API
        with open(tmp_file_path, "rb") as f:
            files = {"file": f}
            response = requests.post(ANALYZE_ENDPOINT, files=files)

        if response.status_code == 200:
            return response.json()
        else:
            print(f"API Error: {response.status_code}")
            return None

    except Exception as e:
        print(f"Error connecting to API: {str(e)}")
        return None

    finally:
        # Clean up temporary file
        os.unlink(tmp_file_path)


def check_api_health() -> bool:
    """
    Check if the backend API is healthy and running.

    Returns:
        True if API is healthy, False otherwise
    """
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        return response.status_code == 200
    except Exception:
        return False


def validate_email_file(file) -> tuple[bool, str]:
    """
    Validate the uploaded email file.

    Args:
        file: Uploaded file object

    Returns:
        Tuple of (is_valid, message)
    """
    if file is None:
        return False, "No file selected"

    if not file.name.lower().endswith(".eml"):
        return False, "Please select a valid .eml file"

    # Check file size (limit to 10MB)
    max_size = 10 * 1024 * 1024  # 10MB
    if len(file.getvalue()) > max_size:
        return False, "File size too large (max 10MB)"

    return True, "File is valid"


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

    if uploaded_file is not None:
        st.success(f"File uploaded: **{uploaded_file.name}**")

        # Display file info
        file_size = len(uploaded_file.getvalue())
        st.info(f"File size: {file_size:,} bytes")

    return uploaded_file


def render_analysis_results(result: Dict[str, Any]):
    """
    Render the analysis results in a structured format.

    Args:
        result: Analysis result dictionary from the API
    """
    # Risk Assessment Header
    st.header("Analysis Results")

    # Risk Score Overview
    col1, col2, col3 = st.columns(3)

    with col1:
        risk_score = result.get("risk", 0)
        if risk_score >= 1.0:
            st.error("HIGH RISK")
        elif risk_score >= 0.5:
            st.warning("MEDIUM RISK")
        else:
            st.success("LOW RISK")

    with col2:
        st.metric("Risk Score", f"{risk_score:.2f}")

    with col3:
        label = result.get("label", "UNKNOWN")
        st.metric("Classification", label)

    # Detection Reasons
    reasons = result.get("reasons", [])
    if reasons:
        st.subheader("Detection Reasons")
        for reason in reasons:
            st.write(f"• {reason}")

    # Email Information
    meta = result.get("meta", {})
    if meta:
        render_email_information(meta)

    # Keywords
    keywords = meta.get("keywords", [])
    if keywords:
        render_keywords(keywords)

    # Domains
    domains = meta.get("domains", [])
    whitelisted = meta.get("whitelisted_domains", [])
    if domains:
        render_domains(domains, whitelisted)

    # Content Previews
    render_content_previews(meta)

    # All Headers
    render_email_headers(meta)


def render_email_information(meta: Dict[str, Any]):
    """Render email information section."""
    st.subheader("Email Information")

    col1, col2 = st.columns(2)

    with col1:
        subject = meta.get("subject", "No subject")
        st.write(f"**Subject:** {subject}")

        if "key_headers" in meta:
            headers = meta["key_headers"]
            st.write(f"**From:** {headers.get('from', 'Not specified')}")
            st.write(f"**To:** {headers.get('to', 'Not specified')}")
            if headers.get("cc"):
                st.write(f"**CC:** {headers.get('cc')}")
            st.write(f"**Date:** {headers.get('date', 'Not specified')}")

    with col2:
        if "content_stats" in meta:
            stats = meta["content_stats"]
            st.write(f"**Body Length:** {stats.get('body_length', 0)} characters")
            st.write(f"**HTML Length:** {stats.get('html_length', 0)} characters")
            st.write(f"**Domains Found:** {stats.get('domain_count', 0)}")
            st.write(f"**Has HTML:** {'Yes' if stats.get('has_html', False) else 'No'}")


def render_keywords(keywords: list):
    """Render detected keywords section."""
    st.subheader("Detected Keywords")

    keyword_data = []
    for kw in keywords:
        keyword_data.append(
            {"Keyword": kw.get("keyword", ""), "Count": kw.get("count", 0)}
        )

    if keyword_data:
        st.table(keyword_data)


def render_domains(domains: list, whitelisted: list):
    """Render extracted domains section."""
    st.subheader("Extracted Domains")

    for domain in domains:
        if domain in whitelisted:
            st.write(f"[SAFE] {domain} (Whitelisted)")
        else:
            st.write(f"[CHECK] {domain}")


def render_content_previews(meta: Dict[str, Any]):
    """Render content preview sections."""
    col1, col2 = st.columns(2)

    with col1:
        if "body_preview" in meta and meta["body_preview"]:
            st.subheader("Body Content Preview")
            st.text_area(
                "", meta["body_preview"], height=150, disabled=True, key="body_preview"
            )

    with col2:
        if "html_preview" in meta and meta["html_preview"]:
            st.subheader("HTML Content Preview")
            st.text_area(
                "", meta["html_preview"], height=150, disabled=True, key="html_preview"
            )


def render_email_headers(meta: Dict[str, Any]):
    """Render all email headers section."""
    if "headers" in meta and meta["headers"]:
        st.subheader("All Email Headers")

        with st.expander("Click to expand"):
            headers_text = ""
            for key, value in meta["headers"].items():
                headers_text += f"{key}: {value}\n"
            st.code(headers_text, language="text")


def main():
    """Main Streamlit application."""
    # Configure page
    st.set_page_config(page_title="Phishing Email Analyzer", layout="wide")

    # Render sidebar
    with st.sidebar:
        st.header("About")

        st.markdown(
            """
        This application analyzes email files (`.eml`) for potential phishing indicators using:

        - **Keyword Detection**: Identifies suspicious keywords
        - **Domain Analysis**: Checks against whitelisted domains
        - **Header Analysis**: Examines email headers for anomalies
        - **Content Analysis**: Reviews email content and structure
        """
        )

        # API Status
        st.subheader("API Status")
        if check_api_health():
            st.success("Backend API is running")
        else:
            st.error("Backend API is not accessible")
            st.info("Make sure the FastAPI server is running on port 8000")

        # Links
        st.subheader("Links")
        st.markdown(f"[API Documentation]({API_BASE_URL}/docs)")
        st.markdown("[GitHub Repository](https://github.com/CT2503322/p2-6-phishing)")

    # Render main content
    st.title("Phishing Email Analyzer")
    st.markdown("Upload an `.eml` file to analyze it for phishing indicators")

    # File upload section
    uploaded_file = render_file_uploader()

    # Analysis section
    if uploaded_file is not None:
        # Validate file
        is_valid, validation_message = validate_email_file(uploaded_file)

        if not is_valid:
            st.error(validation_message)
            return

        # Analysis button
        if st.button("Analyze Email", type="primary"):
            with st.spinner("Analyzing email..."):
                result = analyze_email_file(uploaded_file)

            if result:
                render_analysis_results(result)
            else:
                st.error("Analysis failed: Failed to analyze the email")
                st.info("Please check that the backend API is running and try again.")

    # Instructions
    with st.expander("How to use"):
        st.markdown(
            """
        1. **Upload**: Select an `.eml` file from your computer
        2. **Analyze**: Click the "Analyze Email" button
        3. **Review**: Examine the risk assessment and detailed analysis

        **Note**: Make sure the backend API is running on `http://localhost:8000`
        """
        )

    # Footer
    st.markdown("---")
    st.markdown("Built with Streamlit | Phishing Detection System")


if __name__ == "__main__":
    main()
