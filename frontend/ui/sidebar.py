"""
Sidebar UI components.
"""

import time
import streamlit as st

from .api_client import check_api_health, get_api_info
from .config import API_BASE_URL, MAX_FILE_SIZE_MB, PAGE_TITLE


def render_sidebar():
    """Render the application sidebar with information and status."""
    with st.sidebar:
        st.header("About")

        st.markdown(
            """
        This application analyzes email files (`.eml`) for potential phishing indicators using:

        - **Sender Identity Analysis**: Validates sender information, detects ESPs, and identifies mismatches
        - **Keyword Detection**: Identifies suspicious keywords and phrases
        - **Domain Analysis**: Checks against whitelisted trusted domains
        - **Header Analysis**: Examines email headers for anomalies
        - **Content Analysis**: Reviews email content and structure
        - **Authentication Check**: Validates SPF, DKIM, DMARC, and ARC
        - **Subscription Analysis**: Reviews list management and unsubscribe options
        """
        )

        # API Status with caching
        st.subheader("API Status")
        if "api_status" not in st.session_state or st.button("Refresh Status"):
            with st.spinner("Checking API status..."):
                st.session_state.api_status = check_api_health()
                st.session_state.api_check_time = time.time()

        if st.session_state.get("api_status", False):
            api_info = get_api_info()
            st.success("Backend API is running")
            if api_info:
                st.caption(f"Version: {api_info.get('version', 'Unknown')}")
            st.caption(
                f"Last checked: {time.strftime('%H:%M:%S', time.localtime(st.session_state.api_check_time))}"
            )
        else:
            st.error("Backend API is not accessible")
            st.info("Make sure the FastAPI server is running on port 8000")

        # System Info
        st.subheader("System Info")
        st.caption(f"Max file size: {MAX_FILE_SIZE_MB}MB")
        st.caption("Supported formats: .eml")

        # Links
        st.subheader("Links")
        st.markdown(f"[API Documentation]({API_BASE_URL}/docs)")
        st.markdown("[GitHub Repository](https://github.com/CT2503322/p2-6-phishing)")
