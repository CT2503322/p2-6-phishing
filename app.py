"""
Streamlit application for phishing email analysis.
"""

import streamlit as st
import time

from frontend.ui import (
    PAGE_TITLE,
    render_file_uploader,
    render_email_content,
    render_analysis_results,
    render_sidebar,
    analyze_email_file,
    validate_email_file,
)


def main():
    """Main Streamlit application."""
    # Configure page
    st.set_page_config(
        page_title=PAGE_TITLE,
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Initialize session state
    if "analysis_result" not in st.session_state:
        st.session_state.analysis_result = None
    if "uploaded_file" not in st.session_state:
        st.session_state.uploaded_file = None

    # Render sidebar
    render_sidebar()

    # Render main content
    st.title(f"{PAGE_TITLE}")
    st.markdown("Upload an `.eml` file to analyze it for phishing indicators")

    # File upload section
    uploaded_file = render_file_uploader()

    # Update session state
    if uploaded_file is not st.session_state.uploaded_file:
        st.session_state.uploaded_file = uploaded_file
        st.session_state.analysis_result = None  # Reset analysis when new file uploaded

    # Analysis section
    if uploaded_file is not None:
        # Validate file
        is_valid, validation_message = validate_email_file(uploaded_file)

        if is_valid:
            st.success(validation_message)
        else:
            st.error(validation_message)
            st.session_state.analysis_result = None
            return

        # Analysis section
        st.markdown("---")
        col1, col2, col3 = st.columns([2, 1, 1])

        with col1:
            analyze_button = st.button(
                "Analyze Email",
                type="primary",
                use_container_width=True,
                disabled=not st.session_state.get("api_status", False),
            )

        with col2:
            if st.button("Clear Results", use_container_width=True):
                st.session_state.analysis_result = None
                st.rerun()

        with col3:
            if st.button(
                "Download Report",
                use_container_width=True,
                disabled=st.session_state.analysis_result is None,
            ):
                # Placeholder for download functionality
                st.info("Download feature coming soon!")

        if analyze_button:
            if not st.session_state.get("api_status", False):
                st.error("Cannot analyze: Backend API is not available")
                return

            with st.spinner("Analyzing email for phishing indicators..."):
                progress_bar = st.progress(0)
                for i in range(100):
                    time.sleep(0.01)  # Simulate processing time
                    progress_bar.progress(i + 1)

                result = analyze_email_file(uploaded_file)
                progress_bar.empty()

            if result:
                st.session_state.analysis_result = result
                st.success("Analysis completed successfully!")
                # Scroll to results
                st.markdown(
                    '<script>document.querySelector("h2").scrollIntoView();</script>',
                    unsafe_allow_html=True,
                )
            else:
                st.error("Analysis failed: Unable to process the email")
                st.info("Please check that the backend API is running and try again.")

        # Display results if available
        if st.session_state.analysis_result:
            st.markdown("---")
            render_analysis_results(st.session_state.analysis_result)

    # Instructions
    with st.expander("How to use"):
        st.markdown(
            """
        ### Quick Start Guide

        1. **Upload**: Select an `.eml` file from your computer using the file uploader above
        2. **Process**: View the complete email processing pipeline:
           - **Step 1**: Raw .eml file content (first 2000 characters)
           - **Step 2**: Parsing process with stdlib email library
           - **Step 3**: Structured email components (headers, body, attachments)
        3. **Analyze**: Click the "Analyze Email" button to run phishing detection
        4. **Review**: Examine the risk assessment and detailed analysis results

        ### Tips
        - Files up to **200MB** are supported
        - Only **.eml** format files are accepted
        - Ensure the **backend API** is running on `http://localhost:8000`
        - Use the **sidebar** to check API status and access documentation

        ### Troubleshooting
        - If analysis fails, check the API status in the sidebar
        - Clear results and try uploading the file again
        - For large files, the analysis may take longer
        """
        )

    # Footer
    st.markdown("---")
    st.caption("Built with Streamlit | Phishing Detection System")
    st.caption(f"2025 | Version 0.0.4")


if __name__ == "__main__":
    main()
