import streamlit as st
import requests
import tempfile
import os
from typing import Dict, Any, Optional

# API Configuration
API_BASE_URL = "http://localhost:8000"
PARSE_ENDPOINT = f"{API_BASE_URL}/parse/eml"
ANALYZE_ENDPOINT = f"{API_BASE_URL}/analyze/parsed"


def main():
    """Main Streamlit application."""
    # Configure page
    st.set_page_config(page_title="Phishing Email Analyzer", layout="wide")

    st.title("Phishing Email Analyzer")

    uploaded_file = st.file_uploader("Upload .eml file", type=["eml"])

    if uploaded_file is not None:
        # Parse the email
        with st.spinner("Parsing email..."):
            files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "application/octet-stream")}
            response = requests.post(PARSE_ENDPOINT, files=files)
            if response.status_code == 200:
                parsed_data = response.json()
                st.subheader("Parsed Email Data")
                st.json(parsed_data)
            else:
                st.error(f"Parse Error: {response.status_code} - {response.text}")
                return

        # Analyze the parsed data
        with st.spinner("Analyzing for phishing..."):
            analyze_response = requests.post(ANALYZE_ENDPOINT, json={"parsed": parsed_data})
            if analyze_response.status_code == 200:
                analysis_data = analyze_response.json()
                st.subheader("Analysis Results")
                st.json(analysis_data)
            else:
                st.error(f"Analysis Error: {analyze_response.status_code} - {analyze_response.text}")



if __name__ == "__main__":
    main()
