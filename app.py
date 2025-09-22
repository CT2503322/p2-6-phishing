import streamlit as st
import requests
import tempfile
import os
from typing import Dict, Any, Optional

# API Configuration
API_BASE_URL = "http://localhost:8000"
PARSE_ENDPOINT = f"{API_BASE_URL}/parse/eml"


def main():
    """Main Streamlit application."""
    # Configure page
    st.set_page_config(page_title="Phishing Email Analyzer", layout="wide")

    st.title("Phishing Email Analyzer")

    uploaded_file = st.file_uploader("Upload .eml file", type=["eml"])

    if uploaded_file is not None:
        with st.spinner("Analyzing..."):
            files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "application/octet-stream")}
            response = requests.post(PARSE_ENDPOINT, files=files)
            if response.status_code == 200:
                data = response.json()
                st.write(data)
            else:
                st.error(f"Error: {response.status_code} - {response.text}")



if __name__ == "__main__":
    main()
