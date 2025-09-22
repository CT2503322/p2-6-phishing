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

    # Detection method selection
    detection_method = st.selectbox(
        "Select Detection Method",
        options=["algorithmic", "ML", "LLM"],
        help="Choose the detection method for phishing analysis"
    )

    # Sub-selection for ML models
    ml_model = None
    if detection_method == "ML":
        ml_model = st.selectbox(
            "Select ML Model",
            options=["linear regression", "decision tree", "naive bayes"],
            help="Choose the specific ML model to use"
        )

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
        with st.spinner(f"Analyzing for phishing using {detection_method} detection..."):
            if detection_method == "algorithmic":
                analyze_endpoint = f"{API_BASE_URL}/analyze/algorithmic"
            elif detection_method == "ML":
                analyze_endpoint = f"{API_BASE_URL}/analyze/ml"
            elif detection_method == "LLM":
                analyze_endpoint = f"{API_BASE_URL}/analyze/llm"
            else:
                st.error("Unknown detection method")
                return
            request_data = {"parsed": parsed_data}
            if ml_model:
                request_data["ml_model"] = ml_model
            analyze_response = requests.post(analyze_endpoint, json=request_data)
            if analyze_response.status_code == 200:
                analysis_data = analyze_response.json()
                st.subheader("Analysis Results")
                st.json(analysis_data)
            else:
                st.error(f"Analysis Error: {analyze_response.status_code} - {analyze_response.text}")



if __name__ == "__main__":
    main()
