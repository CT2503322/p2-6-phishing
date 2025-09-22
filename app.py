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
        help="Choose the detection method for phishing analysis",
    )

    # Sub-selection for ML models
    ml_model = None
    if detection_method == "ML":
        ml_model = st.selectbox(
            "Select ML Model",
            options=[
                "naivebayes_complement",
                "naivebayes_multinomial",
                "logistic_regression",
                "decision tree",
                "naive bayes",
            ],
            help="Choose the specific ML model to use",
        )

    # Sub-selection for LLM models
    llm_model = None
    if detection_method == "LLM":
        llm_model = st.selectbox(
            "Select LLM Model",
            options=["gpt-3.5-turbo", "gpt-4", "gpt-4-turbo"],
            index=0,  # Default to first option
            help="Choose the specific LLM model to use",
        )

    input_method = st.radio(
        "Choose input method:", ["Upload .eml file", "Enter email body text"]
    )

    uploaded_file = None
    text_body = ""

    if input_method == "Upload .eml file":
        uploaded_file = st.file_uploader("Upload .eml file", type=["eml"])
    else:
        text_body = st.text_area(
            "Enter email body text:",
            height=300,
            placeholder="Paste the email body here...",
        )

    parsed_data = None

    if uploaded_file is not None:
        # Parse the email
        with st.spinner("Parsing email..."):
            files = {
                "file": (
                    uploaded_file.name,
                    uploaded_file.getvalue(),
                    "application/octet-stream",
                )
            }
            response = requests.post(PARSE_ENDPOINT, files=files)
            if response.status_code == 200:
                parsed_data = response.json()
                st.subheader("Parsed Email Data")
                st.json(parsed_data)
            else:
                st.error(f"Parse Error: {response.status_code} - {response.text}")
                return
    elif input_method == "Enter email body text" and text_body.strip():
        # Create parsed data for text input (body only)
        parsed_data = {
            "from": "",
            "subject": "",
            "body": text_body,
            "attachments": "",
            "message_id": "",
            "received": "",
            "reply-to": "",
            "return-path": "",
        }
        st.subheader("Input Email Data")
        st.write(f"**Body:** {text_body[:500]}{'...' if len(text_body) > 500 else ''}")

    if parsed_data is not None:
        # Analyze the parsed data
        with st.spinner(
            f"Analyzing for phishing using {detection_method} detection..."
        ):
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
            if llm_model:
                request_data["model"] = llm_model
            analyze_response = requests.post(analyze_endpoint, json=request_data)
            if analyze_response.status_code == 200:
                analysis_data = analyze_response.json()
                st.subheader("Analysis Results")

                # Display label and score in columns
                col1, col2 = st.columns(2)
                with col1:
                    label = analysis_data.get("label", "N/A").upper()
                    score = analysis_data.get("score", "N/A")
                    if isinstance(score, (int, float)):
                        label_display = f"Label: {label} ({score:.2f})"
                    else:
                        label_display = f"Label: {label}"
                    st.write(label_display)
                with col2:
                    score = analysis_data.get("score", "N/A")
                    if isinstance(score, (int, float)):
                        # Convert to percentage: assume 0-1 scale or 0-10 scale
                        if score <= 1:
                            score_percent = score * 100
                        else:
                            score_percent = min(
                                100, score * 10
                            )  # Convert from 1-10 scale to %
                        st.metric("Phishing Likelihood", f"{score_percent:.0f}%")
                        st.progress(score_percent / 100, "Likelihood of Phishing")
                    else:
                        st.write(f"**Likelihood:** {score}")

                st.write("**Key Findings:**")
                if "explanations" in analysis_data:
                    for expl in analysis_data["explanations"]:
                        st.write(f"• {expl}")
                else:
                    st.write("*Explanations not available for this detection method.*")

                if "highlighted_body" in analysis_data:
                    st.write("**Highlighted Email Content:**")
                    st.markdown(
                        analysis_data["highlighted_body"], unsafe_allow_html=True
                    )
            else:
                st.error(
                    f"Analysis Error: {analyze_response.status_code} - {analyze_response.text}"
                )


if __name__ == "__main__":
    main()
