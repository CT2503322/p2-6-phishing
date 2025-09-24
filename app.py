import streamlit as st
import requests
import tempfile
import os
import hashlib
from typing import Dict, Any, Optional

# API Configuration
API_BASE_URL = "http://localhost:8000"
PARSE_ENDPOINT = f"{API_BASE_URL}/parse/eml"


def main():
    """Main Streamlit application."""
    # Configure page
    st.set_page_config(page_title="Phishing Email Analyzer", layout="wide")

    st.image("img/phisherman_logo.png", width=150)  # Replace with actual logo URL
    st.title("Phishingman - Your personalized Email Analyzer")

    if "analysis_requested" not in st.session_state:
        st.session_state["analysis_requested"] = False
    if "analysis_result" not in st.session_state:
        st.session_state["analysis_result"] = None
    if "input_signature" not in st.session_state:
        st.session_state["input_signature"] = None
    if "last_analysis_signature" not in st.session_state:
        st.session_state["last_analysis_signature"] = None

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
                "decision_tree",
                "naive bayes",
            ],
            help="Choose the specific ML model to use",
        )

    # Sub-selection for LLM models
    llm_model = None
    if detection_method == "LLM":
        llm_model = st.selectbox(
            "Select LLM Model",
            options=["gpt-5-nano", "gpt-4.1-nano", "gpt-4o-mini"],
            index=0,  # Default to first option
            help="Choose the specific LLM model to use",
        )

    input_method = st.radio(
        "Choose input method:", ["Upload .eml file", "Enter email body text"]
    )

    uploaded_file = None
    text_body = ""
    parsed_data = None
    input_data_signature = "no-input"

    if input_method == "Upload .eml file":
        uploaded_file = st.file_uploader("Upload .eml file", type=["eml"])
        if uploaded_file is not None:
            file_size = getattr(uploaded_file, "size", None)
            if file_size is None:
                file_size = len(uploaded_file.getvalue())
            input_data_signature = f"file:{uploaded_file.name}:{file_size}"
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
                    st.session_state["analysis_result"] = None
                    st.session_state["last_analysis_signature"] = None
                    st.error(f"Parse Error: {response.status_code} - {response.text}")
                    return
    else:
        text_body = st.text_area(
            "Enter email body text:",
            height=300,
            placeholder="Paste the email body here...",
        )
        cleaned_text = text_body.strip()
        if cleaned_text:
            text_hash = hashlib.sha256(cleaned_text.encode("utf-8")).hexdigest()
            input_data_signature = f"text:{text_hash}"
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
            preview = text_body[:500]
            suffix = "..." if len(text_body) > 500 else ""
            st.write(f"**Body:** {preview}{suffix}")

    signature_parts = [
        detection_method,
        ml_model or "",
        llm_model or "",
        input_method,
        input_data_signature,
    ]
    input_signature = "|".join(signature_parts)

    if st.session_state["input_signature"] != input_signature:
        st.session_state["input_signature"] = input_signature
        st.session_state["analysis_requested"] = False
        st.session_state["analysis_result"] = None
        st.session_state["last_analysis_signature"] = None

    if parsed_data is not None:
        analyze_clicked = st.button("Run Analysis", type="primary")
        if analyze_clicked:
            st.session_state["analysis_requested"] = True

        analysis_data = None
        if (
            st.session_state["analysis_result"] is not None
            and st.session_state["last_analysis_signature"] == input_signature
        ):
            analysis_data = st.session_state["analysis_result"]

        if st.session_state["analysis_requested"]:
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
                    st.session_state["analysis_requested"] = False
                    return
                request_data = {"parsed": parsed_data}
                if ml_model:
                    request_data["ml_model"] = ml_model
                if llm_model:
                    request_data["model"] = llm_model
                analyze_response = requests.post(analyze_endpoint, json=request_data)
                if analyze_response.status_code == 200:
                    analysis_data = analyze_response.json()
                    st.session_state["analysis_result"] = analysis_data
                    st.session_state["last_analysis_signature"] = input_signature
                else:
                    st.session_state["analysis_result"] = None
                    st.session_state["last_analysis_signature"] = None
                    st.error(
                        f"Analysis Error: {analyze_response.status_code} - {analyze_response.text}"
                    )
                st.session_state["analysis_requested"] = False

        if (
            st.session_state["analysis_result"] is not None
            and st.session_state["last_analysis_signature"] == input_signature
        ):
            analysis_data = st.session_state["analysis_result"]

        if analysis_data:
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
                        score_percent = min(100, score * 10)  # Convert from 1-10 scale to %
                    st.metric("Phishing Likelihood", f"{score_percent:.0f}%")
                    st.progress(score_percent / 100, "Likelihood of Phishing")
                else:
                    st.write(f"**Likelihood:** {score}")

            st.write("**Key Findings:**")
            if "explanations" in analysis_data:
                for expl in analysis_data["explanations"]:
                    st.write(f"- {expl}")
            else:
                st.write("*Explanations not available for this detection method.*")

            if "highlighted_body" in analysis_data:
                st.write("**Highlighted Email Content:**")
                st.markdown(analysis_data["highlighted_body"], unsafe_allow_html=True)


if __name__ == "__main__":
    main()
