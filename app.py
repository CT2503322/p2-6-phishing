import streamlit as st
import requests
import tempfile
import os
import hashlib
import pandas as pd
from typing import Dict, Any, Optional
import base64
import random

# API Configuration
API_BASE_URL = "http://localhost:8000"
PARSE_ENDPOINT = f"{API_BASE_URL}/parse/eml"

def main():
    """Main Streamlit application."""
    # Configure page
    st.set_page_config(page_title="Phishing Email Analyzer", layout="wide")

    def get_base64_of_bin_file(bin_file):
        with open(bin_file, 'rb') as f:
            data = f.read()
        return base64.b64encode(data).decode()

    phisherman_logo = get_base64_of_bin_file("img/phisherman_logo.png")

    taglines = [
        "Powered by caffeine and suspicion",
        "We catch em so you do not click em",
        "Reeling in shady emails since day one"
    ]
    selected_tagline = random.choice(taglines)

    # Custom CSS
    st.markdown("""
        <style>
            .banner {
                display: flex;
                justify-content: center;   /* centers whole content */
                align-items: center;
                background-color: #1E2A38; /* dark grey-blue */
                color: white;
                padding: 1.5rem 2rem;
                border-radius: 12px;
                margin-bottom: 20px;
                box-shadow: 0 4px 10px rgba(0,0,0,0.2);
                text-align: left;
            }
            .banner img {
                height: 100px;
                width: 100px;
                border-radius: 50%;
                background-color: white;
                padding: 7px;
                object-fit: contain;
                margin-right: 15px;
            }
            .banner-text {
                display: flex;
                flex-direction: column;
                align-items: flex-start;
                text-align: left;
            }
            .banner h1 {
                font-size: 3rem;
                font-weight: 700;
                margin: 0;
            }
            .tagline {
                font-size: 1rem;
                font-weight: 400;
                margin-top: 5px;
                color: #cfd8dc;
            }
            
            }
        </style>
    """, unsafe_allow_html=True)

    
    # Banner HTML
    st.markdown(f"""
    <div class="banner">
        <img src="data:image/png;base64,{phisherman_logo}" alt="logo">
        <div class="banner-text">
        <h1>Phisherman</h1>
        <div class="tagline">{selected_tagline}</div>
    </div>
    </div>
    """, unsafe_allow_html=True)


    #st.image("img/phisherman_logo.png", width=150) 
    st.title("Welcome to your personalised phishing detector!\n")

    # Session defaults
    st.session_state.setdefault("analysis_requested", False)
    st.session_state.setdefault("analysis_result", None)           
    st.session_state.setdefault("input_signature", None)
    st.session_state.setdefault("last_analysis_signature", None)
    st.session_state.setdefault("multi_analysis_results", {})      

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
            index=0,
            help="Choose the specific LLM model to use",
        )

    # ---------- Input method ----------
    input_method = st.radio(
        "Choose input method:", ["Upload .eml files", "Enter email body text"]
    )

    uploaded_files = []
    text_body = ""
    parsed_text_data = None
    input_data_signature = "no-input"

    # ---------- Helpers ----------
    def compute_score_percent(score):
        if isinstance(score, (int, float)):
            if score <= 1:
                return max(0.0, min(1.0, float(score))) * 100.0
            return min(100.0, float(score) * 10.0)
        return float(score)
        

    def parse_eml_file(one_file):
        # Returns (parsed_data | None, error_msg | None)
        try:
            files = {
                "file": (
                    one_file.name,
                    one_file.getvalue(),
                    "application/octet-stream",
                )
            }
            resp = requests.post(PARSE_ENDPOINT, files=files)
            if resp.status_code == 200:
                return resp.json(), None
            else:
                return None, f"Parse Error: {resp.status_code} - {resp.text}"
        except Exception as e:
            return None, f"Parse Exception: {e}"

    def analyze_parsed(parsed_data):
        # Uses selected detection method and models
        if detection_method == "algorithmic":
            analyze_endpoint = f"{API_BASE_URL}/analyze/algorithmic"
        elif detection_method == "ML":
            analyze_endpoint = f"{API_BASE_URL}/analyze/ml"
        elif detection_method == "LLM":
            analyze_endpoint = f"{API_BASE_URL}/analyze/llm"
        else:
            return None, "Unknown detection method"

        payload = {"parsed": parsed_data}
        if ml_model:
            payload["ml_model"] = ml_model
        if llm_model:
            payload["model"] = llm_model

        try:
            resp = requests.post(analyze_endpoint, json=payload)
            if resp.status_code == 200:
                return resp.json(), None
            else:
                return None, f"Analysis Error: {resp.status_code} - {resp.text}"
        except Exception as e:
            return None, f"Analysis Exception: {e}"


    if input_method == "Upload .eml files":
        uploaded_files = st.file_uploader(
            "Upload one or more .eml files", type=["eml"], accept_multiple_files=True
        )
        if uploaded_files:
            sig_parts = []
            for f in uploaded_files:
                size = getattr(f, "size", None) or len(f.getvalue())
                sig_parts.append(f"{f.name}:{size}")
            sig_parts.sort()
            input_data_signature = "files:" + "|".join(sig_parts)

    
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
            parsed_text_data = {
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
        st.session_state["multi_analysis_results"] = {}
        st.session_state["last_analysis_signature"] = None

    analyze_clicked = st.button("Run Analysis", type="primary")
    if analyze_clicked:
        st.session_state["analysis_requested"] = True

    if st.session_state["analysis_requested"]:
        if input_method == "Upload .eml files" and uploaded_files:
            results = {}
            errors = {}
            with st.spinner(f"Analyzing {len(uploaded_files)} file(s) using {detection_method} detection..."):
                for f in uploaded_files:
                    with st.status(f"Processing **{f.name}**", expanded=False) as status:
                        parsed, perr = parse_eml_file(f)
                        if perr:
                            errors[f.name] = perr
                            status.update(label=f"❌ {f.name}: parse failed", state="error")
                            continue

                        analysis, aerr = analyze_parsed(parsed)
                        if aerr:
                            errors[f.name] = aerr
                            status.update(label=f"❌ {f.name}: analysis failed", state="error")
                            continue

                        results[f.name] = {"parsed": parsed, "analysis": analysis}
                        status.update(label=f"✅ {f.name}: done", state="complete")

            st.session_state["multi_analysis_results"] = results
            st.session_state["last_analysis_signature"] = input_signature
            st.session_state["analysis_requested"] = False

            if errors:
                with st.expander("Errors (click to expand)"):
                    for fn, msg in errors.items():
                        st.error(f"{fn}: {msg}")

        
        elif parsed_text_data is not None:
            with st.spinner(f"Analyzing for phishing using {detection_method} detection..."):
                analysis, err = analyze_parsed(parsed_text_data)
                if err:
                    st.session_state["analysis_result"] = None
                    st.session_state["last_analysis_signature"] = None
                    st.error(err)
                else:
                    st.session_state["analysis_result"] = analysis
                    st.session_state["last_analysis_signature"] = input_signature
            st.session_state["analysis_requested"] = False
        else:
            st.session_state["analysis_requested"] = False
            st.warning("No input to analyze yet.")

    
    if (
        input_method == "Upload .eml files"
        and st.session_state["multi_analysis_results"]
        and st.session_state["last_analysis_signature"] == input_signature
    ):
        st.subheader("Analysis Summary")

        rows = []
        for fname, bundle in st.session_state["multi_analysis_results"].items():
            analysis = bundle.get("analysis", {}) or {}
            label = (analysis.get("label") or "N/A").upper()
            score = analysis.get("score", None)
            pct = compute_score_percent(score)
            rows.append({
                "File Name": fname,
                "Legitimate / Phishing": label,
                "Phishing Likelihood (%)": None if pct is None else round(pct, 0),
            })

        df = pd.DataFrame(rows).sort_values(by="File Name").reset_index(drop=True)
        st.dataframe(df, width='stretch')

        st.caption("Click a file below to view detailed findings.")
        for fname, bundle in sorted(st.session_state["multi_analysis_results"].items()):
            analysis = bundle.get("analysis", {}) or {}
            parsed = bundle.get("parsed", {}) or {}

            with st.expander(fname):
                col1, col2 = st.columns(2)
                with col1:
                    label = (analysis.get("label") or "N/A").upper()
                    score = analysis.get("score", "N/A")
                    if isinstance(score, (int, float)):
                        st.write(f"**Label:** {label} ({score:.2f})")
                    else:
                        st.write(f"**Label:** {label}")

                with col2:
                    pct = compute_score_percent(analysis.get("score", "N/A"))
                    if pct is not None:
                        st.metric("Phishing Likelihood", f"{pct:.0f}%")
                        st.progress(pct / 100, "Likelihood of Phishing")
                    else:
                        st.write(f"**Likelihood:** {analysis.get('score', 'N/A')}")

                st.write("**Key Findings:**")
                if "explanations" in analysis and analysis["explanations"]:
                    for expl in analysis["explanations"]:
                        st.write(f"- {expl}")
                else:
                    st.write("*Explanations not available for this detection method.*")

                if "highlighted_body" in analysis and analysis["highlighted_body"]:
                    st.write("**Highlighted Email Content:**")
                    st.markdown(analysis["highlighted_body"], unsafe_allow_html=True)

                with st.expander("Parsed Email Data (raw JSON)"):
                    st.json(parsed)


    elif (
        st.session_state["analysis_result"] is not None
        and st.session_state["last_analysis_signature"] == input_signature
        and parsed_text_data is not None
    ):
        analysis_data = st.session_state["analysis_result"]
        st.subheader("Analysis Results")

        col1, col2 = st.columns(2)
        with col1:
            label = (analysis_data.get("label", "N/A") or "N/A").upper()
            score = analysis_data.get("score", "N/A")
            if isinstance(score, (int, float)):
                st.write(f"**Label:** {label} ({score:.2f})")
            else:
                st.write(f"**Label:** {label}")
        with col2:
            pct = compute_score_percent(analysis_data.get("score", "N/A"))
            if pct is not None:
                st.metric("Phishing Likelihood", f"{pct:.0f}%")
                st.progress(pct / 100, "Likelihood of Phishing")
            else:
                st.write(f"**Likelihood:** {analysis_data.get('score', 'N/A')}")

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