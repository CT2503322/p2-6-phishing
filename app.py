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
    custom_css = """
        <style>
            :root {
                --primary-color: #2563eb;
                --primary-dark: #1e40af;
                --accent-color: #22d3ee;
                --surface-color: rgba(30, 58, 138, 0.28);
                --surface-hover: rgba(30, 58, 138, 0.33);
                --border-subtle: rgba(148, 163, 184, 0.25);
                --text-strong: #e2e8f0;
                --text-muted: #94a3b8;
                --radius-lg: 22px;
                --radius-md: 16px;
                --shadow-elevated: 0 24px 55px rgba(15, 23, 42, 0.45);
            }
            [data-testid="stAppViewContainer"] > .main {
                background: radial-gradient(circle at 10% 20%, #0f172a 0%, #020617 45%, #0b1120 100%);
                color: var(--text-strong);
                padding: 2.5rem 3.5rem 3rem;
            }
            [data-testid="stHeader"], [data-testid="stToolbar"] {
                background: transparent;
            }
            .banner {
                display: grid;
                grid-template-columns: auto 1fr auto;
                align-items: center;
                gap: 1.75rem;
                background: linear-gradient(135deg, rgba(37,99,235,0.95), rgba(129,140,248,0.95));
                padding: 1.75rem 2rem;
                border-radius: var(--radius-lg);
                box-shadow: var(--shadow-elevated);
                margin-bottom: 2.5rem;
            }

            .banner .logo-wrap {
                width: 96px;
                height: 96px;
                border-radius: 50%;
                background: rgba(255, 255, 255, 0.9);
                display: grid;
                place-items: center;
                overflow: hidden;
            }

            .banner .logo-wrap img {
                width: 140%;
                height: 140%;
                object-fit: cover; 
            }

            .banner-text {
                display: flex;
                flex-direction: column;
                justify-content:center;  
            }

            .banner h1 {
                font-size: 2.6rem;
                font-weight: 700;
                margin: 0;
                color: #ffffff;
            }

            .banner .tagline {
                margin: 0;
                font-size: 1.05rem;
                color: rgba(226, 232, 240, 0.85);
            }

            .banner .badge {
                background: rgba(15, 23, 42, 0.25);
                color: #e0f2fe;
                padding: 0.35rem 0.9rem;
                border-radius: 999px;
                font-size: 0.85rem;
                font-weight: 600;
                border: 1px solid rgba(224, 242, 254, 0.4);
                white-space: nowrap;
            }

            .page-intro {
                font-size: 1.75rem;
                font-weight: 600;
                margin-bottom: 0.35rem;
            }

            .page-description {
                font-size: 1rem;
                color: var(--text-muted);
                margin-bottom: 1.8rem;
                max-width: 780px;
            }

            .card {
                background: var(--surface-color);
                border-radius: var(--radius-lg);
                padding: 1.8rem 2rem;
                border: 1px solid var(--border-subtle);
                margin-bottom: 1.5rem;
                box-shadow: 0 18px 45px rgba(15, 23, 42, 0.35);
                backdrop-filter: blur(12px);
            }

            .card:hover {
                background: var(--surface-hover);
            }

            .card h3 {
                margin-top: 0;
                margin-bottom: 0.25rem;
                font-size: 1.35rem;
                font-weight: 650;
            }

            .card .card-description {
                margin-bottom: 1.2rem;
                color: var(--text-muted);
            }

            .selection-hint {
                color: var(--text-muted);
                padding-top: 0.75rem;
                font-size: 0.95rem;
            }

            .section-heading {
                font-size: 1.05rem;
                font-weight: 600;
                margin: 1.2rem 0 0.6rem;
            }

            .stButton > button {
                background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
                color: #f8fafc;
                border: none;
                border-radius: 999px;
                padding: 0.8rem 1.9rem;
                font-weight: 600;
                letter-spacing: 0.02em;
                box-shadow: 0 20px 40px rgba(37, 99, 235, 0.35);
            }

            .stButton > button:hover {
                background: linear-gradient(135deg, var(--primary-dark), var(--primary-color));
            }

            .stSelectbox label, .stRadio label, .stTextArea label {
                font-weight: 600 !important;
                color: var(--text-strong) !important;
            }

            div[data-baseweb="select"] > div {
                background: rgba(15, 23, 42, 0.55);
                border-radius: var(--radius-md);
                border: 1px solid var(--border-subtle);
            }

            div[data-baseweb="select"] > div:hover {
                border-color: rgba(96, 165, 250, 0.8);
            }

            .stTextArea textarea {
                background: rgba(15, 23, 42, 0.55);
                border-radius: var(--radius-md);
                border: 1px solid var(--border-subtle);
                color: var(--text-strong);
            }

            .stTextArea textarea:focus {
                border-color: rgba(96, 165, 250, 0.9);
                box-shadow: 0 0 0 1px rgba(96, 165, 250, 0.45);
            }

            [data-testid="stFileUploaderDropzone"] {
                border-radius: var(--radius-lg);
                background: rgba(15, 23, 42, 0.5);
                border: 1.4px dashed var(--border-subtle);
                padding: 1.25rem 1rem;
                transition: border 0.2s ease, background 0.2s ease;
            }

            [data-testid="stFileUploaderDropzone"]:hover {
                border-color: rgba(96, 165, 250, 0.85);
            }

            .stRadio div[role="radiogroup"] > label {
                border-radius: var(--radius-md);
                border: 1px solid transparent;
                background: rgba(15, 23, 42, 0.35);
                padding: 0.55rem 0.85rem;
                transition: border 0.2s ease, background 0.2s ease;
            }

            .stRadio div[role="radiogroup"] > label:hover {
                border-color: rgba(96, 165, 250, 0.45);
            }

            .stProgress > div > div {
                background: var(--accent-color);
            }

            [data-testid="stMetricValue"] {
                color: #f8fafc;
            }

            .streamlit-expanderHeader {
                background: rgba(15, 23, 42, 0.4);
                border-radius: var(--radius-md);
                color: var(--text-strong);
                border: 1px solid var(--border-subtle);
            }

            [data-testid="stDataFrame"] > div:nth-child(1) > div {
                border-radius: var(--radius-md);
                border: 1px solid var(--border-subtle);
            }

            .stAlert {
                border-radius: var(--radius-md);
            }

            div[data-testid="stMarkdown"] ul {
                padding-left: 1.2rem;
                margin-bottom: 0.75rem;
            }

            div[data-testid="stMarkdown"] li {
                margin-bottom: 0.4rem;
                overflow-wrap: anywhere;
                word-break: break-word;
            }

            div[data-testid="stMarkdown"] li a {
                overflow-wrap: anywhere;
                word-break: break-all;
            }

            div[data-testid="stMarkdown"] a {
                overflow-wrap: anywhere;
                word-break: break-all;
            }
            
        </style>
    """
    st.markdown(custom_css, unsafe_allow_html=True)

    # Banner HTML
    st.markdown(
        f"""
        <div class="banner">
            <div class="logo-wrap">
                <img src="data:image/png;base64,{phisherman_logo}" alt="Phisherman logo">
            </div>
            <div class="banner-text">
                <h1>Phisherman</h1>
                <p class="tagline">{selected_tagline}</p>
            </div>
            <div class="badge">Live threat intelligence</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="page-intro">Welcome to Phisherman!</div>
        <p class="page-description">
            Upload suspicious email files or paste the message body. Compare rule-based, machine learning,
            and LLM-driven analysis without leaving this workspace.
        </p>
        """,
        unsafe_allow_html=True,
    )

    # Session defaults
    st.session_state.setdefault("analysis_requested", False)
    st.session_state.setdefault("analysis_result", None)
    st.session_state.setdefault("input_signature", None)
    st.session_state.setdefault("last_analysis_signature", None)
    st.session_state.setdefault("multi_analysis_results", {})

    ml_model: Optional[str] = None
    llm_model: Optional[str] = None

    st.markdown(
        "<div class='card card-settings'><h3>Detection preferences</h3>"
        "<p class='card-description'>Tune how the analyzer inspects your message.</p>",
        unsafe_allow_html=True,
    )
    settings_columns = st.columns((1, 1))
    with settings_columns[0]:
        detection_method = st.selectbox(
            "Select detection method",
            options=["algorithmic", "ML", "LLM"],
            help="Choose the detection method for phishing analysis",
        )
    with settings_columns[1]:
        if detection_method == "ML":
            ml_labels = {
                "naivebayes_complement": "Naive Bayes (Complement)",
                "naivebayes_multinomial": "Naive Bayes (Multinomial)",
                "logistic_regression": "Logistic Regression",
                "decision_tree": "Decision Tree",
            }
            ml_model = st.selectbox(
                "Select ML model",
                options=[
                    "naivebayes_complement",
                    "naivebayes_multinomial",
                    "logistic_regression",
                    "decision_tree",
                ],
                format_func=lambda x: ml_labels.get(x, x),
                help="Choose the specific ML model to use",
            )
        elif detection_method == "LLM":
            llm_model = st.selectbox(
                "Select LLM model",
                options=["gpt-5-nano", "gpt-4.1-nano", "gpt-4o-mini"],
                index=0,
                help="Choose the specific LLM model to use",
            )
        else:
            st.markdown(
                "<div class='selection-hint'>Heuristic rule engine selected.</div>",
                unsafe_allow_html=True,
            )
    st.markdown("</div>", unsafe_allow_html=True)

    uploaded_files = []
    text_body = ""
    parsed_text_data = None
    input_data_signature = "no-input"

    st.markdown(
        "<div class='card card-input'><h3>Email input</h3>"
        "<p class='card-description'>Choose how you'd like to supply the message for inspection.</p>",
        unsafe_allow_html=True,
    )
    input_method = st.radio(
        "Choose input method:",
        ["Upload .eml files", "Enter email body text"],
        horizontal=True,
    )

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
            height=280,
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
            st.markdown(
                "<h4 class='section-heading'>Input email data</h4>",
                unsafe_allow_html=True,
            )
            preview = text_body[:500]
            suffix = "..." if len(text_body) > 500 else ""
            st.write(f"**Body:** {preview}{suffix}")

    button_columns = st.columns([0.32, 0.68])
    with button_columns[0]:
        analyze_clicked = st.button("Run Analysis", type="primary")
    st.markdown("</div>", unsafe_allow_html=True)

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
        st.markdown("<div class='card card-results'>", unsafe_allow_html=True)
        st.markdown("<h3 class='section-heading'>Analysis summary</h3>", unsafe_allow_html=True)

        rows = []
        for fname, bundle in st.session_state["multi_analysis_results"].items():
            analysis = bundle.get("analysis", {}) or {}
            label = (analysis.get("label") or "N/A")
            score = analysis.get("score", None)
            pct = compute_score_percent(score)
            rows.append({
                "File Name": fname,
                "Legitimate / Phishing": label,
                "Confidence Rating (%)": None if pct is None else round(pct, 0),
            })

        df = pd.DataFrame(rows).sort_values(by="File Name").reset_index(drop=True)
        st.dataframe(df, width="content")

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
                        st.metric("Confidence Rating", f"{pct:.0f}%")
                        st.progress(pct / 100, "Likelihood of Phishing")
                    else:
                        st.write(f"**Likelihood:** {analysis.get('score', 'N/A')}")

                st.markdown("**Key Findings:**")
                if "explanations" in analysis and analysis["explanations"]:
                    findings_lines = "\n".join(f"- {expl}" for expl in analysis["explanations"])
                    st.markdown(findings_lines)
                else:
                    st.markdown("*Explanations not available for this detection method.*")

                if "highlighted_body" in analysis and analysis["highlighted_body"]:
                    st.write("**Highlighted Email Content:**")
                    st.markdown(analysis["highlighted_body"], unsafe_allow_html=True)

            with st.expander("Parsed Email Data (raw JSON)"):
                st.json(parsed)

        st.markdown("</div>", unsafe_allow_html=True)


    elif (
        st.session_state["analysis_result"] is not None
        and st.session_state["last_analysis_signature"] == input_signature
        and parsed_text_data is not None
    ):
        analysis_data = st.session_state["analysis_result"]
        st.markdown("<div class='card card-results'>", unsafe_allow_html=True)
        st.markdown("<h3 class='section-heading'>Analysis results</h3>", unsafe_allow_html=True)

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

        st.markdown("</div>", unsafe_allow_html=True)


if __name__ == "__main__":
    main()

