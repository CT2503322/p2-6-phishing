"""
Email content display UI components.
"""

import streamlit as st
import time
from typing import Dict, Any


def render_processing_pipeline_steps(uploaded_file):
    """
    Render a step-by-step visualization of the email processing pipeline.

    Args:
        uploaded_file: The uploaded file to analyze
    """
    st.markdown("### Email Processing Pipeline")

    # Define the processing steps in order
    steps = [
        {
            "step": 1,
            "name": "File Upload Validation",
            "description": "Validating file format and size limits",
            "status": "completed",  # Always completed when we get here
        },
        {
            "step": 2,
            "name": "Raw Email Parsing",
            "description": "Parsing .eml file with Python email library",
            "status": "pending",
        },
        {
            "step": 3,
            "name": "Structure Validation",
            "description": "Validating email structure and format",
            "status": "pending",
        },
        {
            "step": 4,
            "name": "Header Extraction",
            "description": "Extracting and normalizing email headers",
            "status": "pending",
        },
        {
            "step": 5,
            "name": "Content Processing",
            "description": "Processing text and HTML body content",
            "status": "pending",
        },
        {
            "step": 6,
            "name": "MIME Parts Analysis",
            "description": "Analyzing multipart and attachment structure",
            "status": "pending",
        },
        {
            "step": 7,
            "name": "Sender Identity Analysis",
            "description": "Analyzing sender information and consistency",
            "status": "pending",
        },
        {
            "step": 8,
            "name": "Authentication Verification",
            "description": "Verifying SPF, DKIM, DMARC authentication",
            "status": "pending",
        },
        {
            "step": 9,
            "name": "Attachment Security",
            "description": "Scanning attachments for malicious content",
            "status": "pending",
        },
        {
            "step": 10,
            "name": "Domain & URL Analysis",
            "description": "Extracting and analyzing domains and URLs",
            "status": "pending",
        },
        {
            "step": 11,
            "name": "Keyword Detection",
            "description": "Position-aware keyword and phishing pattern detection",
            "status": "pending",
        },
        {
            "step": 12,
            "name": "Lookalike Detection",
            "description": "Detecting typosquatting and similar domains",
            "status": "pending",
        },
        {
            "step": 13,
            "name": "Risk Assessment",
            "description": "Calculating final phishing risk score",
            "status": "pending",
        },
    ]

    # Create progress containers for each step
    step_containers = []
    for i, step_data in enumerate(steps):
        if i == 0:  # File upload is always completed when we get here
            step_data["status"] = "completed"
        container = st.empty()
        step_containers.append(container)

    # Render initial state
    for i, (container, step_data) in enumerate(zip(step_containers, steps)):
        _render_step(container, step_data, i + 1)

    return step_containers, steps


def _render_step(container, step_data, step_number):
    """Render a single processing step with appropriate styling."""
    with container:
        status = step_data["status"]

        if status == "completed":
            col1, col2, col3 = st.columns([1, 1, 8])
            with col1:
                st.success(f"STEP {step_number}")
            with col2:
                st.write("OK")
            with col3:
                st.write(f"**{step_data['name']}** - {step_data['description']}")

        elif status == "processing":
            col1, col2, col3 = st.columns([1, 1, 8])
            with col1:
                st.info(f"STEP {step_number}")
            with col2:
                st.write("...")  # Changed from ⟳
            with col3:
                st.write(f"**{step_data['name']}** - {step_data['description']}")

        elif status == "failed":
            col1, col2, col3 = st.columns([1, 1, 8])
            with col1:
                st.error(f"STEP {step_number}")
            with col2:
                st.write("FAIL")
            with col3:
                st.write(f"**{step_data['name']}** - {step_data['description']}")

        else:  # pending
            col1, col2, col3 = st.columns([1, 1, 8])
            with col1:
                st.write(f"STEP {step_number}")
            with col2:
                st.write("WAIT")
            with col3:
                st.write(f"**{step_data['name']}** - {step_data['description']}")


def update_pipeline_step(
    step_containers, steps, step_index, status="completed", delay=0.5
):
    """
    Update the status of a specific pipeline step with a delay for visual effect.

    Args:
        step_containers: List of Streamlit containers for each step
        steps: List of step data dictionaries
        step_index: Index of the step to update (0-based)
        status: New status ("completed", "processing", "failed", "pending")
        delay: Delay in seconds before updating
    """
    if delay > 0:
        time.sleep(delay)

    if 0 <= step_index < len(steps):
        steps[step_index]["status"] = status
        _render_step(step_containers[step_index], steps[step_index], step_index + 1)


def show_analysis_pipeline(uploaded_file, api_result):
    """
    Show the complete analysis pipeline with step-by-step progression.

    Args:
        uploaded_file: The uploaded .eml file
        api_result: Results from the API analysis
    """
    st.markdown("---")

    # Initialize pipeline display
    step_containers, steps = render_processing_pipeline_steps(uploaded_file)

    # Simulate step progression based on API result structure
    if api_result:
        # Step 2: Raw parsing
        update_pipeline_step(step_containers, steps, 1, "completed", 0.2)

        # Step 3: Structure validation
        update_pipeline_step(step_containers, steps, 2, "completed", 0.2)

        # Step 4: Header extraction (always present in key_headers)
        update_pipeline_step(step_containers, steps, 3, "completed", 0.2)

        # Step 5: Content processing (html_text or subject indicates processing)
        update_pipeline_step(step_containers, steps, 4, "completed", 0.2)

        # Step 6: MIME parts analysis
        if "parts" in api_result or "attachment_findings" in api_result:
            update_pipeline_step(step_containers, steps, 5, "completed", 0.2)
        else:
            update_pipeline_step(step_containers, steps, 5, "completed", 0.2)

        # Step 7: Sender identity analysis
        if "sender_identity" in api_result:
            update_pipeline_step(step_containers, steps, 6, "completed", 0.2)
        else:
            update_pipeline_step(step_containers, steps, 6, "completed", 0.2)

        # Step 8: Authentication verification
        if "auth" in api_result:
            update_pipeline_step(step_containers, steps, 7, "completed", 0.2)
        else:
            update_pipeline_step(step_containers, steps, 7, "completed", 0.2)

        # Step 9: Attachment analysis
        update_pipeline_step(step_containers, steps, 8, "completed", 0.2)

        # Step 10: Domain & URL analysis
        if "domains" in api_result or "url_findings" in api_result:
            update_pipeline_step(step_containers, steps, 9, "completed", 0.2)
        else:
            update_pipeline_step(step_containers, steps, 9, "completed", 0.2)

        # Step 11: Keyword detection
        if "keyword_analysis" in api_result:
            update_pipeline_step(step_containers, steps, 10, "completed", 0.2)
        else:
            update_pipeline_step(step_containers, steps, 10, "completed", 0.2)

        # Step 12: Lookalike detection
        if "lookalike_domains" in api_result or "confusable_findings" in api_result:
            update_pipeline_step(step_containers, steps, 11, "completed", 0.2)
        else:
            update_pipeline_step(step_containers, steps, 11, "completed", 0.2)

        # Step 13: Risk assessment
        if "score_total" in api_result or "label" in api_result:
            update_pipeline_step(step_containers, steps, 12, "completed", 0.2)
        else:
            update_pipeline_step(step_containers, steps, 12, "completed", 0.2)
    else:
        # Mark all steps as failed if no result
        for i in range(len(steps)):
            if i == 0:  # Skip first step as it's always completed
                continue
            update_pipeline_step(step_containers, steps, i, "failed", 0.1)


def render_email_content(raw_eml_bytes: bytes):
    """
    Render the email processing pipeline from raw .eml to parsed content.

    Args:
        raw_eml_bytes: Raw .eml file bytes for display
    """
    from backend.ingestion.mime import MultiPartParser
    from backend.ingestion.parse_eml import EmlReader
    from .config import MAX_DISPLAY_CONTENT_LENGTH, MAX_PART_CONTENT_LENGTH

    parser = MultiPartParser(raw_eml_bytes)
    reader = EmlReader(raw_eml_bytes)

    with st.expander("Email Processing Pipeline", expanded=False):
        # Step 1: Raw .eml Input
        st.subheader("Step 1: Raw .eml Input")
        st.markdown("**Raw email file content (first 2000 characters):**")

        # Decode bytes to string for display
        try:
            raw_content = raw_eml_bytes.decode("utf-8", errors="replace")
            # Show first 2000 characters to avoid overwhelming the UI
            display_content = raw_content[:MAX_DISPLAY_CONTENT_LENGTH]
            if len(raw_content) > MAX_DISPLAY_CONTENT_LENGTH:
                display_content += f"\n\n... ({len(raw_content) - MAX_DISPLAY_CONTENT_LENGTH} more characters)"

            st.code(display_content, language="text")
            st.info(f"Raw file size: {len(raw_eml_bytes):,} bytes")
        except Exception as e:
            st.error(f"Could not decode raw content: {str(e)}")
            st.code(f"Binary data ({len(raw_eml_bytes)} bytes)", language="text")

        # Processing indicator
        st.markdown("---")
        st.subheader("Step 2: Parsing Process")
        with st.container():
            col1, col2, col3 = st.columns(3)

            with col1:
                st.success("**Bytes Parsed**")
                st.write(
                    "Raw .eml bytes converted using stdlib email parser with policy=default"
                )

            with col2:
                st.success("**Headers Extracted**")
                st.write("Email headers parsed and decoded")

            with col3:
                st.success("**Content Structured**")
                st.write("Multipart content organized into parts")

        # Step 3: Parsed Results
        st.markdown("---")
        st.subheader("Step 3: Parsed Email Structure")

        # Basic headers
        st.markdown("**Headers**")
        col1, col2 = st.columns(2)

        with col1:
            headers_to_show = ["From", "To", "Subject", "Date"]
            for header in headers_to_show:
                value = reader.get_header(header)
                if value:
                    st.write(f"**{header}:** {value}")

        with col2:
            additional_headers = ["Reply-To", "Return-Path", "Message-ID"]
            for header in additional_headers:
                value = reader.get_header(header)
                if value:
                    st.write(f"**{header}:** {value}")

        # Content type info
        st.markdown("**Content Type Information**")
        ctype = parser.get_content_type()
        st.write(f"• **Media Type:** {ctype.get('media_type', 'N/A')}")
        st.write(f"• **Sub Type:** {ctype.get('sub_type', 'N/A')}")
        if ctype.get("charset"):
            st.write(f"• **Charset:** {ctype.get('charset')}")
        if ctype.get("boundary"):
            st.write(f"• **Boundary:** {ctype.get('boundary')}")

        # Body content
        st.markdown("**Body Content**")
        text_body = reader.get_body_text()
        html_body = reader.get_body_html()
        if text_body:
            st.text_area("Text Body", text_body, height=200, disabled=True)
        if html_body:
            st.code(html_body, language="html")
        if not text_body and not html_body:
            st.info("No body content found")

        # Multipart information
        parts = parser.get_multi_parts()
        if parts:
            st.markdown("**Multipart Components**")
            st.info(f"Email contains {len(parts)} parts")

            for i, part in enumerate(parts, 1):
                with st.expander(f"Part {i} Details", expanded=False):
                    part_ctype = part.get_content_type()
                    st.write(
                        f"**Content Type:** {part_ctype.get('media_type', 'N/A')}/{part_ctype.get('sub_type', 'N/A')}"
                    )

                    if part.is_attachment:
                        st.success(
                            f"**Attachment Detected:** {part.get_filename() or 'Unnamed'}"
                        )
                    elif part.is_inline_image:
                        st.success(
                            f"**Inline Image Detected:** {part.get_filename() or 'Unnamed'} (CID: {part.get_content_id() or 'N/A'})"
                        )

                    part_body = part.get_body()
                    if part_body:
                        if len(part_body) < MAX_PART_CONTENT_LENGTH:
                            st.text_area(
                                f"Part {i} Content",
                                part_body,
                                height=100,
                                disabled=True,
                                key=f"part_{i}",
                            )
                        else:
                            st.write(
                                f"Content too long to display ({len(part_body)} characters)"
                            )
                            st.text_area(
                                f"Part {i} Content (truncated)",
                                part_body[:MAX_PART_CONTENT_LENGTH] + "...",
                                height=100,
                                disabled=True,
                                key=f"part_{i}",
                            )

        # Flags summary
        st.markdown("**Detection Flags**")
        flags = []
        if parser.is_attachment:
            flags.append("Has Attachments")
        if parser.is_inline_image:
            flags.append("Has Inline Images")

        if flags:
            for flag in flags:
                st.write(f"• {flag}")
        else:
            st.write("• No special content flags detected")

        # Processing summary
        st.markdown("---")
        st.subheader("Processing Summary")
        summary_col1, summary_col2, summary_col3 = st.columns(3)

        with summary_col1:
            st.metric("Raw Size", f"{len(raw_eml_bytes):,} bytes")

        with summary_col2:
            st.metric("Parts Found", len(parts) if parts else 0)

        with summary_col3:
            content_type = parser.content_type or "Unknown"
            st.metric(
                "Root Type",
                content_type.split("/")[0] if "/" in content_type else content_type,
            )
