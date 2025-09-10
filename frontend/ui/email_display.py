"""
Email content display UI components.
"""

import streamlit as st

from backend.ingestion.mime import MultiPartParser
from backend.ingestion.parse_eml import EmlReader
from .config import MAX_DISPLAY_CONTENT_LENGTH, MAX_PART_CONTENT_LENGTH


def render_email_content(raw_eml_bytes: bytes):
    """
    Render the email processing pipeline from raw .eml to parsed content.

    Args:
        raw_eml_bytes: Raw .eml file bytes for display
    """
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
