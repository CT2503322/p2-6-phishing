"""
Analysis results UI components.
"""

import streamlit as st
from typing import Dict, Any


def render_analysis_results(result: Dict[str, Any]):
    """
    Render the analysis results from the backend API.

    Args:
        result: Analysis results from the API
    """
    st.success("Analysis Complete!")

    # Scoring removed - no risk score display

    # Sender Identity Analysis
    if "sender_identity" in result:
        render_sender_identity_results(result["sender_identity"])

    # Authentication Results
    if "auth" in result:
        render_authentication_results(result["auth"])

    # Raw Authentication Headers
    if "raw_auth_headers" in result:
        render_raw_authentication_headers(result["raw_auth_headers"])

    # Subscription Metadata
    if "subscription" in result:
        render_subscription_metadata(result["subscription"])

    # Routing Information
    if "routing_data" in result:
        render_routing_results(result["routing_data"])

    # Detailed Results
    if "meta" in result:
        meta = result["meta"]

        # Keywords
        if "keywords" in meta:
            with st.expander("Keyword Analysis"):
                keywords = meta["keywords"]
                if keywords:
                    for keyword in keywords:
                        st.write(f"• {keyword['keyword']} (count: {keyword['count']})")
                else:
                    st.write("No suspicious keywords detected")

        # Domains
        if "domains" in meta:
            with st.expander("Domain Analysis"):
                domains = meta["domains"]
                if domains:
                    for domain in domains:
                        st.write(f"• {domain}")
                else:
                    st.write("No domains detected")

        # Headers
        if "headers" in meta:
            with st.expander("Header Analysis"):
                headers = meta["headers"]
                if headers:
                    for header, value in headers.items():
                        st.write(f"• **{header}:** {value}")
                else:
                    st.write("No headers detected")

    # URL Findings
    if "url_findings" in result and result["url_findings"]:
        render_url_findings_results(result["url_findings"])

    # Detailed Keyword Analysis
    if "keyword_analysis" in result:
        render_keyword_analysis_results(result["keyword_analysis"])

    # Content Analysis Summary
    if "html_text" in result or "domains" in result:
        render_content_analysis(result)

    # Raw JSON (for debugging)
    with st.expander("Raw Analysis Data"):
        st.json(result)


def render_authentication_results(auth_data: Dict[str, Any]):
    """
    Render the authentication results in a user-friendly format.

    Args:
        auth_data: Authentication data from the analysis
    """
    with st.expander("Authentication Analysis", expanded=True):
        st.markdown("**Email Authentication Results**")

        # SPF Results
        if auth_data.get("spf"):
            spf = auth_data["spf"]
            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.metric("SPF", spf.get("result", "unknown").upper())

            with col2:
                st.metric("SPF Domain", spf.get("domain", "N/A"))

            with col3:
                st.metric("SPF IP", spf.get("ip", "N/A"))

            with col4:
                st.metric("SPF Aligned", spf.get("aligned", False))

        # DKIM Results
        if auth_data.get("dkim"):
            dkim_list = auth_data["dkim"]
            st.markdown("**DKIM Signatures**")

            for i, dkim in enumerate(dkim_list, 1):
                col1, col2, col3, col4 = st.columns(4)

                with col1:
                    st.metric(f"DKIM {i}", dkim.get("result", "unknown").upper())

                with col2:
                    st.metric(f"DKIM {i} Domain", dkim.get("d", "N/A"))

                with col3:
                    st.metric(f"DKIM {i} Selector", dkim.get("s", "N/A"))

                with col4:
                    st.metric(f"DKIM {i} Aligned", dkim.get("aligned", False))

        # DMARC Results
        if auth_data.get("dmarc"):
            dmarc = auth_data["dmarc"]
            st.markdown("**DMARC**")

            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.metric("DMARC", dmarc.get("result", "unknown").upper())

            with col2:
                st.metric("DMARC Policy", dmarc.get("policy", "N/A"))

            with col3:
                st.metric("DMARC Org Domain", dmarc.get("org_domain", "N/A"))

            with col4:
                st.metric("DMARC Aligned", dmarc.get("aligned", False))

        # ARC Results
        if auth_data.get("arc"):
            arc = auth_data["arc"]
            st.markdown("**ARC (Authenticated Received Chain)**")

            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.metric("ARC Instance", arc.get("instance", "N/A"))

            with col2:
                st.metric("ARC Seal", arc.get("seal", "unknown"))

            with col3:
                st.metric("ARC Chain Validation", arc.get("cv", "N/A"))

            with col4:
                st.metric("ARC Chain Count", arc.get("chain_count", "N/A"))

        # Summary
        st.markdown("---")
        st.markdown("**Authentication Summary**")

        auth_status = []
        if auth_data.get("spf", {}).get("result") == "pass":
            auth_status.append("SPF Pass")
        if any(dkim.get("result") == "pass" for dkim in auth_data.get("dkim", [])):
            auth_status.append("DKIM Pass")
        if auth_data.get("dmarc", {}).get("result") == "pass":
            auth_status.append("DMARC Pass")
        if auth_data.get("arc", {}).get("seal") == "pass":
            auth_status.append("ARC Pass")

        if auth_status:
            st.success("Email authentication passed: " + " | ".join(auth_status))
        else:
            st.warning("Email authentication failed or not present")


def render_sender_identity_results(sender_identity: Dict[str, Any]):
    """
    Render the sender identity analysis results in a user-friendly format.

    Args:
        sender_identity: Sender identity data from the analysis
    """
    with st.expander("Sender Identity Analysis", expanded=True):
        st.markdown("**Sender Information & Validation**")

        # Basic sender information
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("**From Address**")
            from_address = sender_identity.get("from_address", "N/A")
            from_name = sender_identity.get("from_name", "")
            if from_name:
                st.code(f"{from_name} <{from_address}>")
            else:
                st.code(from_address)

            st.markdown("**From Domain**")
            from_domain = sender_identity.get("from_domain", "N/A")
            st.code(from_domain)

        with col2:
            st.markdown("**Reply-To Address**")
            reply_to_address = sender_identity.get("reply_to_address")
            reply_to_name = sender_identity.get("reply_to_name", "")
            if reply_to_address:
                if reply_to_name:
                    st.code(f"{reply_to_name} <{reply_to_address}>")
                else:
                    st.code(reply_to_address)
            else:
                st.info("No Reply-To specified")

            st.markdown("**Reply-To Domain**")
            reply_to_domain = sender_identity.get("reply_to_domain")
            if reply_to_domain:
                st.code(reply_to_domain)
            else:
                st.info("No Reply-To domain")

        # Organizational domain
        st.markdown("**Organizational Domain**")
        org_domain = sender_identity.get("organizational_domain")
        if org_domain:
            st.success(f"**{org_domain}**")
        else:
            st.info("Could not determine organizational domain")

        # ESP Detection
        st.markdown("---")
        st.markdown("**Email Service Provider (ESP) Detection**")

        esp_provider = sender_identity.get("email_service_provider")
        esp_confidence = sender_identity.get("esp_confidence", 0.0)

        if esp_provider:
            confidence_pct = esp_confidence * 100
            if confidence_pct >= 80:
                st.success(
                    f"**{esp_provider.title()}** detected ({confidence_pct:.1f}% confidence)"
                )
            elif confidence_pct >= 60:
                st.warning(
                    f"**{esp_provider.title()}** detected ({confidence_pct:.1f}% confidence)"
                )
            else:
                st.info(
                    f"**{esp_provider.title()}** detected ({confidence_pct:.1f}% confidence)"
                )
        else:
            st.info("No specific ESP detected")

        # ESP Indicators
        esp_indicators = sender_identity.get("esp_indicators", [])
        if esp_indicators:
            st.markdown("**Detection Indicators**")
            for indicator in esp_indicators[:8]:  # Show first 8 indicators
                st.write(f"• {indicator}")
            if len(esp_indicators) > 8:
                st.write(f"... and {len(esp_indicators) - 8} more indicators")

        # Mismatch Detection
        st.markdown("---")
        st.markdown("**From/Reply-To Mismatch Analysis**")

        has_mismatch = sender_identity.get("has_from_reply_mismatch", False)
        mismatch_details = sender_identity.get("mismatch_details", [])

        if has_mismatch:
            st.error("**WARNING: From/Reply-To Mismatch Detected!**")
            st.markdown("This could indicate potential spoofing or phishing attempt.")

            for detail in mismatch_details:
                st.write(f"• {detail}")
        else:
            st.success("**No From/Reply-To mismatches found**")
            st.markdown("Sender addresses appear legitimate and consistent.")

        # Infrastructure Details
        st.markdown("---")
        st.markdown("**Infrastructure Analysis**")

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("**Sending IP Address**")
            sending_ip = sender_identity.get("sending_ip")
            if sending_ip:
                st.code(sending_ip)
            else:
                st.info("IP not detected")

        with col2:
            st.markdown("**Return Path Domain**")
            return_path_domain = sender_identity.get("return_path_domain")
            if return_path_domain:
                st.code(return_path_domain)
            else:
                st.info("Return path not found")

        # Summary
        st.markdown("---")
        st.markdown("**Sender Identity Summary**")

        summary_items = []

        if esp_provider:
            summary_items.append(
                f"ESP: {esp_provider.title()} ({esp_confidence*100:.1f}% confidence)"
            )

        if org_domain:
            summary_items.append(f"Organization: {org_domain}")

        if has_mismatch:
            summary_items.append("Address/domain mismatches detected")
        else:
            summary_items.append("Consistent sender information")

        if sending_ip:
            summary_items.append(f"Infrastructure: {sending_ip}")

        if summary_items:
            for item in summary_items:
                st.write(f"• {item}")
        else:
            st.info("Limited sender identity information available")


def render_subscription_metadata(subscription_data: Dict[str, Any]):
    """
    Render the subscription metadata in a user-friendly format.

    Args:
        subscription_data: Subscription metadata from the analysis
    """
    with st.expander("Subscription & List Management", expanded=True):
        st.markdown("**List Unsubscribe Information**")

        # List-Unsubscribe-Post header
        if subscription_data.get("list_unsubscribe_post"):
            post_value = subscription_data["list_unsubscribe_post"]
            if "One-Click" in post_value:
                st.success("**One-Click Unsubscribe**: Supported")
            else:
                st.info(f"**Unsubscribe Method**: {post_value}")

        # List-Unsubscribe details
        if subscription_data.get("list_unsubscribe"):
            unsubscribe = subscription_data["list_unsubscribe"]

            st.markdown("**Unsubscribe Options**")

            col1, col2 = st.columns(2)

            with col1:
                # One-click capability
                if unsubscribe.get("one_click"):
                    st.success("**One-Click Unsubscribe**: Available")
                else:
                    st.info("**Traditional Unsubscribe**: Required")

                # HTTP URL
                if unsubscribe.get("http"):
                    st.markdown("**Web Unsubscribe URL:**")
                    url = unsubscribe["http"]
                    # Truncate long URLs for display
                    display_url = url[:80] + "..." if len(url) > 80 else url
                    st.code(display_url, language="text")
                    st.markdown(f"[Open URL]({url})", unsafe_allow_html=True)

            with col2:
                # Mailto address
                if unsubscribe.get("mailto"):
                    st.markdown("**Email Unsubscribe:**")
                    mailto = unsubscribe["mailto"]
                    st.code(mailto, language="text")

                    # Subject line
                    if unsubscribe.get("mailto_subject"):
                        st.markdown(f"**Subject:** `{unsubscribe['mailto_subject']}`")

                # Provider detection
                if unsubscribe.get("provider"):
                    provider = unsubscribe["provider"]
                    st.markdown(f"**Email Service Provider:** {provider.title()}")

        # Feedback-ID
        if subscription_data.get("feedback_id"):
            st.markdown("**Feedback Information**")
            st.info(f"**Feedback ID**: `{subscription_data['feedback_id']}`")

        # Precedence
        if subscription_data.get("precedence"):
            precedence = subscription_data["precedence"]
            st.markdown("**Message Priority**")

            if precedence.lower() == "bulk":
                st.info("**Precedence**: Bulk (Marketing/Newsletter)")
            elif precedence.lower() == "list":
                st.info("**Precedence**: List (Mailing List)")
            elif precedence.lower() == "auto":
                st.warning("**Precedence**: Auto (Automated Message)")
            else:
                st.write(f"**Precedence**: {precedence}")

        # Summary
        st.markdown("---")
        st.markdown("**Subscription Analysis Summary**")

        summary_items = []

        if subscription_data.get("list_unsubscribe"):
            unsubscribe = subscription_data["list_unsubscribe"]
            if unsubscribe.get("one_click"):
                summary_items.append("One-click unsubscribe available")
            if unsubscribe.get("http"):
                summary_items.append("Web-based unsubscribe option")
            if unsubscribe.get("mailto"):
                summary_items.append("Email-based unsubscribe option")
            if unsubscribe.get("provider"):
                summary_items.append(f"Provider: {unsubscribe['provider'].title()}")

        if subscription_data.get("list_unsubscribe_post"):
            summary_items.append("POST method supported")

        if subscription_data.get("feedback_id"):
            summary_items.append("Feedback tracking enabled")

        if summary_items:
            for item in summary_items:
                st.write(f"• {item}")
        else:
            st.info("No subscription management information found")


def render_routing_results(routing_data: Dict[str, Any]):
    """
    Render the email routing information in a user-friendly format.

    Args:
        routing_data: Routing data from the analysis
    """
    with st.expander("Email Routing Analysis", expanded=True):
        st.markdown("**Email Routing & Path Information**")

        # Received headers (routing hops)
        if routing_data.get("received") and len(routing_data["received"]) > 0:
            st.markdown("**Mail Routing Path (Received Headers)**")

            for i, received_line in enumerate(routing_data["received"], 1):
                st.markdown(f"**Hop {i}:**")
                # Display the raw received line but formatted nicely
                st.code(received_line.strip(), language="text")

                # Show parsed hop information if available
                if routing_data.get("hops") and i <= len(routing_data["hops"]):
                    hop = routing_data["hops"][i - 1]
                    col1, col2, col3, col4 = st.columns(4)

                    with col1:
                        if hop.get("by"):
                            st.markdown("**Received by:**")
                            st.code(hop["by"], language="text")

                    with col2:
                        if hop.get("from_"):
                            st.markdown("**Received from:**")
                            st.code(hop["from_"], language="text")

                    with col3:
                        if hop.get("with_"):
                            st.markdown("**Using protocol:**")
                            st.code(hop["with_"], language="text")

                    with col4:
                        if hop.get("timestamp"):
                            st.markdown("**Timestamp:**")
                            st.code(hop["timestamp"], language="text")
                    if i != len(routing_data["received"]):
                        st.markdown("---")
        else:
            st.info("No Received headers found - this appears to be a sent email")

        # X-Received headers
        if routing_data.get("x_received") and len(routing_data["x_received"]) > 0:
            st.markdown("---")
            st.markdown("**X-Received Headers**")

            for i, x_received in enumerate(routing_data["x_received"], 1):
                st.markdown(f"**X-Received {i}:**")
                st.code(x_received.strip(), language="text")

        # X-Original-To header
        if routing_data.get("x_original_to"):
            st.markdown("---")
            st.markdown("**Original Recipient**")
            st.info(f"**X-Original-To:** `{routing_data['x_original_to']}`")

        # Delivered-To header
        if routing_data.get("delivered_to"):
            st.markdown("**Final Delivery**")
            st.success(f"**Delivered-To:** `{routing_data['delivered_to']}`")

        # Summary
        if (
            routing_data.get("received")
            or routing_data.get("x_received")
            or routing_data.get("x_original_to")
            or routing_data.get("delivered_to")
        ):
            st.markdown("---")
            st.markdown("**Routing Analysis Summary**")

            summary_items = []

            if routing_data.get("received"):
                hop_count = len(routing_data["received"])
                summary_items.append(
                    f"{hop_count} routing hop{'s' if hop_count != 1 else ''} detected"
                )

            if routing_data.get("x_received"):
                x_rec_count = len(routing_data["x_received"])
                summary_items.append(
                    f"{x_rec_count} X-Received header{'s' if x_rec_count != 1 else ''}"
                )

            if routing_data.get("x_original_to"):
                summary_items.append("Original recipient information available")

            if routing_data.get("delivered_to"):
                summary_items.append("Final delivery address recorded")

            if summary_items:
                for item in summary_items:
                    st.write(f"• {item}")

            # Show total number of routing indicators
            total_indicators = sum(
                [
                    len(routing_data.get("received", [])),
                    len(routing_data.get("x_received", [])),
                    1 if routing_data.get("x_original_to") else 0,
                    1 if routing_data.get("delivered_to") else 0,
                ]
            )

            if total_indicators > 0:
                st.metric("Total Routing Indicators", total_indicators)
        else:
            st.info("No routing information found in this email")


def render_raw_authentication_headers(raw_auth_headers: Dict[str, Any]):
    """
    Render the raw authentication headers in a user-friendly format.

    Args:
        raw_auth_headers: Raw authentication header data from the analysis
    """
    if not raw_auth_headers:
        return

    with st.expander("Raw Authentication Headers", expanded=False):
        st.markdown("**Raw Authentication Data**")

        # Authentication-Results header
        if "authentication_results" in raw_auth_headers:
            st.markdown("**Authentication-Results Header**")
            st.code(raw_auth_headers["authentication_results"], language="text")
            st.markdown("• Contains SPF, DKIM, DMARC, and ARC results")

        # DKIM-Signature headers
        if "dkim_signature" in raw_auth_headers:
            st.markdown("---")
            st.markdown("**DKIM-Signature Headers**")
            dkim_data = raw_auth_headers["dkim_signature"]
            if isinstance(dkim_data, list):
                for i, sig in enumerate(dkim_data, 1):
                    st.code(sig, language="text")
                    if i < len(dkim_data):
                        st.markdown("")
            else:
                st.code(dkim_data, language="text")
            st.markdown("• Verifies email authenticity and prevents modification")

        # SPF/Reported-SPF headers
        if any(key in raw_auth_headers for key in ["received_spf", "reported_spf"]):
            st.markdown("---")
            st.markdown("**SPF Headers**")
            for key in ["received_spf", "reported_spf"]:
                if key in raw_auth_headers:
                    spf_data = raw_auth_headers[key]
                    if isinstance(spf_data, list):
                        for i, spf in enumerate(spf_data, 1):
                            st.code(spf, language="text")
                    else:
                        st.code(spf_data, language="text")
            st.markdown("• Validates sender IP address against authorized SPF records")

        # ARC headers
        arc_headers = [key for key in raw_auth_headers.keys() if key.startswith("arc_")]
        if arc_headers:
            st.markdown("---")
            st.markdown("**ARC (Authenticated Received Chain) Headers**")
            for header in sorted(arc_headers):
                st.markdown(f"**{header}:**")
                st.code(raw_auth_headers[header], language="text")
                st.markdown("• Chain validation for authenticated email transfers")

        # Summary
        header_count = len(raw_auth_headers)
        st.markdown("---")
        st.markdown(f"**Total headers:** {header_count}")


def render_url_findings_results(url_findings: Dict[str, Any]):
    """
    Render the URL findings in a user-friendly format.

    Args:
        url_findings: URL findings data from the analysis
    """
    if not url_findings:
        return

    with st.expander("URL Analysis & Findings", expanded=True):
        st.markdown("**URL Link Analysis**")
        st.markdown("Links found in the email content with security analysis:")

        # Summary metrics
        total_urls = len(url_findings)
        suspicious_count = sum(
            1
            for finding in url_findings
            if finding.get("is_ip_literal")
            or finding.get("is_shortener")
            or finding.get("text_href_mismatch")
            or (finding.get("is_punycode") and finding.get("skeleton_match"))
        )

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total URLs", total_urls)
        with col2:
            st.metric("Suspicious URLs", suspicious_count)
        with col3:
            st.metric("Safe URLs", total_urls - suspicious_count)

        # Individual URL findings
        for i, finding in enumerate(url_findings, 1):
            # Determine if suspicious
            is_suspicious = (
                finding.get("is_ip_literal")
                or finding.get("is_shortener")
                or finding.get("text_href_mismatch")
                or (finding.get("is_punycode") and finding.get("skeleton_match"))
            )

            # Color coding based on threat level
            if finding.get("is_ip_literal"):
                st.error(f"**HIGH RISK** - IP Literal URL {i}")
            elif finding.get("is_shortener"):
                st.warning(f"**MEDIUM RISK** - URL Shortener {i}")
            elif finding.get("text_href_mismatch"):
                st.warning(f"**MEDIUM RISK** - Mismatched Text {i}")
            elif finding.get("is_punycode"):
                st.warning(f"**MEDIUM RISK** - IDN/Punycode URL {i}")
            else:
                st.success(f"**LOW RISK** - Clean URL {i}")

            # Display URL details
            col1, col2 = st.columns([2, 1])

            with col1:
                st.markdown("**Link Text:**")
                st.info(f'"{finding.get("text", "N/A")}"')

                st.markdown("**URL:**")
                url = finding.get("href", "")
                if url:
                    # Truncate long URLs for display
                    display_url = url[:60] + "..." if len(url) > 60 else url
                    st.code(display_url, language="text")
                    st.markdown(f"[Open URL]({url})", unsafe_allow_html=True)
                else:
                    st.code("N/A")

            with col2:
                st.markdown("**Domain:**")
                domain = finding.get("netloc", "N/A")
                st.code(domain)

                st.markdown("**Position:**")
                pos = finding.get("first_seen_pos", 0)
                st.code(f"#{pos}")

            # Risk indicators
            risk_indicators = []

            if finding.get("is_ip_literal"):
                risk_indicators.append(
                    "**IP Address** - Uses IP instead of domain name"
                )

            if finding.get("is_punycode"):
                risk_indicators.append(
                    "**IDN/Punycode** - International Domain Name encoding"
                )

            if finding.get("skeleton_match"):
                risk_indicators.append(
                    "**Skeleton Match** - Confusable character detection"
                )

            if finding.get("is_shortener"):
                risk_indicators.append("**URL Shortener** - Link obfuscation service")

            if finding.get("text_href_mismatch"):
                risk_indicators.append(
                    "**Text Mismatch** - Link text doesn't match destination"
                )

            if finding.get("brand_match"):
                brand = finding.get("brand_match")
                risk_indicators.append(f"**Brand Match** - Recognized as {brand}")

            if not risk_indicators:
                risk_indicators.append("**Clean** - No obvious security concerns")

            if risk_indicators:
                st.markdown("**Analysis:**")
                for indicator in risk_indicators:
                    st.write(f"• {indicator}")

            # Evidence
            evidence = finding.get("evidence", "")
            if evidence:
                st.markdown("**Evidence:**")
                st.info(evidence)

            # Separator between URLs
            if i < len(url_findings):
                st.markdown("---")

        # Overall summary
        st.markdown("---")
        st.markdown("**URL Analysis Summary**")

        summary_items = []

        if suspicious_count > 0:
            summary_items.append(f"{suspicious_count} suspicious URL(s) detected")
        else:
            summary_items.append("No suspicious URLs found")

        summary_items.append(f"{total_urls} total URL(s) analyzed")

        if any(f.get("brand_match") for f in url_findings):
            brand_count = sum(1 for f in url_findings if f.get("brand_match"))
            summary_items.append(f"{brand_count} recognized brand domain(s)")

        for item in summary_items:
            st.write(f"• {item}")


def render_content_analysis(result: Dict[str, Any]):
    """
    Render content analysis summary.

    Args:
        result: Analysis results from the API
    """
    with st.expander("Content Analysis Summary", expanded=False):
        st.markdown("**Email Content Overview**")

        col1, col2 = st.columns(2)

        with col1:
            # Domains
            if "domains" in result and result["domains"]:
                st.markdown("**Domains Found:**")
                domains = list(
                    set(result["domains"][:10])
                )  # Show first 10 unique domains
                for domain in domains:
                    st.write(f"• {domain}")

                total_domains = len(set(result["domains"]))
                if total_domains > 10:
                    st.write(f"*... and {total_domains - 10} more*")
            else:
                st.write("• No domains detected")

        with col2:
            # HTML text preview
            if "html_text" in result and result["html_text"]:
                st.markdown("**Content Preview:**")
                text_preview = result["html_text"].strip()[:200]
                if len(result["html_text"]) > 200:
                    text_preview += "..."
                st.info(text_preview)
            else:
                st.info("No text content available")

        # HTML metrics
        if "html_metrics" in result:
            html_metrics = result["html_metrics"]

            st.markdown("---")
            st.markdown("**HTML Structure Metrics**")

            metric_cols = st.columns(4)

            metrics_data = [
                ("Length", f"{html_metrics.get('length', 0):,} chars"),
                ("Links", html_metrics.get("link_count", 0)),
                ("Images", html_metrics.get("image_count", 0)),
                ("Remote CSS", "Yes" if html_metrics.get("remote_css") else "No"),
            ]

            for i, (label, value) in enumerate(metrics_data):
                with metric_cols[i]:
                    st.metric(label, value)


def render_keyword_analysis_results(keyword_analysis: Dict[str, Any]):
    """
    Render the detailed keyword analysis results in a user-friendly format.

    Args:
        keyword_analysis: Keyword analysis data from the backend
    """
    if not keyword_analysis:
        return

    with st.expander("🔍 Advanced Keyword Analysis (Position-Aware)", expanded=True):
        st.markdown("**Position-Aware Keyword Detection**")
        st.markdown(
            "Keywords are weighted based on their position in the email to better assess phishing risk:"
        )

        # Overall metrics
        col1, col2, col3 = st.columns(3)

        with col1:
            total_hits = len(keyword_analysis.get("keyword_hits", []))
            st.metric("Total Keyword Hits", total_hits)

        with col2:
            total_score = keyword_analysis.get("total_score", 0.0)
            # Determine risk level based on score
            if total_score >= 10.0:
                st.metric("Risk Score", f"{total_score:.1f}", "High")
            elif total_score >= 5.0:
                st.metric("Risk Score", f"{total_score:.1f}", "Medium")
            else:
                st.metric("Risk Score", f"{total_score:.1f}", "Low")

        with col3:
            unique_keywords = len(keyword_analysis.get("term_stats", {}))
            st.metric("Unique Keywords", unique_keywords)

        # Term Statistics (most important keywords)
        term_stats = keyword_analysis.get("term_stats", {})

        if term_stats:
            st.markdown("---")
            st.markdown("**Keyword Statistics & Positions**")

            # Sort by total score (descending)
            sorted_terms = sorted(
                term_stats.items(),
                key=lambda x: x[1].get("total_score", 0),
                reverse=True,
            )

            # Create a table/dataframe for better display
            import pandas as pd

            table_data = []
            for term, stats in sorted_terms:
                positions = stats.get("positions", [])
                windows = list(set(stats.get("windows", [])))

                table_data.append(
                    {
                        "Keyword": term,
                        "Hits": stats.get("count", 0),
                        "Total Score": round(stats.get("total_score", 0), 2),
                        "Positions": ", ".join([f"#{p}" for p in positions[:3]]),
                        "Windows": ", ".join(windows),
                    }
                )

            # Show first 10 most significant keywords
            if table_data:
                df = pd.DataFrame(table_data[:10])
                st.dataframe(
                    df,
                    use_container_width=True,
                    column_config={
                        "Keyword": st.column_config.TextColumn(
                            "Keyword", width="medium"
                        ),
                        "Hits": st.column_config.NumberColumn("Hits", width="small"),
                        "Total Score": st.column_config.NumberColumn(
                            "Total Score", width="small"
                        ),
                        "Positions": st.column_config.TextColumn(
                            "Positions", width="large"
                        ),
                        "Windows": st.column_config.TextColumn(
                            "Windows", width="large"
                        ),
                    },
                )

                if len(table_data) > 10:
                    st.write(f"*... and {len(table_data) - 10} more keywords*")

        # Detailed hits breakdown (show first few)
        keyword_hits = keyword_analysis.get("keyword_hits", [])
        if keyword_hits:
            st.markdown("---")
            st.markdown("**Detailed Keyword Hits**")
            st.markdown("Each keyword hit with position information:")

            # Show first 8 hits
            for i, hit in enumerate(keyword_hits[:8], 1):
                term = hit.get("term", "")
                where = hit.get("where", "")
                pos = hit.get("pos", 0)
                weight = hit.get("weight", 0.0)
                window = hit.get("window", "")

                # Color coding based on weight
                if weight >= 2.0:
                    st.error(
                        f"**{i}.** `{term}` - **{where}** position {pos} (weight: {weight:.2f})"
                    )
                elif weight >= 1.0:
                    st.warning(
                        f"**{i}.** `{term}` - {where} position {pos} (weight: {weight:.2f})"
                    )
                else:
                    st.info(
                        f"**{i}.** `{term}` - {where} position {pos} (weight: {weight:.2f})"
                    )

                # Window information
                if window:
                    st.write(f"   Window: `{window}`")

                if i < len(keyword_hits[:8]):
                    st.write("")

            if len(keyword_hits) > 8:
                st.write(f"*... and {len(keyword_hits) - 8} more hits*")

        # Analysis summary
        st.markdown("---")
        st.markdown("**Analysis Summary**")

        summary_items = []

        if total_score >= 10.0:
            summary_items.append("**HIGH RISK** - Suspicious keyword patterns detected")
        elif total_score >= 5.0:
            summary_items.append("**MEDIUM RISK** - Some concerning keywords found")
        else:
            summary_items.append("**LOW RISK** - Few or no suspicious keywords")

        if "urgent" in [hit.get("term", "") for hit in keyword_hits]:
            summary_items.append("Urgency keywords detected")
        if "password" in [hit.get("term", "") for hit in keyword_hits]:
            summary_items.append("Password-related keywords detected")
        if "click here" in [hit.get("term", "") for hit in keyword_hits]:
            summary_items.append("Call-to-action keywords detected")

        # Subject vs Body distribution
        subject_hits = sum(1 for hit in keyword_hits if hit.get("where") == "subject")
        body_hits = sum(1 for hit in keyword_hits if hit.get("where") == "body")

        if subject_hits > 0:
            summary_items.append(f"{subject_hits} keyword(s) in subject line")
        if body_hits > 0:
            summary_items.append(f"{body_hits} keyword(s) in email body")

        if summary_items:
            for item in summary_items:
                st.write(f"• {item}")
        else:
            st.info("No significant keyword analysis available")

        # Technical notes
        with st.expander("ℹTechnical Details", expanded=False):
            st.markdown(
                """
            **Position Weighting System:**
            - **Subject keywords**: 3x multiplier (highest impact)
            - **Early body keywords** (first 500 chars): Linear decay from 2x to 1x
            - **Late body keywords**: 1x base weight
            - **Window types**: 'subject', 'body_0_500', 'body'
            """
            )
