"""
Analysis results UI components.
"""

import streamlit as st
from typing import Dict, Any
from backend.core.keywords import keyword_config


def render_analysis_results(result: Dict[str, Any]):
    """
    Render the analysis results from the backend API.

    Args:
        result: Analysis results from the API
    """
    st.success("Analysis Complete!")

    # Display overall score and label
    if "score_total" in result and "label" in result:
        # Advanced scoring metrics display
        if "scored_analysis" in result:
            # Advanced analysis available
            scored_analysis = result["scored_analysis"]

            # Top-level metrics
            col1, col2, col3, col4 = st.columns([2, 1, 1, 1])

            with col1:
                st.header("Advanced Analysis Result")

            with col2:
                score = result["score_total"]
                threshold = scored_analysis.get("threshold_used", 3.2)
                if score >= threshold:
                    st.metric("Risk Score", f"{score:.2f}", "HIGH")
                elif score >= threshold * 0.5:
                    st.metric("Risk Score", f"{score:.2f}", "MEDIUM")
                else:
                    st.metric("Risk Score", f"{score:.2f}", "LOW")

            with col3:
                label = result["label"]
                if label == "PHISHING":
                    st.error("PHISHING")
                else:
                    st.success("SAFE")

            with col4:
                confidence = scored_analysis.get("confidence_level", 0.0)
                if confidence >= 0.8:
                    st.metric("Confidence", f"{confidence:.1%}")
                elif confidence >= 0.6:
                    st.metric("Confidence", f"{confidence:.1%}")
                else:
                    st.metric("Confidence", f"{confidence:.1%}", "?")

            st.markdown("---")

            # Advanced metrics row
            col1, col2, col3, col4 = st.columns([1, 1, 1, 1])

            with col1:
                prob = scored_analysis.get("phishing_probability", 0.0)
                uncertainty = scored_analysis.get("uncertainty_level", 0.0)
                st.metric("Phishing Probability", f"{prob:.1%}")

            with col2:
                st.metric("Uncertainty", f"{uncertainty:.1%}")

            with col3:
                rules = scored_analysis.get("rule_counts", {})
                active_rules = rules.get("total_rules", 0)
                st.metric("Active Rules", active_rules)

            with col4:
                high_rules = rules.get("strong_contributors", 0)
                st.metric("High-Impact Rules", high_rules)

            st.markdown("---")

            # Enhanced Analysis Technology Note
            st.info(
                """
            **Advanced Machine Learning Analysis**: This analysis includes sophisticated algorithms:
            adaptive rule weighting, probabilistic scoring, confidence assessment, and behavioral feature extraction.
            View detailed breakdown in the "Rule Analysis" section below.
            """
            )
        else:
            # Legacy analysis display
            col1, col2, col3 = st.columns([2, 1, 1])

            with col1:
                st.header("Analysis Result")

            with col2:
                score = result["score_total"]
                if score >= result.get("threshold_used", 3.2):
                    st.metric("Risk Score", f"{score:.2f}", "HIGH")
                elif score >= (result.get("threshold_used", 3.2) * 0.5):
                    st.metric("Risk Score", f"{score:.2f}", "MEDIUM")
                else:
                    st.metric("Risk Score", f"{score:.2f}", "LOW")

            with col3:
                label = result["label"]
                if label == "PHISHING":
                    st.error("PHISHING")
                else:
                    st.success("SAFE")

            st.markdown("---")

        # Enhanced Analysis Technology Note (legacy fallback)
        if "raw_context_aware_analysis" in result and "scored_analysis" not in result:
            st.info(
                """
            **Advanced Analysis Available**: This analysis includes context-aware keyword detection,
            which analyzes keyword proximity, negation patterns, and contextual relationships.
            View details in the "Advanced Keyword Analysis" section.
            """
            )
            st.markdown("---")

    # Rule-by-rule breakdown
    if "scored_analysis" in result:
        scored_analysis = result["scored_analysis"]
        render_rule_breakdown(scored_analysis)

    # Advanced explanations (for scored analysis)
    if "explanations" in result:
        render_explanations(result["explanations"])

    # Sender Identity Analysis
    if "sender_identity" in result:
        render_sender_identity_results(result["sender_identity"])

    # Reply-To vs From Mismatch Analysis
    if "replyto_from_mismatch" in result:
        render_replyto_from_mismatch_results(result["replyto_from_mismatch"])

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
        render_routing_results(result["routing_data"], result.get("routing_verdict"))

    # Attachment Findings
    if "attachment_findings" in result and result["attachment_findings"]:
        render_attachment_findings_results(result["attachment_findings"])

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

        # Confusable Findings
    if "confusable_findings" in result and result["confusable_findings"]:
        render_confusable_findings_results(result["confusable_findings"])

        # Lookalike Domain Findings
    if "lookalike_domains" in result and result["lookalike_domains"]:
        render_lookalike_findings_results(result["lookalike_domains"])

    # URL Findings
    if "url_findings" in result and result["url_findings"]:
        render_url_findings_results(result["url_findings"])

    # Whitelist Hits
    if "whitelist_hit" in result and result["whitelist_hit"]:
        render_whitelist_hit_results(result["whitelist_hit"])

    # Detailed Keyword Analysis
    if "keyword_analysis" in result:
        render_keyword_analysis_results(result["keyword_analysis"])

    # Context-Aware Keyword Analysis (Advanced)
    if "raw_context_aware_analysis" in result:
        render_context_aware_keyword_analysis(result["raw_context_aware_analysis"])

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

        # Auth Mode and DNS Stats
        if "auth_mode" in auth_data:
            st.markdown("---")
            st.markdown("**Authentication Mode**")
            auth_mode = auth_data["auth_mode"]
            if auth_mode == "header_trust":
                st.info("**Mode:** Header Trust (using email headers only)")
            elif auth_mode == "live_verify":
                st.success("**Mode:** Live Verify (real-time DNS checks)")

        if auth_data.get("dns_cache_stats"):
            st.markdown("**DNS Cache Stats**")
            dns_stats = auth_data["dns_cache_stats"]
            col1, col2 = st.columns(2)
            with col1:
                st.metric("DNS Hits", dns_stats.get("hits", 0))
            with col2:
                st.metric("DNS Misses", dns_stats.get("misses", 0))

        # Alignment Information
        if "alignment" in auth_data:
            st.markdown("---")
            st.markdown("**DMARC Alignment Summary**")

            alignment = auth_data["alignment"]
            evaluated_against = alignment.get("evaluated_against", "N/A")
            st.markdown(f"**Evaluated Against:** {evaluated_against}")

            # DKIM domains
            dkim_domains = alignment.get("dkim_d", [])
            if dkim_domains:
                st.markdown("**DKIM Domains:**")
                for domain in dkim_domains:
                    st.write(f"• {domain}")

            # SPF domain
            spf_domain = alignment.get("spf_domain")
            if spf_domain:
                st.markdown(f"**SPF Domain:** {spf_domain}")

            # From Org
            from_org = alignment.get("from_org")
            if from_org and from_org != evaluated_against:
                st.markdown(f"**From Org:** {from_org}")
            else:
                st.markdown("**From Org:** Same as evaluated against")

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


def render_routing_results(
    routing_data: Dict[str, Any], routing_verdict: Dict[str, Any] = None
):
    """
    Render the email routing information in a user-friendly format.

    Args:
        routing_data: Routing data from the analysis
        routing_verdict: Routing verdict with analysis results
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

        # Routing Verdict
        if routing_verdict:
            st.markdown("---")
            st.markdown("**Routing Sanity Analysis**")

            # Main verdict
            routing_findings = routing_verdict.get("routing_findings", "")
            if routing_findings:
                st.markdown("**Verdict:**")
                # Color code based on content
                if (
                    "Suspicious routing patterns detected" in routing_findings
                    or "mismatch detected" in routing_findings
                ):
                    st.warning(routing_findings)
                elif "no obvious routing anomalies" in routing_findings.lower():
                    st.success(routing_findings)
                else:
                    st.info(routing_findings)

            # Display key metrics in columns
            col1, col2, col3 = st.columns(3)

            with col1:
                helo_domain = routing_verdict.get("helo_domain")
                if helo_domain:
                    st.markdown("**HELO Domain:**")
                    st.code(helo_domain)
                else:
                    st.info("HELO domain not detected")

            with col2:
                received_chain_count = routing_verdict.get("received_chain_count", 0)
                st.metric("Routing Chain Length", received_chain_count)

            with col3:
                suspicious_hop = routing_verdict.get("suspicious_hop", False)
                if suspicious_hop:
                    st.error("Suspicious Hops: Detected")
                else:
                    st.success("Suspicious Hops: None")

            # HELO IP mismatch info
            helo_ip_mismatch = routing_verdict.get("helo_ip_mismatch", False)
            if helo_ip_mismatch:
                st.markdown("**HELO Mismatch:**")
                st.error("HELO hostname/IP mismatch detected")

            # Evidence
            evidence = routing_verdict.get("evidence", "")
            if evidence and evidence != "Standard routing analysis":
                st.markdown("**Analysis Evidence:**")
                # Format evidence for readability
                if "; " in evidence:
                    evidence_parts = evidence.split("; ")
                    for part in evidence_parts:
                        st.write(f"• {part}")
                else:
                    st.info(evidence)

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

            # Add routing verdict summary items
            if routing_verdict:
                if routing_verdict.get("helo_domain"):
                    summary_items.append("HELO/EHLO information extracted")
                if routing_verdict.get("helo_ip_mismatch"):
                    summary_items.append("HELO hostname/IP mismatch found")
                if routing_verdict.get("suspicious_hop"):
                    summary_items.append("Suspicious routing patterns detected")

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


def render_confusable_findings_results(confusable_findings: list):
    """
    Render the confusable character and IDN findings in a user-friendly format.

    Args:
        confusable_findings: List of confusable findings from the analysis
    """
    if not confusable_findings:
        return

    with st.expander("🔍 Confusable Character & IDN Analysis", expanded=True):
        st.markdown("**Homoglyph & IDN Domain Analysis**")
        st.markdown("Detection of similar-looking characters used for brand spoofing:")

        # Summary metrics
        total_findings = len(confusable_findings)
        skeleton_matches = sum(
            1 for f in confusable_findings if f.get("skeleton_match")
        )
        brand_matches = sum(1 for f in confusable_findings if f.get("matched_brand"))

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Findings", total_findings)
        with col2:
            st.metric("Skeleton Matches", skeleton_matches)
        with col3:
            st.metric("Brand Matches", brand_matches)

        # Individual findings
        for i, finding in enumerate(confusable_findings, 1):
            finding_type = finding.get("type", "unknown")
            domain = finding.get("domain", "N/A")
            matched_brand = finding.get("matched_brand")
            skeleton_match = finding.get("skeleton_match")
            evidence = finding.get("evidence", "")

            # Determine threat level
            threat_level = "low"
            if matched_brand and skeleton_match:
                threat_level = "high"
            elif matched_brand or skeleton_match:
                threat_level = "medium"

            # Color coding based on threat level
            if threat_level == "high":
                st.error(f"**HIGH THREAT** - {finding_type.title()} {i}")
            elif threat_level == "medium":
                st.warning(f"**MEDIUM THREAT** - {finding_type.title()} {i}")
            else:
                st.info(f"**LOW RISK** - {finding_type.title()} {i}")

            # Display finding details
            col1, col2 = st.columns([2, 1])

            with col1:
                st.markdown(f"**Domain:**")
                st.code(domain)

                if matched_brand:
                    st.markdown(f"**Imitates Brand:** {matched_brand}")
                    if skeleton_match:
                        st.warning(
                            "⚠️ **Skeleton Match Detected** - Characters visually similar"
                        )
                    else:
                        st.info("📝 Brand detected but no skeleton match")

                # Classification by type
                if finding_type == "sender_from":
                    st.markdown("**Classification:** Sender From Address Domain")
                elif finding_type == "sender_reply_to":
                    st.markdown("**Classification:** Sender Reply-To Domain")
                elif finding_type == "sender_return_path":
                    st.markdown("**Classification:** Sender Return-Path Domain")
                else:
                    st.markdown(f"**Classification:** {finding_type}")

            with col2:
                st.markdown("**Technical Details:**")
                if finding.get("unicode_replacements"):
                    unicode_chars = finding["unicode_replacements"]
                    st.write(f"Unicode Chars: {len(unicode_chars)}")
                    if len(unicode_chars) <= 5:
                        st.code("".join(unicode_chars))
                    else:
                        st.code("".join(unicode_chars[:5]) + "...")

                if skeleton_match:
                    st.write("🦴 Skeleton: Yes")

                # Brand similarity score if available
                if finding.get("brand_similarity_score"):
                    score = finding["brand_similarity_score"]
                    if score > 0.8:
                        st.error(f"Similarity: {score:.2f}")
                    elif score > 0.6:
                        st.warning(f"Similarity: {score:.2f}")
                    else:
                        st.info(f"Similarity: {score:.2f}")

            # Evidence/Details
            if evidence:
                st.markdown("**Evidence:**")
                # Format evidence for better readability
                if "; " in evidence:
                    evidence_parts = evidence.split("; ")
                    for part in evidence_parts:
                        st.write(f"• {part}")
                else:
                    st.info(evidence)

            # Separator between findings
            if i < len(confusable_findings):
                st.markdown("---")

        # Overall summary
        st.markdown("---")
        st.markdown("**Confusable Analysis Summary**")

        summary_items = []

        if total_findings > 0:
            summary_items.append(f"{total_findings} domain(s) analyzed for confusables")
        else:
            summary_items.append("No domains analyzed")

        if skeleton_matches > 0:
            summary_items.append(
                f"{skeleton_matches} skeleton match(es) found - possible homoglyph attacks"
            )

        if brand_matches > 0:
            summary_items.append(
                f"{brand_matches} brand match(es) detected - potential spoofing attempts"
            )

        if any(f.get("matched_brand") for f in confusable_findings):
            unique_brands = set(
                f.get("matched_brand")
                for f in confusable_findings
                if f.get("matched_brand")
            )
            brand_list = ", ".join(sorted(unique_brands))
            summary_items.append(f"Brands targeted: {brand_list}")

        if any(f.get("unicode_replacements") for f in confusable_findings):
            total_unicode = sum(
                len(f.get("unicode_replacements", [])) for f in confusable_findings
            )
            summary_items.append(f"{total_unicode} Unicode characters detected")

        threat_findings = [
            f
            for f in confusable_findings
            if f.get("matched_brand") and f.get("skeleton_match")
        ]
        if threat_findings:
            summary_items.append(
                "⚠️ **HIGH RISK:** Skeleton + brand matches indicate sophisticated spoofing attempts"
            )

        for item in summary_items:
            st.write(f"• {item}")


def render_lookalike_findings_results(lookalike_findings: list):
    """
    Render the edit-distance lookalike findings in a user-friendly format.

    Args:
        lookalike_findings: List of lookalike findings from the analysis
    """
    if not lookalike_findings:
        return

    with st.expander("🔍 Edit-Distance Lookalike Analysis", expanded=True):
        st.markdown("**Typosquatting & Edit-Distance Domain Analysis**")
        st.markdown(
            "Detection of domains similar to known brands using edit distance algorithms:"
        )

        # Summary metrics
        total_findings = len(lookalike_findings)
        high_cutoff = sum(1 for f in lookalike_findings if f.get("distance") == 1)
        within_cutoff = sum(1 for f in lookalike_findings if f.get("within_cutoff"))

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Findings", total_findings)
        with col2:
            st.metric("Distance = 1", high_cutoff)
        with col3:
            st.metric("Within Cutoff (≤2)", within_cutoff)

        # Individual findings
        for i, finding in enumerate(lookalike_findings, 1):
            suspect_domain = finding.get("suspect_domain", "N/A")
            target_domain = finding.get("target_domain", "N/A")
            distance = finding.get("distance", 0)
            within_cutoff = finding.get("within_cutoff", False)
            evidence = finding.get("evidence", "")

            # Determine threat level
            threat_level = (
                "high" if distance == 1 else "medium" if within_cutoff else "low"
            )

            # Color coding based on threat level
            if threat_level == "high":
                st.error(f"**HIGH THREAT** - Single Character Difference {i}")
            elif threat_level == "medium":
                st.warning(f"**MEDIUM THREAT** - Similar Domain {i}")
            else:
                st.info(f"**LOW RISK** - Distant Match {i}")

            # Display finding details
            col1, col2 = st.columns([3, 1])

            with col1:
                st.markdown("**Suspect Domain:**")
                st.code(suspect_domain)

                st.markdown("**Target Domain:**")
                st.code(target_domain)

                st.markdown("**Edit Distance:**")
                if distance == 1:
                    st.error(f"**{distance}** (Single character difference)")
                elif within_cutoff:
                    st.warning(f"**{distance}** (Within cutoff threshold)")
                else:
                    st.info(f"**{distance}** (Above threshold)")

                # Brand information
                if "Imitates brand:" in evidence:
                    brand_matches = [
                        part
                        for part in evidence.split("; ")
                        if "Imitates brand:" in part
                    ]
                    if brand_matches:
                        brand = brand_matches[0].replace("Imitates brand: ", "")
                        st.markdown(f"**Brand Target:** {brand}")

            with col2:
                st.markdown("**Technical Details:**")

                # Pattern detection
                if "Single character difference" in evidence:
                    st.write("Single Char Diff")

                if "Possible character swap" in evidence:
                    st.write("Char Swap")

                if "Possible missing character" in evidence:
                    st.write("Missing Char")

                if "Possible extra character" in evidence:
                    st.write("Extra Char")

                if "Possible character substitution" in evidence:
                    st.write("Substitution")

                # Similarity score if available
                if not within_cutoff:
                    st.metric("Distance", distance)

            # Evidence
            if evidence:
                st.markdown("**Analysis Evidence:**")
                # Format evidence for better readability
                if "; " in evidence:
                    evidence_parts = evidence.split("; ")
                    for part in evidence_parts:
                        if not part.startswith("Target:") and not part.startswith(
                            "Imitates brand:"
                        ):
                            st.write(f"• {part}")
                else:
                    st.info(evidence)

            # Separator between findings
            if i < len(lookalike_findings):
                st.markdown("---")

        # Overall summary
        st.markdown("---")
        st.markdown("**Lookalike Analysis Summary**")

        summary_items = []

        if total_findings > 0:
            summary_items.append(
                f"{total_findings} suspicious domain(s) analyzed for typosquatting"
            )
        else:
            summary_items.append("No suspicious domains analyzed")

        if high_cutoff > 0:
            summary_items.append(
                f"{high_cutoff} single-character difference(s) found - high threat potential"
            )

        if within_cutoff > 0:
            summary_items.append(
                f"{within_cutoff} domain(s) within cutoff threshold - potential spoofing attempts"
            )

        # Extract unique brands targeted
        brands_targeted = set()
        for finding in lookalike_findings:
            evidence = finding.get("evidence", "")
            if "Imitates brand:" in evidence:
                brand_matches = [
                    part for part in evidence.split("; ") if "Imitates brand:" in part
                ]
                if brand_matches:
                    brand = brand_matches[0].replace("Imitates brand: ", "")
                    brands_targeted.add(brand)

        if brands_targeted:
            brand_list = ", ".join(sorted(brands_targeted))
            summary_items.append(f"Brands targeted: {brand_list}")

        # Check for high-risk patterns
        high_risk_findings = [
            f
            for f in lookalike_findings
            if f.get("distance") == 1 and "Imitates brand:" in f.get("evidence", "")
        ]
        if high_risk_findings:
            summary_items.append(
                "**CRITICAL RISK:** Single-character brand impersonation detected"
            )

        for item in summary_items:
            st.write(f"• {item}")

        # Technical notes
        with st.expander("ℹTechnical Details", expanded=False):
            st.markdown(
                """
            **Edit Distance Algorithm:**
            - **Distance 1**: Single character addition, deletion, or substitution
            - **Cutoff Threshold**: ≤2 character changes considered suspicious
            - **Levenshtein Distance**: Minimum operations to transform one string to another
            - **Typosquatting Detection**: Common phishing technique using similar domains
            """
            )


def render_keyword_analysis_results(keyword_analysis: Dict[str, Any]):
    """
    Render the detailed keyword analysis results in a user-friendly format.

    Args:
        keyword_analysis: Keyword analysis data from the backend
    """
    if not keyword_analysis:
        return

    with st.expander("Advanced Keyword Analysis (Position-Aware)", expanded=True):
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
                    width="stretch",
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


def render_attachment_findings_results(attachment_findings: list):
    """
    Render the attachment findings in a user-friendly format.

    Args:
        attachment_findings: List of attachment findings from the analysis
    """
    if not attachment_findings:
        return

    with st.expander("📎 Attachment Analysis & Security Findings", expanded=True):
        st.markdown("**Email Attachment Analysis**")
        st.markdown("Security analysis of files attached to the email:")

        # Summary metrics
        total_attachments = len(attachment_findings)
        dangerous_types = sum(
            1 for f in attachment_findings if f.get("is_dangerous_type")
        )
        macro_enabled = sum(1 for f in attachment_findings if f.get("is_macro_enabled"))
        archives_with_dangerous = sum(
            1 for f in attachment_findings if f.get("archive_contains_dangerous")
        )
        double_extensions = sum(1 for f in attachment_findings if f.get("double_ext"))
        mime_mismatches = sum(
            1
            for f in attachment_findings
            if f.get("sniffed_mime") and f["sniffed_mime"] != f.get("declared_mime")
        )

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Attachments", total_attachments)
        with col2:
            st.metric(
                "Potentially Dangerous",
                dangerous_types + macro_enabled + archives_with_dangerous,
            )
        with col3:
            st.metric("Suspicious Patterns", double_extensions + mime_mismatches)

        # Individual attachment findings
        for i, finding in enumerate(attachment_findings, 1):
            filename = finding.get("filename", "N/A")
            ext_primary = finding.get("ext_primary", "")
            declared_mime = finding.get("declared_mime", "")
            sniffed_mime = finding.get("sniffed_mime")
            is_macro_enabled = finding.get("is_macro_enabled", False)
            is_dangerous_type = finding.get("is_dangerous_type", False)
            is_archive = finding.get("is_archive", False)
            archive_contains_dangerous = finding.get("archive_contains_dangerous")
            double_ext = finding.get("double_ext", False)
            evidence = finding.get("evidence", "")

            # Determine threat level
            threat_level = "low"
            high_risk_indicators = 0

            if is_dangerous_type:
                high_risk_indicators += 1
            if double_ext:
                high_risk_indicators += 1
            if archive_contains_dangerous:
                high_risk_indicators += 1
            if sniffed_mime and sniffed_mime != declared_mime:
                high_risk_indicators += 1

            if high_risk_indicators >= 2 or (is_dangerous_type and double_ext):
                threat_level = "high"
            elif (
                high_risk_indicators >= 1
                or is_macro_enabled
                or archive_contains_dangerous
            ):
                threat_level = "medium"

            # Color coding based on threat level
            if threat_level == "high":
                st.error(f"**HIGH RISK** - Attachment {i}")
            elif threat_level == "medium":
                st.warning(f"**MEDIUM RISK** - Attachment {i}")
            else:
                st.success(f"**LOW RISK** - Attachment {i}")

            # Display attachment details
            col1, col2 = st.columns([1, 1])

            with col1:
                st.markdown("**Filename:**")
                st.code(filename)

                st.markdown("**Primary Extension:**")
                if ext_primary:
                    st.code(ext_primary)
                else:
                    st.info("No extension")

                st.markdown("**Declared MIME Type:**")
                st.code(declared_mime)

                if sniffed_mime:
                    st.markdown("**Sniffed MIME Type:**")
                    if sniffed_mime == declared_mime:
                        st.success(sniffed_mime)
                    else:
                        st.error(sniffed_mime + " (MISMATCH)")

            with col2:
                st.markdown("**Security Analysis:**")

                # Security flags
                security_flags = []

                if is_macro_enabled:
                    security_flags.append(
                        "**Macros Detected** - Potential VBA/Office macro content"
                    )

                if is_dangerous_type:
                    security_flags.append(
                        f"**Dangerous Type** - {ext_primary} files should not be sent via email"
                    )

                if double_ext:
                    security_flags.append(
                        "**Double Extension** - Filename has multiple extensions (possible obfuscation)"
                    )

                if is_archive:
                    security_flags.append("**Archive File** - Contains multiple files")
                    if archive_contains_dangerous is True:
                        security_flags.append(
                            "**DANGEROUS CONTENT** - Archive contains executable or malicious files"
                        )
                    elif archive_contains_dangerous is False:
                        security_flags.append(
                            "**Archive Safe** - No dangerous files detected"
                        )
                    else:
                        security_flags.append(
                            "**Archive Not Scanned** - Content inspection unavailable"
                        )

                if not security_flags:
                    security_flags.append("**Clean** - No obvious security concerns")

                for flag in security_flags:
                    st.write(flag)

            # Evidence
            if evidence and evidence != "No suspicious patterns detected":
                st.markdown("**Analysis Evidence:**")
                # Format evidence for better readability
                if "; " in evidence:
                    evidence_parts = evidence.split("; ")
                    for part in evidence_parts:
                        st.write(f"• {part}")
                else:
                    st.info(evidence)

            # Separator between attachments
            if i < len(attachment_findings):
                st.markdown("---")

        # Overall summary
        st.markdown("---")
        st.markdown("**Attachment Analysis Summary**")

        summary_items = []

        if total_attachments > 0:
            summary_items.append(f"{total_attachments} attachment(s) analyzed")
        else:
            summary_items.append("No attachments found")

        # Security summary
        security_concerns = []
        if dangerous_types > 0:
            security_concerns.append(f"{dangerous_types} dangerous file type(s)")
        if macro_enabled > 0:
            security_concerns.append(f"{macro_enabled} macro-enabled file(s)")
        if archives_with_dangerous > 0:
            security_concerns.append(
                f"{archives_with_dangerous} archive(s) with dangerous content"
            )
        if double_extensions > 0:
            security_concerns.append(f"{double_extensions} double extension file(s)")
        if mime_mismatches > 0:
            security_concerns.append(f"{mime_mismatches} MIME type mismatch(es)")

        if security_concerns:
            summary_items.append(
                "**SECURITY CONCERNS:** " + ", ".join(security_concerns)
            )
        else:
            summary_items.append("**No security concerns detected**")

        # Archive inspection status
        archives_inspected = sum(1 for f in attachment_findings if f.get("is_archive"))
        archives_not_inspected = sum(
            1
            for f in attachment_findings
            if f.get("is_archive") and f.get("archive_contains_dangerous") is None
        )

        if archives_inspected > 0:
            if archives_not_inspected > 0:
                summary_items.append(
                    f"{archives_inspected - archives_not_inspected}/{archives_inspected} archives successfully inspected"
                )
            else:
                summary_items.append(
                    f"{archives_inspected} archives successfully inspected"
                )

        for item in summary_items:
            st.write(item)


def render_whitelist_hit_results(whitelist_hits: list):
    """
    Render the whitelist hit results in a user-friendly format.

    Args:
        whitelist_hits: List of whitelist hit findings from the analysis
    """
    if not whitelist_hits:
        return

    with st.expander("Whitelist Analysis", expanded=True):
        st.markdown("**Whitelist Hit Analysis**")
        st.markdown(
            "Domains found in the email that match configured whitelisted domains:"
        )

        # Summary metrics
        total_hits = len(whitelist_hits)
        exact_hits = sum(1 for hit in whitelist_hits if hit.get("scope") == "exact")
        apex_hits = sum(1 for hit in whitelist_hits if hit.get("scope") == "apex")
        subdomain_hits = sum(
            1 for hit in whitelist_hits if hit.get("scope") == "subdomain"
        )

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Hits", total_hits)
        with col2:
            st.metric("Exact Matches", exact_hits)
        with col3:
            st.metric("Apex Hits", apex_hits)
        with col4:
            st.metric("Subdomain Hits", subdomain_hits)

        # Individual whitelist hits
        for i, hit in enumerate(whitelist_hits, 1):
            matched_domain = hit.get("matched_domain", "N/A")
            scope = hit.get("scope", "N/A")
            reason = hit.get("reason", "N/A")

            # Color coding based on scope
            if scope == "exact":
                st.success(f"**EXACT MATCH** - Whitelist Hit {i}")
            elif scope == "apex":
                st.info(f"**APEX HIT** - Whitelist Hit {i}")
            elif scope == "subdomain":
                st.warning(f"**SUBDOMAIN HIT** - Whitelist Hit {i}")
            else:
                st.error(f"**UNKNOWN SCOPE** - Whitelist Hit {i}")

            # Display whitelist hit details
            col1, col2 = st.columns([2, 1])

            with col1:
                st.markdown("**Matched Domain:**")
                st.code(matched_domain)

                st.markdown("**Reason:**")
                st.code(reason)

                # Scope description
                if scope == "exact":
                    st.markdown("**Match Type:** Exact domain match")
                elif scope == "apex":
                    st.markdown(
                        "**Match Type:** Apex domain coverage (includes subdomains)"
                    )
                elif scope == "subdomain":
                    st.markdown("**Match Type:** Subdomain of whitelisted domain")
                else:
                    st.markdown(f"**Match Type:** {scope}")

            with col2:
                st.markdown("**Scope:**")
                if scope == "exact":
                    st.success("Exact")
                elif scope == "apex":
                    st.info("Apex")
                elif scope == "subdomain":
                    st.warning("Subdomain")
                else:
                    st.error("Unknown")

                # Security implication
                st.markdown("**Implication:**")
                if scope == "exact":
                    st.info("Trusted Domain")
                elif scope == "apex":
                    st.info("Trusted Organization")
                elif scope == "subdomain":
                    st.warning("Trusted Subdomain")
                else:
                    st.error("Unknown Trust Level")

            # Separator between hits
            if i < len(whitelist_hits):
                st.markdown("---")

        # Overall summary
        st.markdown("---")
        st.markdown("**Whitelist Analysis Summary**")

        summary_items = []

        if total_hits > 0:
            summary_items.append(f"{total_hits} whitelisted domain hit(s) detected")
        else:
            summary_items.append("No whitelisted domains detected")

        if exact_hits > 0:
            summary_items.append(f"{exact_hits} exact whitelist matches")
        if apex_hits > 0:
            summary_items.append(
                f"{apex_hits} apex domain matches (subdomains trusted)"
            )
        if subdomain_hits > 0:
            summary_items.append(f"{subdomain_hits} subdomain matches")

        # Extract unique reasons
        reasons = set(
            hit.get("reason", "N/A")
            for hit in whitelist_hits
            if hit.get("reason") != "N/A"
        )
        if reasons:
            reason_list = ", ".join(sorted(reasons))
            summary_items.append(f"Whitelist sources: {reason_list}")

        for item in summary_items:
            st.write(f"• {item}")

        # Technical notes
        with st.expander("ℹTechnical Details", expanded=False):
            st.markdown(
                """
            **Whitelist Scope Definitions:**
            - **Exact**: Exact domain match only
            - **Apex**: Root domain allows all subdomains
            - **Subdomain**: Specific subdomain allowed
            - **Reason**: Source or category of the whitelist entry
            """
            )


def render_context_aware_keyword_analysis(context_analysis: Dict[str, Any]):
    """
    Render the context-aware keyword analysis results in a user-friendly format.

    Args:
        context_analysis: Context-aware keyword analysis data from the backend
    """
    if not context_analysis:
        return

    with st.expander("Context-Aware Keyword Analysis", expanded=True):
        st.markdown("**Advanced Context-Aware Phishing Detection**")
        st.markdown(
            "Intelligent keyword analysis with negation detection and contextual relationships:"
        )

        # Overall metrics
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            total_hits = len(context_analysis.get("keyword_hits", []))
            st.metric("Total Keyword Hits", total_hits)

        with col2:
            total_score = context_analysis.get("total_score", 0.0)
            # Determine risk level based on context scoring
            if total_score >= 15.0:
                st.metric("Context Score", f"{total_score:.1f}", "Very High")
            elif total_score >= 10.0:
                st.metric("Context Score", f"{total_score:.1f}", "High")
            elif total_score >= 5.0:
                st.metric("Context Score", f"{total_score:.1f}", "Medium")
            else:
                st.metric("Context Score", f"{total_score:.1f}", "Low")

        with col3:
            negated_count = sum(
                1
                for hit in context_analysis.get("keyword_hits", [])
                if hit.get("weight", 0)
                < keyword_config.keywords.get(hit.get("term"), {}).get("weight", 1.0)
            )
            st.metric("Negated Keywords", negated_count)

        with col4:
            boosted_count = sum(
                1
                for hit in context_analysis.get("keyword_hits", [])
                if hit.get("weight", 0)
                > keyword_config.keywords.get(hit.get("term"))["weight"] * 1.5
            )
            st.metric("Context Boosted", boosted_count)

        # Keyword hits analysis
        keyword_hits = context_analysis.get("keyword_hits", [])
        if keyword_hits:
            st.markdown("---")
            st.markdown("**Detailed Context Analysis**")
            st.markdown("Keywords analyzed with negation and context awareness:")

            # Show first 10 most significant hits
            for i, hit in enumerate(keyword_hits[:10], 1):
                term = hit.get("term", "")
                base_weight = keyword_config.keywords.get(term, {}).get("weight", 1.0)
                actual_weight = hit.get("weight", 0.0)
                where = hit.get("where", "")
                pos = hit.get("pos", 0)
                window = hit.get("window", "")

                # Determine analysis type
                analysis_type = ""
                if actual_weight < base_weight * 0.5:
                    analysis_type = "**NEGATED** - Reduced weight due to negation"
                    st.error(
                        f"**{i}.** `{term}` - {where} pos {pos} (weight: {actual_weight:.2f} ↓)"
                    )
                elif actual_weight > base_weight * 1.5:
                    analysis_type = (
                        "**CONTEXT BOOSTED** - Increased weight due to context"
                    )
                    st.warning(
                        f"**{i}.** `{term}` - {where} pos {pos} (weight: {actual_weight:.2f} ↑)"
                    )
                else:
                    analysis_type = "**STANDARD** - Normal detection"
                    st.info(
                        f"**{i}.** `{term}` - {where} pos {pos} (weight: {actual_weight:.2f} =)"
                    )

                # Show context analysis
                if analysis_type:
                    st.write(f"   {analysis_type}")
                if window:
                    st.write(f"   Window: `{window}`")

                if i < len(keyword_hits[:10]):
                    st.write("")

            if len(keyword_hits) > 10:
                st.write(f"*... and {len(keyword_hits) - 10} more keyword detections*")

        # Term Statistics with context insights
        term_stats = context_analysis.get("term_stats", {})

        if term_stats:
            st.markdown("---")
            st.markdown("**Context-Aware Term Statistics**")

            # Sort by effectiveness (consider both base weight and context effects)
            terms_with_insights = []
            for term, stats in term_stats.items():
                count = stats.get("count", 0)
                total_score = stats.get("total_score", 0)
                base_weight = keyword_config.keywords.get(term, {}).get("weight", 1.0)
                avg_weight = total_score / count if count > 0 else 0

                # Calculate context effectiveness
                context_effective = "neutral"
                if avg_weight < base_weight * 0.8:
                    context_effective = "negated"
                elif avg_weight > base_weight * 1.2:
                    context_effective = "boosted"

                terms_with_insights.append(
                    {
                        "term": term,
                        "count": count,
                        "total_score": total_score,
                        "avg_weight": avg_weight,
                        "base_weight": base_weight,
                        "context_effective": context_effective,
                    }
                )

            # Sort by total score
            terms_with_insights.sort(key=lambda x: x["total_score"], reverse=True)

            import pandas as pd

            table_data = []
            for item in terms_with_insights[:8]:
                table_data.append(
                    {
                        "Keyword": item["term"],
                        "Occurrences": item["count"],
                        "Total Score": round(item["total_score"], 2),
                        "Avg Weight": f"{item['avg_weight']:.2f}",
                        "Base Weight": f"{item['base_weight']:.2f}",
                        "Context Effect": (
                            "NEGATED"
                            if item["context_effective"] == "negated"
                            else (
                                "BOOSTED"
                                if item["context_effective"] == "boosted"
                                else "Normal"
                            )
                        ),
                    }
                )

            if table_data:
                df = pd.DataFrame(table_data)
                st.dataframe(
                    df,
                    width="stretch",
                    column_config={
                        "Keyword": st.column_config.TextColumn(
                            "Keyword", width="medium"
                        ),
                        "Occurrences": st.column_config.NumberColumn(
                            "Hits", width="small"
                        ),
                        "Total Score": st.column_config.NumberColumn(
                            "Score", width="small"
                        ),
                        "Avg Weight": st.column_config.TextColumn(
                            "Avg Weight", width="small"
                        ),
                        "Base Weight": st.column_config.TextColumn(
                            "Base Weight", width="small"
                        ),
                        "Context Effect": st.column_config.TextColumn(
                            "Context", width="medium"
                        ),
                    },
                    hide_index=True,
                )

                if len(table_data) > 8:
                    st.write(f"*... and {len(terms_with_insights) - 8} more terms*")

        # Context analysis summary
        st.markdown("---")
        st.markdown("**Context Analysis Summary**")

        summary_items = []

        if negated_count > 0:
            summary_items.append(
                f"{negated_count} keywords affected by negation detection"
            )
        if boosted_count > 0:
            summary_items.append(
                f"{boosted_count} keywords boosted by contextual relationships"
            )

        # Risk assessment based on context findings
        high_risk_negations = sum(
            1
            for hit in keyword_hits
            if hit.get("weight", 0)
            < keyword_config.keywords.get(hit.get("term"), {}).get("weight", 1.0) * 0.5
        )
        if high_risk_negations > 0:
            summary_items.append(
                f"**HIGH ATTENTION**: {high_risk_negations} heavily negated suspicious keywords"
            )

        low_effective_keywords = sum(
            1 for hit in keyword_hits if hit.get("weight", 0) < 0.5
        )
        if low_effective_keywords > 0:
            summary_items.append(
                f"{low_effective_keywords} keywords effectively eliminated by negation"
            )

        context_elevated_risk = sum(
            1
            for hit in keyword_hits
            if hit.get("weight", 0)
            > keyword_config.keywords.get(hit.get("term"), {}).get("weight", 1.0) * 2.0
        )
        if context_elevated_risk > 0:
            summary_items.append(
                f"{context_elevated_risk} keywords significantly boosted by context"
            )

        if not summary_items:
            summary_items.append(
                "Standard keyword analysis with no significant context effects"
            )

        for item in summary_items:
            st.write(f"• {item}")

        # Technical notes
        with st.expander("📈 Context Analysis Details", expanded=False):
            st.markdown(
                """
            **Context-Aware Detection:**
            - **Negation Detection**: Keywords preceded by negation words (not, isn't, etc.) get 0.2x weight
            - **Context Boosting**: Keywords near related terms (e.g., verify + account) get 1.5x weight
            - **Window Analysis**: Context examined within 100-character proximity around keywords
            - **Position Multipliers**: Subject keywords (3x), early body (2x), regular body (1x)
            - **Combined Effects**: Both position and context multipliers applied simultaneously
            """
            )


def render_rule_breakdown(scored_analysis: Dict[str, Any]):
    """
    Render the comprehensive rule-based scoring breakdown.

    Args:
        scored_analysis: The scored analysis from the backend containing rule breakdown
    """
    if not scored_analysis:
        return

    with st.expander("Rule-by-Rule Scoring Breakdown", expanded=True):
        st.markdown("**Detailed Rule Analysis**")
        st.markdown(
            "Each security rule contributes to the overall phishing risk score:"
        )

        # Get rule breakdown
        score_breakdown = scored_analysis.get("score_breakdown", [])
        tuning_profile = scored_analysis.get("tuning_profile", "default")
        threshold_used = scored_analysis.get("threshold_used", 3.2)

        # Summary metrics
        total_rules = len(score_breakdown)
        triggered_rules = sum(
            1 for rule in score_breakdown if rule.get("delta", 0) != 0
        )
        positive_contributions = sum(
            rule.get("delta", 0) for rule in score_breakdown if rule.get("delta", 0) > 0
        )
        negative_contributions = sum(
            rule.get("delta", 0) for rule in score_breakdown if rule.get("delta", 0) < 0
        )

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Rules Evaluated", total_rules)
        with col2:
            high_contrib = sum(
                1 for rule in score_breakdown if abs(rule.get("delta", 0)) >= 1.0
            )
            st.metric("High Impact Rules", high_contrib)
        with col3:
            st.metric("Profile Used", tuning_profile.upper())
        with col4:
            st.metric("Threshold Used", f"{threshold_used:.1f}")

        # Rule breakdown table
        if score_breakdown:
            st.markdown("---")
            st.markdown("**Individual Rule Contributions**")

            import pandas as pd

            table_data = []
            for i, rule in enumerate(score_breakdown, 1):
                delta = rule.get("delta", 0)
                rule_name = rule.get("rule", "unknown")
                evidence = rule.get("evidence", "")

                # Truncate evidence for display
                if len(evidence) > 100:
                    evidence_preview = evidence[:100] + "..."
                else:
                    evidence_preview = evidence

                table_data.append(
                    {
                        "#": i,
                        "Rule": rule_name.replace("_", " ").title(),
                        "Score Delta": f"{delta:+.2f}",
                        "Risk Level": (
                            "High"
                            if abs(delta) >= 1.5
                            else "Medium" if abs(delta) >= 0.5 else "Low"
                        ),
                        "Evidence": evidence_preview,
                    }
                )

            df = pd.DataFrame(table_data)
            st.dataframe(
                df,
                width="stretch",
                column_config={
                    "#": st.column_config.NumberColumn("#", width="small"),
                    "Rule": st.column_config.TextColumn("Rule", width="large"),
                    "Score Delta": st.column_config.TextColumn(
                        "Score Delta", width="medium"
                    ),
                    "Risk Level": st.column_config.TextColumn(
                        "Risk Level", width="medium"
                    ),
                    "Evidence": st.column_config.TextColumn("Evidence", width="large"),
                },
                hide_index=True,
            )

            # Top risk factors
            high_impact_rules = [
                rule for rule in score_breakdown if abs(rule.get("delta", 0)) >= 1.0
            ]

            if high_impact_rules:
                st.markdown("---")
                st.markdown("**Top Risk Factors**")

                for i, rule in enumerate(
                    sorted(
                        high_impact_rules,
                        key=lambda x: abs(x.get("delta", 0)),
                        reverse=True,
                    )[:5],
                    1,
                ):
                    rule_name = rule.get("rule", "").replace("_", " ").title()
                    delta = rule.get("delta", 0)
                    evidence = rule.get("evidence", "")

                    if delta >= 1.0:
                        st.error(f"**{i}. {rule_name}:** +{delta:.2f} points")
                        if evidence:
                            st.write(f"   _{evidence}_")
                    else:
                        st.warning(f"**{i}. {rule_name}:** {delta:+.2f} points")
                        if evidence:
                            st.write(f"   _{evidence}_")

                    if i < len(high_impact_rules) and i < 5:
                        st.write("")

            # Contribution analysis
            if triggered_rules > 0:
                st.markdown("---")
                st.markdown("**Scoring Contribution Analysis**")

                col1, col2 = st.columns(2)

                with col1:
                    st.markdown("**Positive Contributions:**")
                    positive_rules = [
                        r for r in score_breakdown if r.get("delta", 0) > 0
                    ]
                    for rule in sorted(
                        positive_rules, key=lambda x: x.get("delta", 0), reverse=True
                    )[:3]:
                        rule_name = rule["rule"].replace("_", " ").title()
                        delta = rule["delta"]
                        st.write(f"• {rule_name}: **+{delta:.2f}**")

                    if len(positive_rules) > 3:
                        st.write(f"*... and {len(positive_rules) - 3} more*")

                with col2:
                    st.markdown("**Most Infrequent Triggers:**")
                    unique_evidence = set(
                        rule.get("evidence", "") for rule in score_breakdown
                    )
                    st.metric("Unique Evidence Types", len(unique_evidence))

                    # Show rules with evidence that aren't frequently used
                    evidence_counts = {}
                    for rule in score_breakdown:
                        evidence = rule.get("evidence", "")
                        if evidence:
                            evidence_counts[evidence] = (
                                evidence_counts.get(evidence, 0) + 1
                            )

                    rare_evidence = [
                        e for e, count in evidence_counts.items() if count == 1
                    ][:3]
                    for ev in rare_evidence:
                        st.write(f"• _{ev[:50]}{'...' if len(ev) > 50 else ''}_")

        else:
            st.info("No security rules were evaluated or triggered.")

        # Scoring configuration
        with st.expander("🔧 Scoring Configuration", expanded=False):
            st.markdown(
                f"""
            **Current Scoring Setup:**
            - **Profile:** `{tuning_profile}`
            - **Threshold:** `{threshold_used}` (above = PHISHING, below = SAFE)
            - **Total Rules:** `{total_rules}`
            - **Rule Types Evaluated:** URL analysis, sender identity, content patterns, keyword frenzy, brand spoofing
            """
            )


def render_replyto_from_mismatch_results(replyto_mismatch: Dict[str, Any]):
    """
    Render the Reply-To vs From mismatch analysis results in a user-friendly format.

    Args:
        replyto_mismatch: Reply-To mismatch analysis data from the backend
    """
    if not replyto_mismatch:
        return

    with st.expander("Reply-To vs From Analysis", expanded=True):
        st.markdown("**Reply-To vs From Header Mismatch Detection**")
        st.markdown(
            "Advanced analysis of sender header consistency and spoofing indicators:"
        )

        # Basic analysis results
        has_mismatch = replyto_mismatch.get("has_mismatch", False)
        severity = replyto_mismatch.get("severity", 0.0)
        reasons = replyto_mismatch.get("reasons", [])
        from_address = replyto_mismatch.get("from_address")
        reply_to_address = replyto_mismatch.get("reply_to_address")

        # Summary metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            if has_mismatch:
                st.metric("Mismatch Detected", "YES", "ALERT")
            else:
                st.metric("Mismatch Detected", "NO", "SAFE")
        with col2:
            st.metric("Severity Score", f"{severity:.1f}")
        with col3:
            st.metric("Reasons Found", len(reasons))

        # Threat level assessment
        if has_mismatch:
            st.markdown("---")
            st.markdown("**Mismatch Details**")

            if severity >= 2.5:
                st.error("**HIGH RISK:** Significant spoofing indicators detected")
            elif severity >= 2.0:
                st.warning("**MEDIUM RISK:** Suspicious domain changes")
            elif severity >= 1.0:
                st.warning("**LOW RISK:** Minor address differences")
            else:
                st.info("**VERY LOW RISK:** Likely legitimate differences")

            # Address comparison
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**From Address:**")
                if from_address:
                    st.code(from_address)
                else:
                    st.info("N/A")

            with col2:
                st.markdown("**Reply-To Address:**")
                if reply_to_address:
                    st.code(reply_to_address)
                else:
                    st.info("N/A")

            # Reasons for mismatch
            if reasons:
                st.markdown("**Analysis Reasons:**")
                for reason in reasons:
                    if "Potential username spoofing" in reason:
                        st.error(f"• {reason}")
                    elif "Suspicious domain mismatch" in reason:
                        st.error(f"• {reason}")
                    elif "Domain mismatch" in reason:
                        st.warning(f"• {reason}")
                    else:
                        st.info(f"• {reason}")

            # Security implications
            st.markdown("---")
            st.markdown("**Security Implications**")

            if "Potential username spoofing" in str(reasons):
                st.error(
                    "**CRITICAL:** Same username but different domain - classic spoofing pattern"
                )
            elif "Suspicious domain mismatch" in str(reasons):
                st.warning(
                    "**ALERT:** Domains look similar but differ - possible typosquatting"
                )
            elif has_mismatch:
                st.info(
                    "**Note:** Address differences may be legitimate if reply-to is handled by a different service"
                )

        else:
            st.markdown("---")
            st.markdown("**Analysis Result**")
            st.success("**No Reply-To vs From mismatches detected**")
            st.markdown("Sender addresses appear consistent and legitimate.")

        # Technical details
        with st.expander("Technical Analysis Details", expanded=False):
            st.markdown("**Detection Methods Applied**")

            detection_methods = [
                "Address-level comparison (exact string match)",
                "Domain extraction and comparison",
                "Same username, different domain detection (spoofing indicator)",
                "Domain similarity analysis (typosquatting detection)",
                "Organizational domain comparison",
            ]

            for method in detection_methods:
                st.write(f"• {method}")

            st.markdown("---")
            st.markdown("**Severity Scoring Scale**")
            severity_info = [
                "0.0 - No mismatch detected",
                "1.0 - Address mismatch (same domain)",
                "2.0 - Domain mismatch (different organization)",
                "2.5+ - Same username, different domain (spoofing indicator)",
            ]

            for info in severity_info:
                st.write(f"• {info}")


def render_explanations(explanations: Dict[str, Any]):
    """
    Render the detailed explanations from the advanced scoring system.

    Args:
        explanations: Explanations dictionary from the backend analysis
    """
    if not explanations:
        return

    with st.expander("💡 Detailed Analysis Explanations", expanded=True):
        st.markdown("**Comprehensive Scoring Explanation**")
        st.markdown(
            "Detailed analysis explaining the risk assessment and decision making:"
        )

        # Main summary
        if explanations.get("summary"):
            summary = explanations["summary"]
            # Color coding based on summary content
            if "High risk" in summary or "HIGH RISK" in summary:
                st.error("**SUMMARY:** " + summary)
            elif "Medium risk" in summary or "MODERATE" in summary:
                st.warning("**SUMMARY:** " + summary)
            else:
                st.success("**SUMMARY:** " + summary)

        st.markdown("---")

        # Categorization breakdown
        if explanations.get("categories"):
            st.markdown("**Analysis by Category**")

            categories = explanations["categories"]
            for cat_name, cat_info in categories.items():
                rules_triggered = cat_info.get("rules_triggered", 0)
                total_impact = cat_info.get("total_impact", 0)
                confidence_boost = cat_info.get("confidence_boost", 0)
                details = cat_info.get("details", [])

                # Display category header
                if total_impact >= 2.0:
                    st.error(
                        f"**{cat_name.title()}:** {rules_triggered} rules triggered"
                    )
                elif total_impact >= 1.0:
                    st.warning(
                        f"**{cat_name.title()}:** {rules_triggered} rules triggered"
                    )
                else:
                    st.info(
                        f"**{cat_name.title()}:** {rules_triggered} rules triggered"
                    )

                # Show impact metrics
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric(f"Rules in {cat_name.title()}", rules_triggered)
                with col2:
                    st.metric(f"Impact Score", f"{total_impact:.2f}")
                with col3:
                    st.metric(f"Confidence", f"+{confidence_boost:.1%}")

                # Show evidence details
                with st.expander(
                    f"Evidence Details ({cat_name.title()})", expanded=False
                ):
                    for detail in details:
                        st.write(f"• {detail}")

                st.write("")

        # Recommendations
        if explanations.get("recommendations"):
            st.markdown("---")
            st.markdown("**Recommended Actions**")

            recommendations = explanations["recommendations"]
            for i, rec in enumerate(recommendations, 1):
                if "Immediately" in rec or "junks" in rec.lower():
                    st.error(f"**{i}.** {rec}")
                elif "Consider" in rec or "Watch" in rec or "Verify" in rec:
                    st.warning(f"**{i}.** {rec}")
                else:
                    st.success(f"**{i}.** {rec}")

        # False positive/negative risk assessment
        false_positive_risks = explanations.get("false_positive_risks", [])
        false_negative_risks = explanations.get("false_negative_risks", [])

        if false_positive_risks and false_negative_risks:
            st.markdown("---")
            st.markdown("**Risk Assessment Insights**")

            col1, col2 = st.columns(2)

            with col1:
                st.markdown("**False Negative Risks**")
                for risk in false_negative_risks:
                    st.warning("⚠️ " + risk)

            with col2:
                st.markdown("**False Positive Risks**")
                for risk in false_positive_risks:
                    st.info("💡 " + risk)

        elif false_positive_risks:
            st.markdown("---")
            st.markdown("**Risk Assessment Insights**")
            st.markdown("**False Positive Risks**")
            for risk in false_positive_risks:
                st.info("💡 " + risk)

        elif false_negative_risks:
            st.markdown("---")
            st.markdown("**Risk Assessment Insights**")
            st.markdown("**False Negative Risks**")
            for risk in false_negative_risks:
                st.warning("⚠️ " + risk)

        # Technical analysis details
        with st.expander("🔬 Technical Analysis Details", expanded=False):
            st.markdown("**Advanced Algorithm Insights**")

            # Algorithm explanations
            algorithm_insights = [
                "Adaptive weight adjustments reduce false positives in legitimate business communication",
                "Probabilistic scoring accounts for uncertainty near decision thresholds",
                "Confidence levels reflect algorithm agreement across multiple detection methods",
                "ML features capture behavioral patterns indicative of sophisticated attacks",
                "Rule interactions boost detection of combined attack techniques",
            ]

            for insight in algorithm_insights:
                st.write(f"• {insight}")

            # Performance characteristics
            if explanations.get("summary"):
                summary = explanations["summary"]
                if "confidence is low" in summary.lower():
                    st.markdown("**Note:** Low confidence may require manual review")
                elif "risk" in summary.lower():
                    st.markdown(
                        "**Note:** Algorithm reached high certainty in risk assessment"
                    )

        # Branded recommendation disclaimer
        if any(
            "brand" in cat_name.lower()
            for cat_name in explanations.get("categories", {}).keys()
        ):
            st.markdown("---")
            st.caption(
                "*Brand analysis covers major financial institutions, e-commerce platforms, and government agencies*"
            )
