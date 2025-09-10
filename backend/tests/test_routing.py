import pytest
from backend.ingestion.models import RoutingData, RoutingHop, RoutingVerdict
from backend.ingestion.parse_eml import analyze_routing_verdict


class TestRoutingVerdictAnalysis:
    """Test cases for routing verdict analysis functionality."""

    def test_analyze_routing_verdict_normal_case(self):
        """Test analysis of normal routing data."""
        received = [
            "from mail.example.com (mail.example.com [192.0.2.1]) by mx.example.com with ESMTP id ABC123 Mon, 01 Jan 2024 12:00:00 +0000",
            "by smtp.gmail.com with ESMTP id DEF456 Mon, 01 Jan 2024 12:01:00 +0000",
        ]
        hops = [
            RoutingHop(
                by="mx.example.com",
                from_="mail.example.com",
                timestamp="Mon, 01 Jan 2024 12:00:00 +0000",
                with_="ESMTP",
            ),
            RoutingHop(
                by="smtp.gmail.com",
                from_="mx.example.com",
                timestamp="Mon, 01 Jan 2024 12:01:00 +0000",
                with_="ESMTP",
            ),
        ]

        routing_data = RoutingData(
            received=received,
            hops=hops,
            x_received=[],
            x_original_to=None,
            delivered_to=None,
        )

        verdict = analyze_routing_verdict(routing_data)

        assert verdict.received_chain_count == 2
        assert verdict.helo_domain == "mail.example.com"
        assert verdict.helo_ip_mismatch is True  # mail.example.com != 192.0.2.1
        assert verdict.suspicious_hop is False
        assert "Normal routing chain length" in verdict.routing_findings
        assert "HELO hostname/IP mismatch detected" in verdict.routing_findings

    def test_analyze_routing_verdict_private_ip_external(self):
        """Test detection of private IP in external routing position."""
        received = [
            "from mail.example.com (mail.example.com [192.0.2.1]) by mx.example.com with ESMTP Mon, 01 Jan 2024 12:00:00 +0000",
            "from 192.168.1.100 by external.mail.com with ESMTP id DEF456 Mon, 01 Jan 2024 12:01:00 +0000",
        ]
        hops = [
            RoutingHop(
                by="mx.example.com",
                from_="mail.example.com",
                timestamp="Mon, 01 Jan 2024 12:00:00 +0000",
            ),
            RoutingHop(
                by="external.mail.com",
                from_="192.168.1.100",
                timestamp="Mon, 01 Jan 2024 12:01:00 +0000",
            ),
        ]

        routing_data = RoutingData(
            received=received,
            hops=hops,
            x_received=[],
            x_original_to=None,
            delivered_to=None,
        )

        verdict = analyze_routing_verdict(routing_data)

        assert verdict.suspicious_hop is True
        assert "Private IP 192.168.1.100 found in routing hop 2" in verdict.evidence
        assert "Suspicious routing patterns detected" in verdict.routing_findings

    def test_analyze_routing_verdict_helo_ip_mismatch(self):
        """Test detection of HELO hostname/IP mismatch."""
        received = [
            "from mail.example.com (mail.example.com [192.168.1.100]) by mx.example.com with ESMTP Mon, 01 Jan 2024 12:00:00 +0000"
        ]
        hops = [
            RoutingHop(
                by="mx.example.com",
                from_="mail.example.com",
                timestamp="Mon, 01 Jan 2024 12:00:00 +0000",
            )
        ]

        routing_data = RoutingData(
            received=received,
            hops=hops,
            x_received=[],
            x_original_to=None,
            delivered_to=None,
        )

        verdict = analyze_routing_verdict(routing_data)

        assert verdict.helo_ip_mismatch is True
        assert "HELO hostname/IP mismatch detected" in verdict.routing_findings
        assert (
            "HELO IP 192.168.1.100 may not match hostname mail.example.com"
            in verdict.evidence
        )

    def test_analyze_routing_verdict_no_routing_info(self):
        """Test analysis when no routing information is present."""
        routing_data = RoutingData(
            received=[], hops=[], x_received=[], x_original_to=None, delivered_to=None
        )

        verdict = analyze_routing_verdict(routing_data)

        assert verdict.received_chain_count == 0
        assert verdict.helo_domain is None
        assert verdict.suspicious_hop is False
        assert "No routing information present" in verdict.routing_findings
        assert "Standard routing analysis" in verdict.evidence

    def test_analyze_routing_verdict_malformed_hop(self):
        """Test detection of malformed routing hop."""
        received = [
            "from mail.example.com by mx.example.com with ESMTP Mon, 01 Jan 2024 12:00:00 +0000",
            "by smtp.unknown Mon, 01 Jan 2024 12:01:00 +0000",  # Missing 'from' field
        ]
        hops = [
            RoutingHop(
                by="mx.example.com",
                from_="mail.example.com",
                timestamp="Mon, 01 Jan 2024 12:00:00 +0000",
            ),
            RoutingHop(
                by="smtp.unknown",
                from_=None,
                timestamp="Mon, 01 Jan 2024 12:01:00 +0000",
            ),  # Malformed
        ]

        routing_data = RoutingData(
            received=received,
            hops=hops,
            x_received=[],
            x_original_to=None,
            delivered_to=None,
        )

        verdict = analyze_routing_verdict(routing_data)

        assert verdict.suspicious_hop is True
        assert "Malformed routing hop 2: missing from field" in verdict.evidence

    def test_analyze_routing_verdict_missing_timestamp(self):
        """Test detection of hop with missing timestamp."""
        received = ["from mail.example.com by mx.example.com with ESMTP"]
        hops = [
            RoutingHop(by="mx.example.com", from_="mail.example.com", timestamp=None)
        ]

        routing_data = RoutingData(
            received=received,
            hops=hops,
            x_received=[],
            x_original_to=None,
            delivered_to=None,
        )

        verdict = analyze_routing_verdict(routing_data)

        assert verdict.suspicious_hop is True
        assert "Routing hop 1 missing timestamp" in verdict.evidence

    def test_analyze_routing_verdict_extended_chain(self):
        """Test analysis of extended routing chain."""
        received = ["header"] * 5  # 5 received headers
        hops = [RoutingHop()] * 5

        routing_data = RoutingData(
            received=received,
            hops=hops,
            x_received=[],
            x_original_to=None,
            delivered_to=None,
        )

        verdict = analyze_routing_verdict(routing_data)

        assert verdict.received_chain_count == 5
        assert "Extended routing chain" in verdict.routing_findings

    def test_analyze_routing_verdict_single_hop(self):
        """Test analysis of single-hop routing."""
        received = [
            "from mail.example.com by mx.example.com with ESMTP Mon, 01 Jan 2024 12:00:00 +0000"
        ]
        hops = [
            RoutingHop(
                by="mx.example.com",
                from_="mail.example.com",
                timestamp="Mon, 01 Jan 2024 12:00:00 +0000",
            )
        ]

        routing_data = RoutingData(
            received=received,
            hops=hops,
            x_received=[],
            x_original_to=None,
            delivered_to=None,
        )

        verdict = analyze_routing_verdict(routing_data)

        assert verdict.received_chain_count == 1
        assert "Minimal routing" in verdict.routing_findings
