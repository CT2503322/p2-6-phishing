import pytest
from backend.utils.models import (
    Attachment,
    WhitelistHit,
    MimePart,
    HtmlMetrics,
    TextMetrics,
    InlineImage,
    ListUnsubscribe,
    RoutingHop,
    RoutingData,
    RoutingVerdict,
    UrlFinding,
    KeywordHit,
    SubscriptionMetadata,
)


class TestAttachment:
    """Test cases for Attachment dataclass."""

    def test_attachment_creation(self):
        """Test basic Attachment creation."""
        attachment = Attachment(
            filename="test.pdf",
            content_type="application/pdf",
            content=b"fake content",
            filesize=100,
        )
        assert attachment.filename == "test.pdf"
        assert attachment.content_type == "application/pdf"
        assert attachment.content == b"fake content"
        assert attachment.filesize == 100
        assert attachment.content_id is None
        assert attachment.content_disposition is None

    def test_attachment_with_optional_fields(self):
        """Test Attachment with all optional fields."""
        attachment = Attachment(
            filename="test.pdf",
            content_type="application/pdf",
            content=b"content",
            filesize=100,
            content_id="<test@cid>",
            content_disposition="attachment",
        )
        assert attachment.content_id == "<test@cid>"
        assert attachment.content_disposition == "attachment"


class TestMimePart:
    """Test cases for MimePart dataclass."""

    def test_mime_part_creation(self):
        """Test basic MimePart creation."""
        mime_part = MimePart(content_type="text/plain")
        assert mime_part.content_type == "text/plain"
        assert mime_part.charset is None
        assert mime_part.transfer_encoding is None
        assert mime_part.disposition is None
        assert mime_part.filename is None
        assert mime_part.size == 0
        assert mime_part.hash is None
        assert mime_part.is_attachment is False
        assert mime_part.is_inline_image is False

    def test_mime_part_full_creation(self):
        """Test MimePart with all fields."""
        mime_part = MimePart(
            content_type="image/jpeg",
            charset="utf-8",
            transfer_encoding="base64",
            disposition="inline",
            filename="image.jpg",
            size=1024,
            hash="abc123",
            is_attachment=True,
            is_inline_image=True,
        )
        assert mime_part.content_type == "image/jpeg"
        assert mime_part.charset == "utf-8"
        assert mime_part.transfer_encoding == "base64"
        assert mime_part.disposition == "inline"
        assert mime_part.filename == "image.jpg"
        assert mime_part.size == 1024
        assert mime_part.hash == "abc123"
        assert mime_part.is_attachment is True
        assert mime_part.is_inline_image is True


class TestHtmlMetrics:
    """Test cases for HtmlMetrics dataclass."""

    def test_html_metrics_creation(self):
        """Test basic HtmlMetrics creation."""
        metrics = HtmlMetrics()
        assert metrics.length == 0
        assert metrics.link_count == 0
        assert metrics.image_count == 0
        assert metrics.remote_css is False
        assert metrics.tracking_pixels == 0
        assert metrics.ratio_text_to_html == 0.0
        assert metrics.uses_soft_hyphen is False
        assert metrics.has_emoji_in_subject is False
        assert metrics.non_ascii_ratio == 0.0
        assert metrics.url_findings == []

    def test_html_metrics_full_creation(self):
        """Test HtmlMetrics with custom values."""
        url_findings = [
            UrlFinding(
                text="Test Link",
                href="http://example.com",
                netloc="example.com",
                is_ip_literal=False,
                is_punycode=False,
                is_shortener=False,
                text_href_mismatch=False,
                first_seen_pos=10,
                evidence="Test evidence",
            )
        ]

        metrics = HtmlMetrics(
            length=1000,
            link_count=5,
            image_count=3,
            remote_css=True,
            tracking_pixels=2,
            ratio_text_to_html=0.8,
            uses_soft_hyphen=True,
            has_emoji_in_subject=True,
            non_ascii_ratio=0.1,
            url_findings=url_findings,
        )

        assert metrics.length == 1000
        assert metrics.link_count == 5
        assert metrics.image_count == 3
        assert metrics.remote_css is True
        assert metrics.tracking_pixels == 2
        assert metrics.ratio_text_to_html == 0.8
        assert metrics.uses_soft_hyphen is True
        assert metrics.has_emoji_in_subject is True
        assert metrics.non_ascii_ratio == 0.1
        assert metrics.url_findings == url_findings


class TestTextMetrics:
    """Test cases for TextMetrics dataclass."""

    def test_text_metrics_creation(self):
        """Test basic TextMetrics creation."""
        metrics = TextMetrics()
        assert metrics.length == 0
        assert metrics.language is None
        assert metrics.emoji_count == 0
        assert metrics.shouting_ratio == 0.0

    def test_text_metrics_full_creation(self):
        """Test TextMetrics with custom values."""
        metrics = TextMetrics(
            length=500, language="en", emoji_count=3, shouting_ratio=0.7
        )
        assert metrics.length == 500
        assert metrics.language == "en"
        assert metrics.emoji_count == 3
        assert metrics.shouting_ratio == 0.7


class TestInlineImage:
    """Test cases for InlineImage dataclass."""

    def test_inline_image_creation(self):
        """Test basic InlineImage creation."""
        image = InlineImage(
            filename="test.jpg",
            content_type="image/jpeg",
            content=b"image data",
            filesize=2048,
            content_id="cid123",
        )
        assert image.filename == "test.jpg"
        assert image.content_type == "image/jpeg"
        assert image.content == b"image data"
        assert image.filesize == 2048
        assert image.content_id == "cid123"
        assert image.content_disposition is None

    def test_inline_image_with_disposition(self):
        """Test InlineImage with content disposition."""
        image = InlineImage(
            filename="test.png",
            content_type="image/png",
            content=b"png data",
            filesize=1024,
            content_id="cid456",
            content_disposition="inline",
        )
        assert image.content_disposition == "inline"


class TestListUnsubscribe:
    """Test cases for ListUnsubscribe dataclass."""

    def test_list_unsubscribe_creation(self):
        """Test basic ListUnsubscribe creation."""
        unsubscribe = ListUnsubscribe(one_click=False)
        assert unsubscribe.one_click is False
        assert unsubscribe.http is None
        assert unsubscribe.mailto is None
        assert unsubscribe.mailto_subject is None
        assert unsubscribe.provider is None

    def test_list_unsubscribe_full_creation(self):
        """Test ListUnsubscribe with all fields."""
        unsubscribe = ListUnsubscribe(
            one_click=True,
            http="http://example.com/unsubscribe",
            mailto="mailto:unsubscribe@example.com",
            mailto_subject="Unsubscribe request",
            provider="Mailchimp",
        )
        assert unsubscribe.one_click is True
        assert unsubscribe.http == "http://example.com/unsubscribe"
        assert unsubscribe.mailto == "mailto:unsubscribe@example.com"
        assert unsubscribe.mailto_subject == "Unsubscribe request"
        assert unsubscribe.provider == "Mailchimp"


class TestRoutingHop:
    """Test cases for RoutingHop dataclass."""

    def test_routing_hop_creation(self):
        """Test basic RoutingHop creation."""
        hop = RoutingHop()
        assert hop.timestamp is None
        assert hop.by is None
        assert hop.from_ is None
        assert hop.with_ is None
        assert hop.comment is None

    def test_routing_hop_full_creation(self):
        """Test RoutingHop with all fields."""
        hop = RoutingHop(
            timestamp="2023-10-01 10:00:00",
            by="mail.example.com",
            from_="sender@example.com",
            with_="SMTP",
            comment="Test comment",
        )
        assert hop.timestamp == "2023-10-01 10:00:00"
        assert hop.by == "mail.example.com"
        assert hop.from_ == "sender@example.com"
        assert hop.with_ == "SMTP"
        assert hop.comment == "Test comment"


class TestRoutingData:
    """Test cases for RoutingData dataclass."""

    def test_routing_data_creation(self):
        """Test basic RoutingData creation."""
        data = RoutingData(received=[], hops=[], x_received=[])
        assert data.received == []
        assert data.hops == []
        assert data.x_received == []
        assert data.x_original_to is None
        assert data.delivered_to is None

    def test_routing_data_full_creation(self):
        """Test RoutingData with all fields."""
        received = ["from mail.example.com", "by smtp.gmail.com"]
        hops = [RoutingHop(by="mail.example.com")]
        x_received = ["by smtp.gmail.com"]

        data = RoutingData(
            received=received,
            hops=hops,
            x_received=x_received,
            x_original_to="original@example.com",
            delivered_to="recipient@example.com",
        )
        assert data.received == received
        assert data.hops == hops
        assert data.x_received == x_received
        assert data.x_original_to == "original@example.com"
        assert data.delivered_to == "recipient@example.com"


class TestUrlFinding:
    """Test cases for UrlFinding dataclass."""

    def test_url_finding_creation(self):
        """Test UrlFinding creation with required fields."""
        finding = UrlFinding(
            text="Click here",
            href="http://example.com",
            netloc="example.com",
            is_ip_literal=False,
            is_punycode=False,
            is_shortener=False,
            text_href_mismatch=False,
            first_seen_pos=100,
            evidence="Clean URL",
        )
        assert finding.text == "Click here"
        assert finding.href == "http://example.com"
        assert finding.netloc == "example.com"
        assert finding.is_ip_literal is False
        assert finding.is_punycode is False
        assert finding.is_shortener is False
        assert finding.text_href_mismatch is False
        assert finding.first_seen_pos == 100
        assert finding.evidence == "Clean URL"
        assert finding.skeleton_match is None
        assert finding.brand_match is None

    def test_url_finding_with_optional_fields(self):
        """Test UrlFinding with optional fields."""
        finding = UrlFinding(
            text="Google",
            href="https://google.com",
            netloc="google.com",
            is_ip_literal=False,
            is_punycode=False,
            is_shortener=False,
            text_href_mismatch=False,
            first_seen_pos=50,
            evidence="Known brand",
            skeleton_match=True,
            brand_match="Google",
        )
        assert finding.skeleton_match is True
        assert finding.brand_match == "Google"


class TestKeywordHit:
    """Test cases for KeywordHit dataclass."""

    def test_keyword_hit_creation(self):
        """Test KeywordHit creation."""
        hit = KeywordHit(
            term="urgent", weight=0.8, where="subject", pos=10, window="subject_0_50"
        )
        assert hit.term == "urgent"
        assert hit.weight == 0.8
        assert hit.where == "subject"
        assert hit.pos == 10
        assert hit.window == "subject_0_50"


class TestWhitelistHit:
    """Test cases for WhitelistHit dataclass."""

    def test_whitelist_hit_creation(self):
        """Test basic WhitelistHit creation."""
        hit = WhitelistHit(
            matched_domain="example.com",
            scope="exact",
            reason="manual-whitelist",
        )
        assert hit.matched_domain == "example.com"
        assert hit.scope == "exact"
        assert hit.reason == "manual-whitelist"

    def test_whitelist_hit_valid_scopes(self):
        """Test WhitelistHit with all valid scopes."""
        for scope in ["exact", "apex", "subdomain"]:
            hit = WhitelistHit(
                matched_domain="example.com",
                scope=scope,
                reason="test",
            )
            assert hit.scope == scope

    def test_whitelist_hit_invalid_scope(self):
        """Test WhitelistHit with invalid scope raises ValueError."""
        with pytest.raises(ValueError, match="Invalid scope"):
            WhitelistHit(
                matched_domain="example.com",
                scope="invalid",
                reason="test",
            )


class TestRoutingVerdict:
    """Test cases for RoutingVerdict dataclass."""

    def test_routing_verdict_creation(self):
        """Test basic RoutingVerdict creation."""
        verdict = RoutingVerdict(
            routing_findings="Normal routing chain length; No obvious routing anomalies",
            helo_domain="mail.example.com",
            helo_ip_mismatch=False,
            received_chain_count=2,
            suspicious_hop=False,
            evidence="HELO/EHLO hostname: mail.example.com",
        )
        assert (
            verdict.routing_findings
            == "Normal routing chain length; No obvious routing anomalies"
        )
        assert verdict.helo_domain == "mail.example.com"
        assert verdict.helo_ip_mismatch is False
        assert verdict.received_chain_count == 2
        assert verdict.suspicious_hop is False
        assert verdict.evidence == "HELO/EHLO hostname: mail.example.com"

    def test_routing_verdict_with_suspicious_hop(self):
        """Test RoutingVerdict with suspicious hop detected."""
        verdict = RoutingVerdict(
            routing_findings="Extended routing chain; Suspicious routing patterns detected",
            helo_domain="mail.example.com",
            helo_ip_mismatch=True,
            received_chain_count=5,
            suspicious_hop=True,
            evidence="Private IP 192.168.1.1 found in routing hop 2; HELO IP 10.0.0.1 may not match hostname mail.example.com",
        )
        assert verdict.helo_ip_mismatch is True
        assert verdict.suspicious_hop is True
        assert verdict.received_chain_count == 5
        assert "Suspicious routing patterns detected" in verdict.routing_findings

    def test_routing_verdict_no_routing_info(self):
        """Test RoutingVerdict when no routing information is present."""
        verdict = RoutingVerdict(
            routing_findings="No routing information present - may be a sent email; No obvious routing anomalies",
            helo_domain=None,
            helo_ip_mismatch=False,
            received_chain_count=0,
            suspicious_hop=False,
            evidence="Standard routing analysis",
        )
        assert verdict.helo_domain is None
        assert verdict.received_chain_count == 0
        assert "No routing information present" in verdict.routing_findings


class TestSubscriptionMetadata:
    """Test cases for SubscriptionMetadata dataclass."""

    def test_subscription_metadata_creation(self):
        """Test basic SubscriptionMetadata creation."""
        metadata = SubscriptionMetadata()
        assert metadata.list_unsubscribe is None
        assert metadata.list_unsubscribe_post is None
        assert metadata.feedback_id is None
        assert metadata.precedence is None

    def test_subscription_metadata_full_creation(self):
        """Test SubscriptionMetadata with all fields."""
        unsubscribe = ListUnsubscribe(one_click=True, http="http://unsub.example.com")

        metadata = SubscriptionMetadata(
            list_unsubscribe=unsubscribe,
            list_unsubscribe_post="http://post.example.com",
            feedback_id="feedback123",
            precedence="bulk",
        )
        assert metadata.list_unsubscribe == unsubscribe
        assert metadata.list_unsubscribe_post == "http://post.example.com"
        assert metadata.feedback_id == "feedback123"
        assert metadata.precedence == "bulk"
