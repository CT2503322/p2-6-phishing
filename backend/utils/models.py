from dataclasses import dataclass
from typing import Optional, Dict, Any, List
from enum import Enum


class Label(Enum):
    SAFE = "SAFE"
    PHISHING = "PHISHING"


@dataclass
class RuleScore:
    rule: str  # e.g., "url_punycode", "replyto_mismatch"
    delta: float  # ± weight applied to total score
    evidence: str  # Explanation of why this rule was triggered


@dataclass
class RoutingVerdict:
    routing_findings: str  # Condensed verdict explanation
    helo_domain: Optional[str] = None  # HELO domain if present
    helo_ip_mismatch: bool = False  # True if HELO IP doesn't match declared hostname
    received_chain_count: int = 0  # Number of received headers
    suspicious_hop: bool = False  # True if suspicious routing detected
    evidence: str = ""  # Supporting evidence for the verdict


@dataclass
class Attachment:
    filename: str
    content_type: str
    content: bytes
    filesize: int
    content_id: Optional[str] = None
    content_disposition: Optional[str] = None


@dataclass
class MimePart:
    content_type: str
    charset: Optional[str] = None
    transfer_encoding: Optional[str] = None
    disposition: Optional[str] = None
    filename: Optional[str] = None
    size: int = 0
    hash: Optional[str] = None
    is_attachment: bool = False
    is_inline_image: bool = False


@dataclass
class HtmlMetrics:
    length: int = 0
    link_count: int = 0
    image_count: int = 0
    remote_css: bool = False
    tracking_pixels: int = 0
    ratio_text_to_html: float = 0.0
    uses_soft_hyphen: bool = False
    has_emoji_in_subject: bool = False
    non_ascii_ratio: float = 0.0
    url_findings: List["UrlFinding"] = None

    def __post_init__(self):
        if self.url_findings is None:
            self.url_findings = []


@dataclass
class TextMetrics:
    length: int = 0
    language: Optional[str] = None
    emoji_count: int = 0
    shouting_ratio: float = 0.0


@dataclass
class InlineImage:
    filename: str
    content_type: str
    content: bytes
    filesize: int
    content_id: str
    content_disposition: Optional[str] = None


@dataclass
class ListUnsubscribe:
    one_click: bool
    http: Optional[str] = None
    mailto: Optional[str] = None
    mailto_subject: Optional[str] = None
    provider: Optional[str] = None


@dataclass
class RoutingHop:
    timestamp: Optional[str] = None
    by: Optional[str] = None
    from_: Optional[str] = None
    with_: Optional[str] = None
    comment: Optional[str] = None


@dataclass
class RoutingData:
    received: List[str]  # Raw received headers
    hops: List[RoutingHop]  # Parsed routing hops
    x_received: List[str]
    x_original_to: Optional[str] = None
    delivered_to: Optional[str] = None


@dataclass
class UrlFinding:
    text: str  # anchor text as rendered, trimmed
    href: str  # absolute, after resolving base if any
    netloc: str  # domain:port
    is_ip_literal: bool
    is_punycode: bool  # netloc.startswith('xn--')
    is_shortener: (
        bool  # e.g., bit.ly, t.co, tinyurl, goo.gl, cutt.ly, rebrand.ly, lnkd.in, etc.
    )
    text_href_mismatch: (
        bool  # normalized text domain ≠ href domain when text looks like a URL/brand
    )
    first_seen_pos: int  # char index in HTML/text for position weighting
    evidence: str  # string for explanation
    skeleton_match: Optional[bool] = None  # see confusables
    brand_match: Optional[str] = None  # if URL domain maps to a known brand


@dataclass
class KeywordHit:
    term: str
    weight: float
    where: str  # subject | body
    pos: int  # char index; 0-based
    window: str  # e.g., subject, body_0_500


@dataclass
class LookalikeFinding:
    """Data structure for edit-distance-based lookalike detection."""

    suspect_domain: str
    target_domain: str
    distance: int
    within_cutoff: bool
    evidence: str


@dataclass
class AttachmentFinding:
    filename: str
    ext_primary: str  # e.g., .exe, .docm
    double_ext: bool  # parsed pair like .pdf.exe
    declared_mime: str
    is_macro_enabled: bool
    is_dangerous_type: bool
    is_archive: bool
    evidence: str
    sniffed_mime: Optional[str] = None  # optional if magic sniff fails
    archive_contains_dangerous: Optional[bool] = None  # null if not inspected


@dataclass
class WhitelistHit:
    matched_domain: str
    scope: str  # 'exact' | 'apex' | 'subdomain' | 'wildcard-subdomain' | 'wildcard-apex' | 'wildcard-tld' | 'wildcard-pattern'
    reason: str

    def __post_init__(self):
        valid_scopes = {
            "exact",
            "apex",
            "subdomain",
            "wildcard-subdomain",
            "wildcard-apex",
            "wildcard-tld",
            "wildcard-pattern",
        }
        if self.scope not in valid_scopes:
            raise ValueError(f"Invalid scope: {self.scope}")


@dataclass
class SubscriptionMetadata:
    list_unsubscribe: Optional[ListUnsubscribe] = None
    list_unsubscribe_post: Optional[str] = None
    feedback_id: Optional[str] = None
    precedence: Optional[str] = None


@dataclass
class ScoredAnalysis:
    """Comprehensive analysis with detailed rule-based scoring."""

    score_breakdown: List[RuleScore]
    score_total: float
    label: Label
    threshold_used: float
    tuning_profile: str
