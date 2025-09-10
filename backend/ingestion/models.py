from dataclasses import dataclass
from typing import Optional, Dict, Any, List


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
class SubscriptionMetadata:
    list_unsubscribe: Optional[ListUnsubscribe] = None
    list_unsubscribe_post: Optional[str] = None
    feedback_id: Optional[str] = None
    precedence: Optional[str] = None
