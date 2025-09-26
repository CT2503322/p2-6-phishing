from __future__ import annotations

import unicodedata
from typing import Sequence

ZERO_WIDTH_CHARS = frozenset(chr(codepoint) for codepoint in (
    0x200B,
    0x200C,
    0x200D,
    0x200E,
    0x200F,
    0x2060,
    0x2061,
    0x2062,
    0x2063,
    0x2064,
    0xFEFF)
)

CONFUSABLE_CODEPOINTS: dict[str, tuple[int, ...]] = {
    '-': (0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2212),
    '0': (0x07C0, 0x1D7CE),
    '1': (0x07C1, 0x1D7CF),
    '2': (0x07C2, 0x1D7D0),
    '3': (0x07C3, 0x1D7D1),
    '4': (0x07C4, 0x1D7D2, 0x13CE),
    '5': (0x07C5, 0x1D7D3, 0x01BD),
    '6': (0x07C6, 0x1D7D4),
    '7': (0x07C7, 0x1D7D5),
    '8': (0x07C8, 0x1D7D6),
    '9': (0x07C9, 0x1D7D7),
    'a': (0x0250, 0x0430, 0x03B1, 0x2C65, 0x1D00),
    'c': (0x0441, 0x03F2, 0x217D),
    'd': (0x0501, 0x217E),
    'e': (0x0435, 0x03B5, 0x212E),
    'g': (0x0261,),
    'h': (0x04BB, 0x0570),
    'i': (0x0131, 0x0456, 0x2170),
    'j': (0x0458,),
    'k': (0x03BA, 0x043A),
    'l': (0x019A, 0x04C0, 0x217C),
    'm': (0x217F, 0x043C),
    'n': (0x043D, 0x0578),
    'o': (0x043E, 0x03BF, 0x2C9F),
    'p': (0x0440, 0x03C1, 0x1D29),
    'q': (0x051B,),
    'r': (0x0433, 0x1D26),
    's': (0x0455,),
    't': (0x0442, 0x1D1B),
    'u': (0x0446, 0x03C5, 0x057D, 0x1D1C),
    'v': (0x0475, 0x03BD, 0x1D20),
    'w': (0x0461, 0x051D, 0x1D21),
    'x': (0x0445, 0x03C7),
    'y': (0x0443, 0x04AF, 0x03C5),
    'z': (0x1D22, 0x0240),
}

CONFUSABLE_MAP: dict[str, str] = {}
for ascii_char, codepoints in CONFUSABLE_CODEPOINTS.items():
    for codepoint in codepoints:
        CONFUSABLE_MAP[chr(codepoint)] = ascii_char

CONFUSABLE_MAP.update({
    chr(0x00DF): 'ss',
    chr(0x00E6): 'ae',
    chr(0x00F0): 'd',
    chr(0x00FE): 'th',
    chr(0x0111): 'd',
    chr(0x0133): 'ij',
    chr(0x0142): 'l',
    chr(0x0153): 'oe',
})


def contains_zero_width(text: str | None) -> bool:
    if not text:
        return False
    return any(char in ZERO_WIDTH_CHARS for char in text)


def normalize_unicode(text: str | None) -> str:
    if not text:
        return ''
    normalized = unicodedata.normalize('NFKC', text)
    without_zero_width = ''.join(char for char in normalized if char not in ZERO_WIDTH_CHARS)
    return without_zero_width.casefold()


def unicode_skeleton(text: str | None) -> str:
    if not text:
        return ''
    normalized = normalize_unicode(text)
    decomposed = unicodedata.normalize('NFKD', normalized)
    pieces: list[str] = []
    for char in decomposed:
        if unicodedata.combining(char) or char in ZERO_WIDTH_CHARS:
            continue
        mapped = CONFUSABLE_MAP.get(char)
        if mapped is not None:
            pieces.append(mapped)
            continue
        if ord(char) < 128:
            pieces.append(char)
            continue
        fallback = unicodedata.normalize('NFKD', char).encode('ascii', 'ignore').decode('ascii')
        if fallback:
            pieces.append(fallback)
    skeleton = ''.join(pieces)
    return ''.join(char for char in skeleton if char.isascii())


def detect_confusable(domain: str | None, reference_domains: Sequence[str] | None = None) -> str | None:
    if not domain:
        return None
    candidate = domain.strip()
    if not candidate:
        return None

    lower_candidate = candidate.casefold()

    if 'xn--' in lower_candidate:
        return 'punycode label'
    if contains_zero_width(lower_candidate):
        return 'zero-width characters'

    skeleton = unicode_skeleton(lower_candidate)
    ascii_fold = ''.join(char for char in normalize_unicode(lower_candidate) if char.isascii())

    if reference_domains:
        for reference in reference_domains:
            ref = (reference or '').strip()
            if not ref:
                continue
            ref_lower = ref.casefold()
            if ref_lower == lower_candidate:
                continue
            if skeleton and skeleton == unicode_skeleton(ref_lower):
                return f'confusable match for {ref_lower}'

    if any(ord(char) > 127 for char in lower_candidate):
        if skeleton and skeleton != ascii_fold:
            return f'confusable skeleton {skeleton}'
        return 'non-ascii characters'

    return None

