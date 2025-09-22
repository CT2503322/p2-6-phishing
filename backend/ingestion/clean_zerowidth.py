import re
import unicodedata

# Set of known zero-width / formatting chars that often survive isprintable()
ZERO_WIDTH = {
    "\u034F",       # Combining Grapheme Joiner (Mn) "͏"
    "\u200B", "\u200C", "\u200D",  # ZWSP/ZWNs/ZWJ (Cf)
    "\uFEFF",       # BOM / ZWNBSP (Cf)
    "\u2060",       # Word joiner (Cf)
    "\u00AD",       # Soft hyphen (Cf)
}

# Many wide/special spaces to normalize to a plain space
SPACE_LIKE = {
    "\u00A0", "\u1680", "\u2000", "\u2001", "\u2002", "\u2003",
    "\u2004", "\u2005", "\u2006", "\u2007", "\u2008", "\u2009",
    "\u200A", "\u202F", "\u205F", "\u3000"
}

def clean_zerowidth(text: str) -> str:
    """
    Cleans EML body text by removing zero-width characters,
    normalizing spaces, and trimming unnecessary whitespace.
    
    Args:
        text (str): The input text to clean.
    
    Returns:
        str: The cleaned text.
    """
    if not text:
        return ""

    # 1) Unicode normalize to simplify odd forms
    text = unicodedata.normalize("NFKC", text)

    out = []
    for ch in text:
        # Keep newlines intact (we'll collapse multiples later)
        if ch == "\n":
            out.append("\n")
            continue

        # Drop zero-width / formatting junk
        if ch in ZERO_WIDTH or unicodedata.category(ch) == "Cf":
            continue

        # Normalize any exotic spaces to a regular space
        if ch in SPACE_LIKE or ch.isspace():
            out.append(" ")
        else:
            out.append(ch)

    text = "".join(out)

    # 2) Collapse runs of spaces to a single space
    text = re.sub(r"[ ]{2,}", " ", text)

    # 3) Clean spaces around newlines
    text = re.sub(r" *\n *", "\n", text)

    # 4) Limit multiple blank lines to max one blank line (e.g., two \n)
    text = re.sub(r"\n{3,}", "\n\n", text)

    # 5) Trim each line and overall
    text = "\n".join(line.strip() for line in text.splitlines()).strip()

    return text