def is_idn_or_confusable(domain):
    """Check for internationalized domain or confusables.
    Returns the specific issue if found, False otherwise.
    """
    if not domain:
        return False
    if 'xn--' in domain:
        return "xn-- prefix"
    if any(ord(c) > 127 for c in domain):
        return "non-ASCII characters"
    return False

def is_freemx(domain):
    """Check if free mail provider.
    """
    return domain in ['gmail.com', 'yahoo.com', 'hotmail.com']

def mentions_brand(subj, body):
    """Check if common brands mentioned.
    Returns list of detected brands, or None.
    """
    brands = ['paypal', 'ebay', 'amazon', 'apple', 'microsoft']
    text = (subj + ' ' + body).lower()
    found = [brand for brand in brands if brand in text]
    return found if found else None
