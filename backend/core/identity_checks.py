def is_idn_or_confusable(domain):
    """Check for internationalized domain or confusables.
    """
    if not domain:
        return False
    return any(ord(c) > 127 for c in domain) or 'xn--' in domain

def is_freemx(domain):
    """Check if free mail provider.
    """
    return domain in ['gmail.com', 'yahoo.com', 'hotmail.com']

def mentions_brand(subj, body):
    """Check if common brands mentioned.
    """
    brands = ['paypal', 'ebay', 'amazon', 'apple', 'microsoft']
    text = (subj + ' ' + body).lower()
    return any(brand in text for brand in brands)