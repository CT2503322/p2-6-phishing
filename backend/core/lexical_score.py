def lexical_score(subj, body):
    """Simple lexical scoring based on keywords.
    Returns score and matched keywords.
    """
    keywords = ['urgent', 'click here', 'verify', 'login', 'password', 'account']
    text = (subj + ' ' + body).lower()
    matched = [kw for kw in keywords if kw in text]
    count = len(matched)
    return min(count, 5), matched
