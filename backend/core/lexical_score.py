def lexical_score(subj, body):
    """Simple lexical scoring based on keywords.
    """
    keywords = ['urgent', 'click here', 'verify', 'login', 'password', 'account']
    text = (subj + ' ' + body).lower()
    count = sum(keyword in text for keyword in keywords)
    return min(count, 5)