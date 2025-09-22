from email.utils import parseaddr


def norm_domain(domain):
    """Normalize domain to lower case.
    """
    return domain.lower() if domain else None

def parse_core_addresses(headers):
    """Parse from, reply-to, return-path. Assume headers are Dict
    """
    from_addr = parseaddr(headers.get('from', ''))[1]
    reply_to = parseaddr(headers.get('reply-to', ''))[1]
    return_path = parseaddr(headers.get('return-path', ''))[1]
    return from_addr, reply_to, return_path