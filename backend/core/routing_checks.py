import re
from backend.core.helpers import norm_domain


def received_anomaly(received_headers):
    """Check for anomalies in Received headers.
    Returns string describing the anomaly if found, False otherwise.
    """
    # Simple check: if more than 5 hops or length > 1000
    if len(received_headers) > 5:
        return f"{len(received_headers)} headers (>5)"
    long_headers = [r for r in received_headers if len(r) > 1000]
    if long_headers:
        return f"{len(long_headers)} header(s) with length >1000"
    return False

def msgid_domain_mismatch(msgid, from_dom):
    """Check if msgid domain differs from from domain.
    Returns the msgid domain if it differs, else None.
    """
    if not msgid or not from_dom:
        return None
    match = re.search(r'@([\w.-]+)', msgid)
    if match:
        msgid_dom = norm_domain(match.group(1))
        return msgid_dom if msgid_dom != from_dom else None
    return None
