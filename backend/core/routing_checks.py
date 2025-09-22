import re
from backend.core.helpers import norm_domain


def received_anomaly(received_headers):
    """Check for anomalies in Received headers.
    """
    # Simple check: if more than 5 hops or length > 1000
    return len(received_headers) > 5 or any(len(r) > 1000 for r in received_headers)

def msgid_domain_mismatch(msgid, from_dom):
    """Check if msgid domain differs from from domain.
    """
    if not msgid or not from_dom:
        return False
    match = re.search(r'@([\w.-]+)', msgid)
    if match:
        msgid_dom = norm_domain(match.group(1))
        return msgid_dom != from_dom
    return False