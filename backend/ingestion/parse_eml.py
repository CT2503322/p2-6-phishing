from email import policy
import email
from email.parser import BytesParser
from email.utils import getaddresses
import re
from typing import Dict, Any
from email.message import EmailMessage

from backend.ingestion.clean_html import clean_html
from backend.ingestion.clean_zerowidth import clean_zerowidth

def _first_addr(header_value: str | None) -> str | None:
    """
    Return the first RFC-2822 address found in the header (email part only),
    or None if no address is present.
    """
    if not header_value:
        return None
    for _, addr in getaddresses([header_value]):
        if addr:
            return addr
    return None

def parse_eml(file_path):
    """
    Parse an EML file and extract all requested fields, with support for
    HTML content cleaning using BeautifulSoup.
    
    Args:
        file_path (str): Path to the EML file
    
    Returns:
        dict: Extracted email data
    """
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    
    # Extract standard email headers
    subject = msg.get('Subject', 'No Subject')
    sender = msg.get('From', 'No Sender')
    recipients = msg.get('To', 'No Recipients')
    cc = msg.get('Cc', '')
    bcc = msg.get('Bcc', '')
    date = msg.get('Date', 'No Date')
    message_id_raw = (msg.get('Message-ID') or msg.get('Message-Id') or '').strip()
    message_id = re.sub(r'[<>]', '', message_id_raw) or None
    
    # Extract MIME-related headers
    mime_version = msg.get('Mime-Version', '')
    content_type = msg.get('Content-Type', '')
    content_transfer_encoding = msg.get('Content-Transfer-Encoding', '')
    
    reply_to = _first_addr(msg.get('Reply-To'))
    if not reply_to:
        reply_to = _first_addr(msg.get('From'))

    return_path_raw = (msg.get('Return-Path') or '').strip()
    return_path = re.sub(r'[<>]', '', return_path_raw) if return_path_raw else None
    if not return_path:
        # Derive a sensible default chain: Sender, else From
        return_path = _first_addr(msg.get('Sender') or msg.get('From'))

    # Decode subject if needed
    try:
        if subject:
            decoded_subject = email.header.decode_header(subject)
            subject = ''.join(part[0].decode(part[1] or 'utf-8') if isinstance(part[0], bytes) else str(part[0]) for part in decoded_subject)
    except:
        pass
    
    # Extract email body with HTML cleaning support
    body = ''
    attachments = []
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            
            # Handle plain text parts
            if content_type == 'text/plain' and not part.get_filename():
                part_body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                if body:  # If we already have body, append
                    body += '\n' + part_body
                else:
                    body = part_body
            
            # Handle HTML parts with BeautifulSoup cleaning
            elif content_type == 'text/html' and not part.get_filename():
                html_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                clean_content = clean_html(html_content)
                if body:  # If we already have body, append
                    body += '\n' + clean_content
                else:
                    body = clean_content
            
            # Handle attachments
            elif part.get_filename():
                attachments.append(part.get_filename())
    else:
        # Single part message
        payload = msg.get_payload(decode=True)
        if payload:
            content_type = msg.get_content_type()
            
            if content_type == 'text/html':
                body = clean_html(payload.decode('utf-8', errors='ignore'))
                body = clean_zerowidth(body)
            else:
                body = payload.decode('utf-8', errors='ignore')
    
    return {
        'file': file_path,
        'message_id': message_id,
        'reply_to': reply_to,
        'return_path': return_path,
        'date': date,
        'from': sender,
        'to': recipients,
        'cc': cc,
        'bcc': bcc,
        'subject': subject,
        'body': body,
        'mime_version': mime_version,
        'content_type': content_type,
        'content_transfer_encoding': content_transfer_encoding,
        'attachments': '; '.join(attachments) if attachments else ''
    }
