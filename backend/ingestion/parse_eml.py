import base64
import hashlib
import mimetypes
import os
import re
from typing import Any, Dict, Iterable, List

from email import policy
from email.header import decode_header, make_header
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses

from backend.ingestion.clean_html import clean_html
from backend.ingestion.clean_zerowidth import clean_zerowidth

DEFAULT_CHARSET_CANDIDATES: tuple[str, ...] = (
    "utf-8",
    "utf-16",
    "windows-1252",
    "latin-1",
    "iso-8859-1",
    "iso-8859-15",
    "ascii",
)

MAX_INLINE_ATTACHMENT_BYTES = 256 * 1024

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

def _decode_header_value(value: str | None) -> str:
    if not value:
        return ""
    try:
        decoded = make_header(decode_header(value))
        return clean_zerowidth(str(decoded))
    except Exception:
        return clean_zerowidth(value)

def _decode_filename(name: str | None) -> str | None:
    if not name:
        return None
    try:
        decoded = str(make_header(decode_header(name)))
    except Exception:
        decoded = name
    decoded = clean_zerowidth(decoded).strip()
    basename = os.path.basename(decoded)
    return basename or None

def _normalize_content_id(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip().strip("<>").strip()
    return cleaned or None

def _candidate_charsets(preferred: str | None) -> Iterable[str]:
    seen: set[str] = set()
    if preferred:
        normalized = preferred.strip()
        if normalized:
            lowered = normalized.lower()
            if lowered not in seen:
                seen.add(lowered)
                yield normalized
            alt = lowered.replace("_", "-")
            if alt and alt not in seen:
                seen.add(alt)
                yield alt
    for charset in DEFAULT_CHARSET_CANDIDATES:
        if charset not in seen:
            seen.add(charset)
            yield charset

def _get_payload_bytes(part: Message) -> bytes | None:
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = None
    if payload is None:
        raw_payload = part.get_payload()
        if isinstance(raw_payload, str):
            charset = part.get_content_charset() or part.get_param("charset")
            for candidate in _candidate_charsets(charset):
                try:
                    return raw_payload.encode(candidate)
                except (LookupError, UnicodeEncodeError):
                    continue
            return raw_payload.encode("utf-8", "ignore")
        return None
    if isinstance(payload, str):
        return payload.encode("utf-8", "ignore")
    return payload

def _bytes_to_text(payload: bytes | None, charset: str | None) -> str:
    if payload is None:
        return ""
    for candidate in _candidate_charsets(charset):
        try:
            return payload.decode(candidate)
        except (LookupError, UnicodeDecodeError):
            continue
    return payload.decode("utf-8", "ignore")

def _guess_extension(content_type: str) -> str:
    if not content_type:
        return ""
    ext = mimetypes.guess_extension(content_type)
    if ext:
        return ext
    maintype, _, subtype = content_type.partition("/")
    if subtype:
        return f".{subtype}"
    return ""

def _sanitize_filename(raw_name: str | None, index: int, content_type: str) -> str:
    decoded = _decode_filename(raw_name)
    if decoded:
        return decoded
    fallback = _guess_extension(content_type)
    if fallback:
        return f"part-{index}{fallback}"
    return f"part-{index}"

def _is_attachment(part: Message, filename: str | None) -> bool:
    disposition = part.get_content_disposition()
    content_type = part.get_content_type()
    if disposition == "attachment":
        return True
    if content_type == "message/rfc822":
        return True
    if disposition == "inline" and filename:
        return True
    if disposition == "inline" and not content_type.startswith("text/"):
        return True
    if filename and disposition is None:
        return True
    if content_type.startswith("multipart/"):
        return False
    if content_type.startswith("text/"):
        return bool(filename and disposition in (None, "attachment"))
    return True

def _build_attachment_metadata(part: Message, index: int, payload_bytes: bytes | None) -> Dict[str, Any]:
    payload = payload_bytes or b""
    filename = _sanitize_filename(part.get_filename(), index, part.get_content_type())
    encoding_header = part.get("Content-Transfer-Encoding")
    encoding = encoding_header.lower() if encoding_header else None
    size = len(payload)
    payload_base64 = None
    payload_included = False
    if payload and size <= MAX_INLINE_ATTACHMENT_BYTES:
        payload_base64 = base64.b64encode(payload).decode("ascii")
        payload_included = True
    checksum = hashlib.sha256(payload).hexdigest() if payload else None
    return {
        "filename": filename,
        "content_type": part.get_content_type(),
        "size": size,
        "is_inline": part.get_content_disposition() == "inline",
        "content_id": _normalize_content_id(part.get("Content-ID")),
        "content_disposition": part.get_content_disposition(),
        "content_transfer_encoding": encoding,
        "checksum_sha256": checksum,
        "payload_base64": payload_base64,
        "payload_included": payload_included,
    }

def _walk_leaf_parts(message: Message) -> Iterable[Message]:
    stack: List[Message] = [message]
    while stack:
        current = stack.pop()
        if current.is_multipart():
            children = list(current.iter_parts())
            stack.extend(reversed(children))
            continue
        yield current

def _build_mime_tree(part: Message) -> Dict[str, Any]:
    node: Dict[str, Any] = {
        "content_type": part.get_content_type(),
        "content_disposition": part.get_content_disposition(),
        "filename": _decode_filename(part.get_filename()),
    }
    if part.is_multipart():
        node["parts"] = [_build_mime_tree(child) for child in part.iter_parts()]
    elif part.get_content_type() == "message/rfc822":
        payload = part.get_payload()
        children: List[Dict[str, Any]] = []
        if isinstance(payload, list):
            for sub in payload:
                if isinstance(sub, Message):
                    children.append(_build_mime_tree(sub))
        elif isinstance(payload, Message):
            children.append(_build_mime_tree(payload))
        if children:
            node["parts"] = children
    return node

def parse_eml(file_path):
    """
    Parse an EML file and extract all requested fields, with robust MIME
    parsing, charset handling, and attachment extraction.
    """
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    subject_raw = msg.get('Subject')
    subject = _decode_header_value(subject_raw) or 'No Subject'
    sender = _decode_header_value(msg.get('From')) or 'No Sender'
    recipients = _decode_header_value(msg.get('To')) or 'No Recipients'
    cc = _decode_header_value(msg.get('Cc'))
    bcc = _decode_header_value(msg.get('Bcc'))
    date = _decode_header_value(msg.get('Date')) or 'No Date'

    message_id_raw = (msg.get('Message-ID') or msg.get('Message-Id') or '').strip()
    message_id = re.sub(r'[<>]', '', message_id_raw) or None

    mime_version = _decode_header_value(msg.get('Mime-Version'))
    content_type_header = msg.get('Content-Type', '')
    content_transfer_encoding = _decode_header_value(msg.get('Content-Transfer-Encoding'))
    top_level_type = msg.get_content_type()

    reply_to = _first_addr(msg.get('Reply-To'))
    if not reply_to:
        reply_to = _first_addr(msg.get('From'))

    return_path_raw = (msg.get('Return-Path') or '').strip()
    return_path = re.sub(r'[<>]', '', return_path_raw) if return_path_raw else None
    if not return_path:
        return_path = _first_addr(msg.get('Sender') or msg.get('From'))

    attachments_meta: List[Dict[str, Any]] = []
    attachment_names: List[str] = []
    text_parts: List[str] = []
    html_parts: List[str] = []
    body_parts: List[Dict[str, Any]] = []

    for index, part in enumerate(_walk_leaf_parts(msg), 1):
        filename_hint = _decode_filename(part.get_filename())
        payload_bytes = _get_payload_bytes(part)
        charset = part.get_content_charset() or part.get_param('charset')
        content_type = part.get_content_type()

        if _is_attachment(part, filename_hint):
            attachment_meta = _build_attachment_metadata(part, index, payload_bytes)
            attachments_meta.append(attachment_meta)
            attachment_names.append(attachment_meta['filename'])
            continue

        if content_type == 'text/plain':
            text = clean_zerowidth(_bytes_to_text(payload_bytes, charset))
            if text:
                text_parts.append(text)
                body_parts.append({
                    'content_type': content_type,
                    'charset': charset,
                    'content': text,
                    'raw_content': text,
                    'source': 'text/plain',
                })
            continue

        if content_type == 'text/html':
            raw_html = _bytes_to_text(payload_bytes, charset)
            cleaned = clean_html(raw_html)
            cleaned = clean_zerowidth(cleaned)
            if cleaned:
                html_parts.append(cleaned)
                body_parts.append({
                    'content_type': content_type,
                    'charset': charset,
                    'content': cleaned,
                    'raw_content': raw_html,
                    'source': 'text/html',
                })
            continue

        if content_type.startswith('text/'):
            text = clean_zerowidth(_bytes_to_text(payload_bytes, charset))
            if text:
                text_parts.append(text)
                body_parts.append({
                    'content_type': content_type,
                    'charset': charset,
                    'content': text,
                    'raw_content': text,
                    'source': content_type,
                })
            continue

        attachment_meta = _build_attachment_metadata(part, index, payload_bytes)
        attachments_meta.append(attachment_meta)
        attachment_names.append(attachment_meta['filename'])

    body_plain = clean_zerowidth('\n\n'.join(text_parts)).strip() if text_parts else ''
    body_html = clean_zerowidth('\n\n'.join(html_parts)).strip() if html_parts else ''
    body = body_plain or body_html

    headers_map: Dict[str, List[str]] = {}
    for name, value in msg.items():
        headers_map.setdefault(name, []).append(value)

    decoded_headers: Dict[str, List[str]] = {
        name: [_decode_header_value(v) for v in values]
        for name, values in headers_map.items()
    }

    received_header = '\n'.join(headers_map.get('Received', []))

    return {
        'file': file_path,
        'message_id': message_id,
        'reply_to': reply_to,
        'return_path': return_path,
        'date': date,
        'from': sender,
        'to': recipients,
        'cc': cc or '',
        'bcc': bcc or '',
        'subject': subject,
        'body': body,
        'body_plain': body_plain,
        'body_html': body_html,
        'body_parts': body_parts,
        'mime_version': mime_version,
        'content_type': content_type_header or top_level_type,
        'top_level_content_type': top_level_type,
        'content_transfer_encoding': content_transfer_encoding or '',
        'attachments': '; '.join(attachment_names) if attachment_names else '',
        'attachment_names': attachment_names,
        'attachment_details': attachments_meta,
        'received': received_header,
        'headers': headers_map,
        'headers_decoded': decoded_headers,
        'mime_tree': _build_mime_tree(msg),
    }
