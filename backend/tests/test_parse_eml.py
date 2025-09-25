import base64
import hashlib
from email.message import EmailMessage

from backend.ingestion.parse_eml import parse_eml


def test_parse_plain_text_email(tmp_path):
    msg = EmailMessage()
    msg['From'] = 'Alice <alice@example.com>'
    msg['To'] = 'Bob <bob@example.com>'
    msg['Subject'] = 'Simple'
    msg.set_content('Hello world')

    eml_path = tmp_path / 'simple.eml'
    eml_path.write_bytes(msg.as_bytes())

    parsed = parse_eml(str(eml_path))

    assert parsed['subject'] == 'Simple'
    assert parsed['body'] == 'Hello world'
    assert parsed['body_plain'] == 'Hello world'
    assert parsed['attachments'] == ''
    assert parsed['attachment_details'] == []
    assert parsed['mime_tree']['content_type'] == 'text/plain'
    assert parsed['authentication_results'] == []
    assert parsed['received_spf'] == []


def test_parse_multipart_alternative_handles_charsets(tmp_path):
    msg = EmailMessage()
    msg['From'] = 'Carol <carol@example.com>'
    msg['To'] = 'Dan <dan@example.com>'
    msg['Subject'] = 'Charset'

    plain_text = 'Olá Mundo'
    html_text = '<html><body><p>Olá Mundo</p></body></html>'

    msg.set_content(plain_text, charset='iso-8859-1')
    msg.add_alternative(html_text, subtype='html')

    eml_path = tmp_path / 'multipart.eml'
    eml_path.write_bytes(msg.as_bytes())

    parsed = parse_eml(str(eml_path))

    assert parsed['body_plain'] == plain_text
    assert 'Olá Mundo' in parsed['body_html']
    assert parsed['body'] == plain_text
    assert parsed['attachment_details'] == []
    assert parsed['top_level_content_type'] == 'multipart/alternative'
    sources = {part['source'] for part in parsed['body_parts']}
    assert 'text/plain' in sources
    assert 'text/html' in sources


def test_parse_extracts_attachments_with_metadata(tmp_path):
    msg = EmailMessage()
    msg['From'] = 'Eve <eve@example.com>'
    msg['To'] = 'Frank <frank@example.com>'
    msg['Subject'] = 'Attachments'
    msg.set_content('See attachments.')

    note_bytes = b'plain attachment content'
    image_bytes = bytes.fromhex('89504E470D0A1A0A') + bytes([0]) * 10

    msg.add_attachment(note_bytes, maintype='text', subtype='plain', filename='note.txt')
    msg.add_attachment(image_bytes, maintype='image', subtype='png', filename='graphic.png')

    for part in msg.iter_attachments():
        if part.get_filename() == 'graphic.png':
            part.replace_header('Content-Disposition', 'inline; filename="graphic.png"')
            part.add_header('Content-ID', '<img1>')

    eml_path = tmp_path / 'attachments.eml'
    eml_path.write_bytes(msg.as_bytes())

    parsed = parse_eml(str(eml_path))

    assert parsed['attachments'] == 'note.txt; graphic.png'
    assert len(parsed['attachment_details']) == 2

    details = {att['filename']: att for att in parsed['attachment_details']}

    note_meta = details['note.txt']
    assert note_meta['size'] == len(note_bytes)
    assert note_meta['payload_included'] is True
    assert note_meta['checksum_sha256'] == hashlib.sha256(note_bytes).hexdigest()
    assert base64.b64decode(note_meta['payload_base64']) == note_bytes

    image_meta = details['graphic.png']
    assert image_meta['is_inline'] is True
    assert image_meta['content_id'] == 'img1'
    assert image_meta['payload_included'] is True
    assert base64.b64decode(image_meta['payload_base64']) == image_bytes

def test_parse_eml_includes_authentication_metadata(tmp_path):
    msg = EmailMessage()
    msg['From'] = 'Sec Team <security@example.com>'
    msg['To'] = 'User <user@example.com>'
    msg['Subject'] = 'Alert'
    msg['Authentication-Results'] = (
        'Authentication-Results: auth.example; '
        'spf=pass smtp.mailfrom=example.com; '
        'dkim=pass header.d=example.com header.s=s1'
    )
    msg['Received-SPF'] = (
        'Received-SPF: pass (policy) client-ip=203.0.113.9; '
        'envelope-from=example.com; helo=mail.example.com'
    )
    msg.set_content('Just a drill')

    eml_path = tmp_path / 'auth.eml'
    eml_path.write_bytes(msg.as_bytes())

    parsed = parse_eml(str(eml_path))

    auth_results = parsed['authentication_results']
    assert len(auth_results) == 1
    methods = {entry['method']: entry for entry in auth_results[0]['results']}
    assert methods['spf']['result'] == 'pass'
    assert methods['dkim']['properties']['header.d'] == 'example.com'

    received_spf = parsed['received_spf']
    assert received_spf[0]['result'] == 'pass'
    assert received_spf[0]['properties']['client-ip'] == '203.0.113.9'
