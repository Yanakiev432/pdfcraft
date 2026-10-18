#!/usr/bin/env python3
"""Opt-in, loopback-only independent EU DSS validator. No signed files leave this host."""
import base64
import hashlib
import ipaddress
import json
import sys
import os
import urllib.parse
import urllib.request
from pathlib import Path

MAX_PDF = 64 * 1024 * 1024
MAX_RESPONSE = 16 * 1024 * 1024
ENDPOINT = 'http://127.0.0.1:8080/services/rest/validation/validateSignature'

def validate(pdf_path, endpoint=ENDPOINT, timeout=180):
    u = urllib.parse.urlsplit(endpoint)
    try:
        loopback = ipaddress.ip_address(u.hostname).is_loopback
    except (ValueError, TypeError):
        loopback = False
    if u.scheme != 'http' or not loopback or u.username or u.password or u.fragment or u.query:
        raise ValueError('DSS endpoint must be an explicit HTTP loopback IP address')
    if u.port is None or u.path != '/services/rest/validation/validateSignature':
        raise ValueError('Unexpected DSS validation endpoint path')
    pdf = Path(pdf_path)
    if pdf.stat().st_size > MAX_PDF:
        raise ValueError('PDF size limit exceeded')
    data = pdf.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    body = json.dumps({'signedDocument': {
        'bytes': base64.b64encode(data).decode('ascii'),
        'name': 'document.pdf'}}).encode('utf-8')
    req = urllib.request.Request(endpoint, body, {'Content-Type': 'application/json'}, method='POST')
    # Disable proxy routing and redirects, even if the OS has proxy settings.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise ValueError('DSS redirects are forbidden')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise ValueError('DSS returned non-200 status')
        raw = resp.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise ValueError('DSS report size limit exceeded')
    report = json.loads(raw)
    simple = report.get('SimpleReport', report.get('simpleReport'))
    if not isinstance(simple, dict):
        raise ValueError('DSS SimpleReport missing')
    signatures = simple.get('signatureOrTimestampOrEvidenceRecord')
    if not isinstance(signatures, list):
        raise ValueError('DSS signatures array missing')
    actual = [item.get('Signature') for item in signatures if isinstance(item, dict) and isinstance(item.get('Signature'), dict)]
    if len(actual) != 1 or simple.get('SignaturesCount') != 1 or simple.get('ValidSignaturesCount') != 1:
        raise ValueError('DSS single-signature acceptance criteria not met')
    sig = actual[0]
    level = sig.get('SignatureLevel')
    level = level.get('value') if isinstance(level, dict) else None
    indication = sig.get('Indication')
    accepted = indication == 'TOTAL_PASSED' and level == 'QESig'
    return {
        'schema': 'pdfcraft.eidas.independent-dss.v1',
        'pdf_sha256': digest,
        'dss_report_sha256': hashlib.sha256(raw).hexdigest(),
        'dss_validation_time': simple.get('ValidationTime'),
        'dss_indication': indication,
        'dss_signature_level': level,
        'dss_signature_format': sig.get('SignatureFormat'),
        'independent_dss_qes_pass': accepted,
        'native_qes_pass': False,
        'trusted_signing_time_proven_by_this_adapter': False,
    }, raw

if __name__ == '__main__':
    if len(sys.argv) not in (2, 3):
        raise SystemExit('usage: eidas_dss_local_verify.py signed.pdf [private-report-output.json]')
    result, raw = validate(sys.argv[1], os.environ.get('PDFCRAFT_DSS_LOCAL_ENDPOINT', ENDPOINT))
    if len(sys.argv) == 3:
        output = Path(sys.argv[2])
        if output.exists():
            raise SystemExit('refusing to overwrite existing private report')
        output.write_bytes(raw)
    print(json.dumps(result, indent=2))
