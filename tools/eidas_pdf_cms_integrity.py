#!/usr/bin/env python3
"""Verify detached CMS signature against exact PDF ByteRange; no PKIX/QES promotion."""
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

def inspect(pdf_path):
    path = Path(pdf_path)
    if path.stat().st_size > 64*1024*1024:
        raise ValueError('PDF size limit exceeded')
    data = path.read_bytes()
    ranges = re.findall(rb'/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]', data)
    if len(ranges) != 1:
        raise ValueError('Exactly one ByteRange required')
    a, b, c, d = map(int, ranges[0])
    if a != 0 or b <= 0 or c <= b or d <= 0 or c+d != len(data):
        raise ValueError('Unsupported or malformed ByteRange')
    gap = data[b:c]
    m = re.fullmatch(rb'\s*<([0-9a-fA-F\s]+)>\s*', gap, flags=re.S)
    if not m:
        raise ValueError('ByteRange gap is not a hex CMS Contents object')
    hexdata = re.sub(rb'\s+', b'', m.group(1))
    if len(hexdata) % 2:
        raise ValueError('Odd CMS hex length')
    cms_padded = bytes.fromhex(hexdata.decode('ascii'))
    if not cms_padded or len(cms_padded) > 8*1024*1024:
        raise ValueError('CMS size limit exceeded')
    signed = data[:b] + data[c:c+d]
    with tempfile.TemporaryDirectory() as temp:
        folder = Path(temp)
        cms = folder/'signed.der'
        content = folder/'content.bin'
        cms.write_bytes(cms_padded)
        content.write_bytes(signed)
        result = subprocess.run(['openssl', 'cms', '-verify', '-inform', 'DER',
                                 '-in', str(cms), '-content', str(content),
                                 '-binary', '-noverify', '-out', str(folder/'verified.bin')],
                                capture_output=True, timeout=20)
        verified = result.returncode == 0
    return {
        'schema': 'pdfcraft.eidas.pdf-cms-integrity.v1',
        'pdf_sha256': hashlib.sha256(data).hexdigest(),
        'signed_byte_range_sha256': hashlib.sha256(signed).hexdigest(),
        'byte_range_covers_complete_pdf_except_signature': True,
        'cms_detached_signature_integrity_verified': verified,
        'cms_signer_chain_trusted': False,
        'trusted_signing_time_verified': False,
        'qualification': 'Indeterminate',
    }

if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: eidas_pdf_cms_integrity.py signed.pdf')
    print(json.dumps(inspect(sys.argv[1]), indent=2))
