#!/usr/bin/env python3
"""Verify detached CMS signature against exact PDF ByteRange; no PKIX/QES promotion."""
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

def inspect(pdf_path, expected_leaf_pem=None):
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
        signer_file = folder/'signer.pem'
        result = subprocess.run(['openssl', 'cms', '-verify', '-inform', 'DER',
                                 '-in', str(cms), '-content', str(content),
                                 '-binary', '-noverify', '-signer', str(signer_file), '-out', str(folder/'verified.bin')],
                                capture_output=True, timeout=20)
        verified = result.returncode == 0
        signer_bound = False
        if verified and expected_leaf_pem is not None:
            leaf_data = Path(expected_leaf_pem).read_bytes()
            if len(leaf_data) > 256*1024:
                raise ValueError('Expected signer PEM size limit exceeded')
            leaf_match = re.search(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', leaf_data, re.S)
            if leaf_match is None:
                raise ValueError('Expected signer certificate missing')
            expected = x509.load_pem_x509_certificate(leaf_match.group()).fingerprint(hashes.SHA256())
            signer_data = signer_file.read_bytes()
            if len(signer_data) > 256*1024:
                raise ValueError('CMS signer certificate size limit exceeded')
            actual_blocks = re.findall(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', signer_data, re.S)
            signer_bound = len(actual_blocks) == 1 and x509.load_pem_x509_certificate(actual_blocks[0]).fingerprint(hashes.SHA256()) == expected
    return {
        'schema': 'pdfcraft.eidas.pdf-cms-integrity.v1',
        'pdf_sha256': hashlib.sha256(data).hexdigest(),
        'signed_byte_range_sha256': hashlib.sha256(signed).hexdigest(),
        'byte_range_covers_complete_pdf_except_signature': True,
        'cms_detached_signature_integrity_verified': verified,
        'cms_signer_matches_expected_leaf_sha256': signer_bound,
        'cms_signer_chain_trusted': False,
        'trusted_signing_time_verified': False,
        'qualification': 'Indeterminate',
    }

if __name__ == '__main__':
    if len(sys.argv) not in (2, 3):
        raise SystemExit('usage: eidas_pdf_cms_integrity.py signed.pdf [expected-leaf.pem]')
    print(json.dumps(inspect(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else None), indent=2))
