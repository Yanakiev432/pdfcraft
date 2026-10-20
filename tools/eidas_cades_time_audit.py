#!/usr/bin/env python3
"""Bounded CMS signed/unsigned attribute inventory; never claims trusted time."""
import json
import re
import subprocess
import sys
from pathlib import Path

OID = {
    'signing_time': '1.2.840.113549.1.9.5',
    'signature_timestamp': '1.2.840.113549.1.9.16.2.14',
    'content_timestamp': '1.2.840.113549.1.9.16.2.20',
    'archive_timestamp_v3': '0.4.0.1733.2.4',
    'signing_certificate_v2': '1.2.840.113549.1.9.16.2.47',
    'message_digest': '1.2.840.113549.1.9.4',
}
def inspect(cms_path):
    path = Path(cms_path)
    if path.stat().st_size > 8*1024*1024:
        raise ValueError('CMS size limit exceeded')
    result = subprocess.run(['openssl', 'cms', '-inform', 'DER', '-in', str(path),
                             '-cmsout', '-print'], capture_output=True, text=True, timeout=15,
                            check=True)
    raw = result.stdout
    if len(raw) > 2*1024*1024:
        raise ValueError('CMS textual dump limit exceeded')
    # Parse only attribute object declarations, not arbitrary text in certificates.
    found = set(re.findall(r'^\s*object: [^\n]*\(([0-9.]+)\)\s*$', raw, flags=re.M))
    attrs = {name: oid in found for name, oid in OID.items()}
    return {
        'schema': 'pdfcraft.eidas.cades-time-audit.v1',
        'attributes_present_unverified': attrs,
        'trusted_timestamp_token_verified': False,
        'trusted_signing_time_verified': False,
        'qscd_independently_verified': False,
        'qualification': 'Indeterminate',
    }
if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: eidas_cades_time_audit.py signed-cms.der')
    print(json.dumps(inspect(sys.argv[1]), indent=2))
