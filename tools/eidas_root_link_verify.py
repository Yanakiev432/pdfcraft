#!/usr/bin/env python3
"""Offline root link verification. A caller-provided root pin is not an external trust anchor."""
import hashlib
import json
import sys
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from eidas_crl_verify import certs, utc
from eidas_certificate_path_verify import _signature_ok, _valid_at, inspect as leaf_link

def inspect(bundle_pem, root_pem, pinned_root_sha256, evaluation_time):
    if not isinstance(pinned_root_sha256, str) or len(pinned_root_sha256) != 64:
        raise ValueError('A SHA256 root pin is mandatory')
    link = leaf_link(bundle_pem, evaluation_time)
    pair = certs(bundle_pem)
    roots = certs(root_pem)
    if len(pair) != 2 or len(roots) != 1:
        raise ValueError('Exactly leaf, intermediate and one root required')
    issuer, root = pair[1], roots[0]
    actual = hashlib.sha256(root.public_bytes(serialization.Encoding.DER)).hexdigest()
    pin_ok = actual == pinned_root_sha256.lower()
    signature_ok = issuer.issuer == root.subject and _signature_ok(issuer, root)
    try:
        constraints = root.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = root.extensions.get_extension_for_class(x509.KeyUsage).value
        ca_ok = constraints.ca and usage.key_cert_sign
        issuer_aki = issuer.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
        root_ski = root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        aki_ok = issuer_aki.key_identifier is not None and issuer_aki.key_identifier == root_ski.digest
    except x509.ExtensionNotFound:
        ca_ok, aki_ok = False, False
    root_valid = _valid_at(root, utc(evaluation_time))
    local_three_cert_link = bool(link['local_link_verified'] and pin_ok and signature_ok and ca_ok and aki_ok and root_valid)
    return {
        'schema': 'pdfcraft.eidas.root-link.v1',
        'root_der_sha256': actual,
        'caller_root_pin_matches': pin_ok,
        'issuer_signature_by_root_verified': signature_ok,
        'root_ca_constraints_verified': bool(ca_ok),
        'issuer_aki_matches_root_ski': aki_ok,
        'root_valid_at_evaluation_time': root_valid,
        'local_three_certificate_link_verified': local_three_cert_link,
        'independent_root_pin_provenance_verified': False,
        'full_certificate_path_verified': False,
        'qualification': 'Indeterminate',
    }

if __name__ == '__main__':
    if len(sys.argv) != 5:
        raise SystemExit('usage: eidas_root_link_verify.py leaf-issuer.pem root.pem ROOT_SHA256 ISO8601')
    print(json.dumps(inspect(*sys.argv[1:]), indent=2))
