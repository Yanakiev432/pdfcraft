#!/usr/bin/env python3
"""Offline leaf-to-issuer cryptographic link; no independent trust anchor."""
import datetime as dt
import hashlib
import json
import sys
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448, padding
from eidas_crl_verify import certs, utc

def _signature_ok(leaf, issuer):
    key = issuer.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(leaf.signature, leaf.tbs_certificate_bytes, padding.PKCS1v15(), leaf.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))
        elif isinstance(key, dsa.DSAPublicKey):
            key.verify(leaf.signature, leaf.tbs_certificate_bytes, leaf.signature_hash_algorithm)
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key.verify(leaf.signature, leaf.tbs_certificate_bytes)
        else:
            return False
        return True
    except Exception:
        return False

def _valid_at(cert, at):
    before = cert.not_valid_before.replace(tzinfo=dt.timezone.utc)
    after = cert.not_valid_after.replace(tzinfo=dt.timezone.utc)
    return before <= at <= after

def inspect(pem, evaluation_time):
    chain = certs(pem)
    if len(chain) != 2:
        raise ValueError('Exactly leaf and issuer certificates required')
    leaf, issuer = chain
    at = utc(evaluation_time)
    name_ok = leaf.issuer == issuer.subject
    try:
        ca = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
        ca_ok = ca.ca is True
    except x509.ExtensionNotFound:
        ca_ok = False
    try:
        usage = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
        ca_ok = ca_ok and usage.key_cert_sign
    except x509.ExtensionNotFound:
        ca_ok = False
    try:
        leaf_ca = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        ca_ok = ca_ok and not leaf_ca
    except x509.ExtensionNotFound:
        ca_ok = False
    try:
        aki = leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
        ski = issuer.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        key_id_ok = aki.key_identifier is not None and aki.key_identifier == ski.digest
    except x509.ExtensionNotFound:
        key_id_ok = False
    valid = _valid_at(leaf, at) and _valid_at(issuer, at)
    signature_ok = name_ok and _signature_ok(leaf, issuer)
    return {
        'schema': 'pdfcraft.eidas.certificate-link.v1',
        'issuer_der_sha256': hashlib.sha256(issuer.public_bytes(serialization.Encoding.DER)).hexdigest(),
        'issuer_subject_matches': name_ok,
        'issuer_ca_constraints_verified': bool(ca_ok),
        'authority_key_identifier_matches': key_id_ok,
        'both_certificates_valid_at_evaluation_time': valid,
        'leaf_certificate_signature_verified': signature_ok,
        'local_link_verified': bool(name_ok and ca_ok and key_id_ok and valid and signature_ok),
        'independent_trust_anchor_verified': False,
        'full_certificate_path_verified': False,
        'trusted_signing_time_verified': False,
        'qualification': 'Indeterminate',
    }

if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: eidas_certificate_path_verify.py leaf-and-issuer.pem ISO8601')
    print(json.dumps(inspect(sys.argv[1], sys.argv[2]), indent=2))
