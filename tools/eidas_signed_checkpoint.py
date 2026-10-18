#!/usr/bin/env python3
"""Detached Ed25519 checkpoint integrity verification; replay resistance is external."""
import hashlib
import json
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from eidas_rollback_guard import check_authenticated_acceptance

MAX_CHECKPOINT_BYTES = 65536

def verified_checkpoint_bytes(checkpoint_path, signature_path, public_key_path, expected_key_sha256):
    """Verify exact checkpoint bytes against an independently pinned DER SPKI digest."""
    if not isinstance(expected_key_sha256, str) or len(expected_key_sha256) != 64 or any(c not in '0123456789abcdef' for c in expected_key_sha256):
        raise ValueError('Invalid pinned public-key SHA-256')
    with open(checkpoint_path, 'rb') as f:
        raw = f.read(MAX_CHECKPOINT_BYTES + 1)
    if not raw or len(raw) > MAX_CHECKPOINT_BYTES:
        raise ValueError('Empty or oversized checkpoint')
    signature = Path(signature_path).read_bytes()
    if len(signature) != 64:
        raise ValueError('Invalid Ed25519 signature length')
    key = serialization.load_pem_public_key(Path(public_key_path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError('Expected Ed25519 public key')
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if hashlib.sha256(der).hexdigest() != expected_key_sha256:
        raise ValueError('Public key does not match independent pin')
    try:
        key.verify(signature, raw)
    except InvalidSignature as exc:
        raise ValueError('Invalid checkpoint signature') from exc
    baseline = json.loads(raw)
    if not isinstance(baseline, dict) or baseline.get('schema') != 'pdfcraft.eidas.rollback-snapshot.v1':
        raise ValueError('Invalid checkpoint schema')
    return baseline, raw

def verified_checkpoint(checkpoint_path, signature_path, public_key_path, expected_key_sha256):
    baseline, _ = verified_checkpoint_bytes(checkpoint_path, signature_path, public_key_path, expected_key_sha256)
    return baseline

def check_signed_baseline(acceptance_report, checkpoint_path, signature_path, public_key_path, expected_key_sha256):
    baseline = verified_checkpoint(checkpoint_path, signature_path, public_key_path, expected_key_sha256)
    result = check_authenticated_acceptance(acceptance_report, baseline)
    result['baseline_signature_verified'] = True
    result['baseline_signing_key_pin_verified'] = True
    # A valid signature does NOT prevent replay of an older signed checkpoint.
    result['baseline_provenance_verified'] = False
    result['rollback_protection_verified'] = False
    result['qualification'] = 'Indeterminate'
    return result