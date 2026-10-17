#!/usr/bin/env python3
"""Conservative offline OCSP verification relative to an explicitly supplied issuer."""
import datetime as dt
import json
import sys
from pathlib import Path
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448, padding
from eidas_crl_verify import certs, utc

def verify_signature(key, signature, data, algorithm):
    try:
        if isinstance(key, rsa.RSAPublicKey): key.verify(signature, data, padding.PKCS1v15(), algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey): key.verify(signature, data, ec.ECDSA(algorithm))
        elif isinstance(key, dsa.DSAPublicKey): key.verify(signature, data, algorithm)
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)): key.verify(signature, data)
        else: return False
        return True
    except Exception: return False

def inspect(pem, response_file, at_text):
    leaf, issuer = certs(pem)[:2]
    at = utc(at_text)
    result = dict(ocsp_response_success=False, certificate_id_matches=False,
                  response_signature_verified=False, responder_authorized=False,
                  response_fresh_at_evaluation_time=False, revocation_status="Unavailable",
                  issuer_path_verified=False, trusted_evaluation_time=False, qualification="Indeterminate")
    response = ocsp.load_der_ocsp_response(Path(response_file).read_bytes())
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL: return result
    result["ocsp_response_success"] = True
    if leaf.issuer != issuer.subject: return result
    try:
        expected = ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, response.hash_algorithm).build()
        match = (response.serial_number == expected.serial_number and
                 response.issuer_name_hash == expected.issuer_name_hash and
                 response.issuer_key_hash == expected.issuer_key_hash)
    except (ValueError, TypeError, x509.UnsupportedGeneralNameType): return result
    result["certificate_id_matches"] = match
    if not match: return result
    candidates = [issuer, *response.certificates]
    for signer in candidates:
        responder_matches = (response.responder_name is not None and response.responder_name == signer.subject)
        if response.responder_key_hash is not None:
            responder_matches = responder_matches or response.responder_key_hash == x509.SubjectKeyIdentifier.from_public_key(signer.public_key()).digest
        if not responder_matches: continue
        if not verify_signature(signer.public_key(), response.signature, response.tbs_response_bytes, response.signature_hash_algorithm): continue
        result["response_signature_verified"] = True
        authorized = signer == issuer
        if not authorized and signer.issuer == issuer.subject:
            valid_cert = (signer.not_valid_before.replace(tzinfo=dt.timezone.utc) <= at < signer.not_valid_after.replace(tzinfo=dt.timezone.utc))
            valid_sig = verify_signature(issuer.public_key(), signer.signature, signer.tbs_certificate_bytes, signer.signature_hash_algorithm)
            try: eku = ExtendedKeyUsageOID.OCSP_SIGNING in signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            except x509.ExtensionNotFound: eku = False
            try: ku = signer.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature
            except x509.ExtensionNotFound: ku = False
            authorized = valid_cert and valid_sig and eku and ku
        result["responder_authorized"] = authorized
        if authorized: break
    if not result["responder_authorized"]: return result
    if any(ext.critical for ext in response.extensions) or any(ext.critical for ext in response.single_extensions): return result
    this = response.this_update.replace(tzinfo=dt.timezone.utc)
    next_at = response.next_update.replace(tzinfo=dt.timezone.utc) if response.next_update else None
    produced = response.produced_at.replace(tzinfo=dt.timezone.utc)
    fresh = bool(next_at and this <= at < next_at and produced <= at)
    result["response_fresh_at_evaluation_time"] = fresh
    if not fresh: return result
    if response.certificate_status == ocsp.OCSPCertStatus.GOOD: result["revocation_status"] = "GoodAtEvaluationTime"
    elif response.certificate_status == ocsp.OCSPCertStatus.REVOKED:
        revoked_at = response.revocation_time.replace(tzinfo=dt.timezone.utc)
        result["revocation_status"] = "Revoked" if revoked_at <= at else "IndeterminateHistorical"
    return result

if __name__ == "__main__":
    if len(sys.argv) != 4: raise SystemExit("usage: eidas_ocsp_verify.py certs.pem response.der ISO8601")
    print(json.dumps(inspect(*sys.argv[1:]), indent=2))
