#!/usr/bin/env python3
"""Verify issuer-signed CRL evidence for a certificate at a supplied evaluation time.
Does not establish trusted signing time or historical completeness."""
import datetime as dt, json, re, sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, dsa, ed25519, ed448
def utc(value):
    parsed=dt.datetime.fromisoformat(value.replace("Z","+00:00"))
    if parsed.tzinfo is None: raise ValueError("Timezone required")
    return parsed.astimezone(dt.timezone.utc)
def certs(path):
    data=Path(path).read_bytes()
    blocks=re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",data,re.S)
    if not blocks: raise ValueError("Missing PEM certificates")
    return [x509.load_pem_x509_certificate(x) for x in blocks]
def signature_valid(crl, issuer):
    key=issuer.public_key()
    try:
        if isinstance(key,rsa.RSAPublicKey): key.verify(crl.signature,crl.tbs_certlist_bytes,padding.PKCS1v15(),crl.signature_hash_algorithm)
        elif isinstance(key,ec.EllipticCurvePublicKey): key.verify(crl.signature,crl.tbs_certlist_bytes,ec.ECDSA(crl.signature_hash_algorithm))
        elif isinstance(key,dsa.DSAPublicKey): key.verify(crl.signature,crl.tbs_certlist_bytes,crl.signature_hash_algorithm)
        elif isinstance(key,(ed25519.Ed25519PublicKey,ed448.Ed448PublicKey)): key.verify(crl.signature,crl.tbs_certlist_bytes)
        else: return False
        return True
    except Exception: return False
def inspect(pem, crl_file, at_text):
    leaf,issuer=certs(pem)[:2]
    if leaf.issuer != issuer.subject: raise ValueError("Issuer subject mismatch")
    data=Path(crl_file).read_bytes()
    crl=x509.load_pem_x509_crl(data) if data.lstrip().startswith(b"-----BEGIN") else x509.load_der_x509_crl(data)
    issuer_match=crl.issuer==issuer.subject
    sig_ok=issuer_match and signature_valid(crl,issuer)
    at=utc(at_text)
    last=crl.last_update.replace(tzinfo=dt.timezone.utc)
    next_time=crl.next_update.replace(tzinfo=dt.timezone.utc) if crl.next_update else None
    window=bool(next_time and last<=at<next_time)
    revoked=crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
    status="Unavailable"
    if sig_ok and window:
        status="Revoked" if revoked and revoked.revocation_date.replace(tzinfo=dt.timezone.utc)<=at else "GoodAtEvaluationTime"
    return {"crl_issuer_matches":issuer_match,"crl_signature_verified":sig_ok,
            "crl_valid_at_evaluation_time":window,"revocation_status":status,
            "trusted_evaluation_time":False,"issuer_path_verified":False,
            "qualification":"Indeterminate"}
if __name__=="__main__":
    if len(sys.argv)!=4: raise SystemExit("usage: eidas_crl_verify.py certs.pem issuer.crl ISO8601")
    print(json.dumps(inspect(*sys.argv[1:]),indent=2))
