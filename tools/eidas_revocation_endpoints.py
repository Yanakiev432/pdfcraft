#!/usr/bin/env python3
"""Inventory certificate-declared revocation endpoints; do not infer revocation status."""
import json, re, sys
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID
def inventory(pem_path):
    blocks=re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",Path(pem_path).read_bytes(),re.S)
    if not blocks: raise ValueError("No certificates")
    result=[]
    for block in blocks:
        cert=x509.load_pem_x509_certificate(block)
        ca=cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        ocsp=[];crl=[]
        try:
            aia=cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            ocsp=[a.access_location.value for a in aia if a.access_method==AuthorityInformationAccessOID.OCSP and isinstance(a.access_location,x509.UniformResourceIdentifier)]
        except x509.ExtensionNotFound: pass
        try:
            points=cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
            crl=[name.value for point in points for name in (point.full_name or ()) if isinstance(name,x509.UniformResourceIdentifier)]
        except x509.ExtensionNotFound: pass
        result.append({"is_ca":ca,"ocsp_endpoints_declared":ocsp,"crl_endpoints_declared":crl,
                       "ocsp_response_verified":False,"crl_signature_verified":False,
                       "revocation_status":"Unavailable","qualification":"Indeterminate"})
    return result
if __name__=="__main__":
    if len(sys.argv)!=2: raise SystemExit("usage: eidas_revocation_endpoints.py certs.pem")
    print(json.dumps(inventory(sys.argv[1]),indent=2))
