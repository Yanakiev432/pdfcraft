#!/usr/bin/env python3
"""Verify XMLDSig cryptography against an embedded UNTRUSTED public certificate.
This is NOT EU LOTL trust establishment or eIDAS qualification."""
import base64, json, os, subprocess, sys, xml.etree.ElementTree as ET
from pathlib import Path
from tempfile import TemporaryDirectory
from eidas_xml_reference_audit import audit
DS = "{http://www.w3.org/2000/09/xmldsig#}"
XMLSEC = Path(os.environ.get("PDFCRAFT_XMLSEC1", "/usr/bin/xmlsec1"))
def verify(path):
    path = Path(path).resolve()
    structural = audit(path)
    root = ET.parse(path).getroot()
    certificates = root.findall(".//" + DS + "Signature/" + DS + "KeyInfo/" + DS + "X509Data/" + DS + "X509Certificate")
    if len(certificates) != 1 or not certificates[0].text:
        raise ValueError("Expected exactly one embedded signer certificate")
    der = base64.b64decode("".join(certificates[0].text.split()), validate=True)
    if len(der) > 32768: raise ValueError("Certificate too large")
    with TemporaryDirectory() as directory:
        pem = Path(directory) / "untrusted.pem"
        encoded = base64.b64encode(der).decode("ascii")
        pem.write_text("-----BEGIN CERTIFICATE-----\n" + "\n".join(encoded[i:i+64] for i in range(0,len(encoded),64)) + "\n-----END CERTIFICATE-----\n")
        command = [str(XMLSEC), "--verify", "--enabled-reference-uris", "empty,same-doc",
                   "--id-attr:Id", "http://uri.etsi.org/01903/v1.3.2#:SignedProperties",
                   "--pubkey-cert-pem", str(pem), str(path)]
        env = dict(os.environ)
        result = subprocess.run(command, capture_output=True, text=True, timeout=30, env=env)
    return {"structural_check": structural["references_structurally_acceptable"],
            "cryptography_verified_with_untrusted_embedded_key": result.returncode == 0 and "SignedInfo References (ok/all): 2/2" in result.stderr,
            "trusted_list_signer_authenticated": False, "qualification": "Indeterminate"}
if __name__ == "__main__":
    if len(sys.argv) != 2: raise SystemExit("usage: eidas_xmlsig_crypto_check.py FILE.xml")
    print(json.dumps(verify(sys.argv[1]), indent=2))
