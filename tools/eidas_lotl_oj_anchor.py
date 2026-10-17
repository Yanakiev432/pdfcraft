#!/usr/bin/env python3
"""Check EU LOTL signer against SHA-256 pins from OJ C/2026/1944.
The official-journal pins are independent of the input XML.
Source: https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:52026XC01944
This does not replace pivot/revocation/time-policy validation."""
import base64, hashlib, json, os, subprocess, sys, xml.etree.ElementTree as ET
from pathlib import Path
from tempfile import TemporaryDirectory
from eidas_xml_reference_audit import audit
PINS = frozenset((
    "c0641c4f7d56c431b1c924742db7fce9c1eef7d7fd212113a2768486b3abcdc5",
    "e0a620fbb6747362bb933ac44169d676a553444716cf5f31605f12a22b8396b1",
    "df7e29360c34b2b8d6d5f40325c1d4d12c9922cecd33b7407674a74b2b3ca1e5",
    "b63d416744e7098bf9ec2caa596a93bc2468e37f8284ba65ecc061711bcbaa18",
    "236103f03a8031ae8f47f9059bf8de38564cdbfebedde4a597d50f8980aa653b",
    "d2064fdd70f6982dcc516b86d9d5c56aea939417c624b2e478c0b29de54f8474",
))
DS = "{http://www.w3.org/2000/09/xmldsig#}"
def verify(path):
    path = Path(path).resolve()
    audit(path)
    root = ET.parse(path).getroot()
    certs = root.findall(".//" + DS + "Signature/" + DS + "KeyInfo/" + DS + "X509Data/" + DS + "X509Certificate")
    if len(certs) != 1 or not certs[0].text: raise ValueError("Expected one signer certificate")
    der = base64.b64decode("".join(certs[0].text.split()), validate=True)
    digest = hashlib.sha256(der).hexdigest()
    pinned = digest in PINS
    if not pinned:
        return {"signer_sha256": digest, "official_journal_pin_match": False,
                "xmldsig_valid_with_pinned_signer": False, "lotl_authenticated": False}
    with TemporaryDirectory() as d:
        cert = Path(d) / "oj-pinned.pem"
        encoded = base64.b64encode(der).decode("ascii")
        cert.write_text("-----BEGIN CERTIFICATE-----\n" + "\n".join(encoded[i:i+64] for i in range(0,len(encoded),64)) + "\n-----END CERTIFICATE-----\n")
        executable = os.environ.get("PDFCRAFT_XMLSEC1", "xmlsec1")
        args = [executable, "--verify", "--enabled-reference-uris", "empty,same-doc",
                "--id-attr:Id", "http://uri.etsi.org/01903/v1.3.2#:SignedProperties",
                "--pubkey-cert-pem", str(cert), str(path)]
        result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    valid = result.returncode == 0 and "SignedInfo References (ok/all): 2/2" in result.stderr
    return {"signer_sha256": digest, "official_journal_pin_match": True,
            "xmldsig_valid_with_pinned_signer": valid,
            "lotl_authenticated": valid, "pivot_and_temporal_policy_verified": False,
            "qualification": "Indeterminate"}
if __name__ == "__main__":
    print(json.dumps(verify(sys.argv[1]), indent=2))
