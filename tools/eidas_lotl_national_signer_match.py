#!/usr/bin/env python3
"""Match national TSL signer DER to untrusted EU LOTL national-list pointers.
This is a trust-chain candidate only, NOT LOTL authentication."""
import base64, hashlib, json, sys, xml.etree.ElementTree as ET
from pathlib import Path
NS = {"t": "http://uri.etsi.org/02231/v2#", "d": "http://www.w3.org/2000/09/xmldsig#"}
def load(path):
    data = Path(path).read_bytes()
    if not data or len(data) > 8388608 or b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper(): raise ValueError("Unsafe XML")
    root = ET.fromstring(data)
    if root.tag != "{http://uri.etsi.org/02231/v2#}TrustServiceStatusList": raise ValueError("Unexpected XML root")
    return root
def der(node):
    if node is None or not node.text: raise ValueError("Missing X509 certificate")
    return base64.b64decode("".join(node.text.split()), validate=True)
def match(lotl, national, territory="BG"):
    eu, local = load(lotl), load(national)
    signer = local.find(".//d:Signature/d:KeyInfo/d:X509Data/d:X509Certificate", NS)
    national_der = der(signer)
    results = []
    for pointer in eu.findall(".//t:OtherTSLPointer", NS):
        if pointer.findtext(".//t:SchemeTerritory", default="", namespaces=NS) != territory: continue
        location = pointer.findtext("t:TSLLocation", default="", namespaces=NS)
        certificates = [der(x) for x in pointer.iter() if x.tag.endswith("}X509Certificate")]
        results.append({"location_unverified": location, "matching_signer_certificate": national_der in certificates,
                        "listed_certificates": len(certificates)})
    return {"territory": territory, "national_signer_sha256": hashlib.sha256(national_der).hexdigest(),
            "pointers_unverified": results, "lotl_authenticated": False, "national_list_authenticated": False,
            "qualification": "Indeterminate"}
if __name__ == "__main__":
    if len(sys.argv) != 3: raise SystemExit("usage: eidas_lotl_national_signer_match.py EU_LOTL.xml NATIONAL_TSL.xml")
    print(json.dumps(match(sys.argv[1], sys.argv[2]), indent=2))
