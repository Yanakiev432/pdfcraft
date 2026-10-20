#!/usr/bin/env python3
"""Read-only untrusted EU LOTL inventory. NOT XMLDSig verification."""
import hashlib, json, sys, xml.etree.ElementTree as ET
from pathlib import Path
def inventory(path):
    raw = Path(path).read_bytes()
    if not raw or len(raw) > 8388608 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("Unsafe XML input")
    root = ET.fromstring(raw)
    ns = {"tsl": "http://uri.etsi.org/02231/v2#", "ds": "http://www.w3.org/2000/09/xmldsig#"}
    if root.tag != "{http://uri.etsi.org/02231/v2#}TrustServiceStatusList":
        raise ValueError("Unexpected XML root")
    pointers = []
    for pointer in root.findall(".//tsl:OtherTSLPointer", ns):
        territories = [n.text for n in pointer.findall(".//tsl:SchemeTerritory", ns)]
        if "BG" in territories:
            pointers.append({"territory": "BG", "locations_unverified": [n.text for n in pointer.findall("tsl:TSLLocation", ns)]})
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "xml_signature_elements": len(root.findall(".//ds:Signature", ns)),
            "bulgarian_pointers_unverified": pointers,
            "lotl_signature_verified": False, "national_signature_verified": False,
            "qualification_verdict": "Indeterminate",
            "warning": "Inventory only: signatures and URLs have NOT been authenticated."}
if __name__ == "__main__":
    print(json.dumps(inventory(sys.argv[1]), indent=2))
