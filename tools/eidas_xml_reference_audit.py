#!/usr/bin/env python3
"""Untrusted XMLDSig reference audit. Does NOT verify signatures or trust."""
import json, sys, xml.etree.ElementTree as ET
from pathlib import Path
DS = "{http://www.w3.org/2000/09/xmldsig#}"
TSL = "{http://uri.etsi.org/02231/v2#}TrustServiceStatusList"
ALLOWED = {"http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"}
def audit(path):
    data = Path(path).read_bytes()
    if not data or len(data) > 8388608 or b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError("unsafe XML")
    root = ET.fromstring(data)
    if root.tag != TSL: raise ValueError("wrong TSL root")
    ids = {}
    for node in root.iter():
        for key, value in node.attrib.items():
            if key in ("Id", "ID", "id", "{http://www.w3.org/XML/1998/namespace}id"):
                if value in ids: raise ValueError("duplicate XML ID")
                ids[value] = node
    signatures = root.findall(".//" + DS + "Signature")
    if len(signatures) != 1: raise ValueError("expected one XML signature")
    signed_info = signatures[0].find(DS + "SignedInfo")
    if signed_info is None: raise ValueError("missing SignedInfo")
    references = signed_info.findall(DS + "Reference")
    if len(references) != 2: raise ValueError("unexpected reference count")
    found = []
    for ref in references:
        uri = ref.get("URI")
        if uri is None or (uri != "" and (not uri.startswith("#") or uri[1:] not in ids)):
            raise ValueError("external or unresolved reference")
        transforms = ref.find(DS + "Transforms")
        algorithms = [t.get("Algorithm") for t in transforms] if transforms is not None else []
        if any(a not in ALLOWED for a in algorithms): raise ValueError("unsupported transform")
        if ref.find(DS + "DigestMethod") is None or ref.find(DS + "DigestValue") is None:
            raise ValueError("missing reference digest")
        found.append({"uri": uri, "transforms": algorithms})
    if found[0]["uri"] != "" or not found[1]["uri"].startswith("#"):
        raise ValueError("unexpected reference layout")
    return {"references_structurally_acceptable": True, "references_unverified": found,
            "xml_signature_verified": False, "qualification": "Indeterminate"}
if __name__ == "__main__":
    print(json.dumps(audit(sys.argv[1]), indent=2))
