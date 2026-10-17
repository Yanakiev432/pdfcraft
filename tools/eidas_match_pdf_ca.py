#!/usr/bin/env python3
"""Match PDF CMS embedded CA certificate to untrusted TSL service DER bytes.
Never assert eIDAS qualification from this comparison."""
import base64, hashlib, json, re, subprocess, sys, tempfile, xml.etree.ElementTree as ET
from pathlib import Path
NS = {"t": "http://uri.etsi.org/02231/v2#"}
def match(pdf, tsl):
    pdf_bytes = Path(pdf).read_bytes()
    if len(pdf_bytes) > 64 * 1024 * 1024: raise ValueError("PDF too large")
    contents = re.findall(rb"/Contents\s*<([0-9a-fA-F\s]+)>", pdf_bytes)
    if len(contents) != 1: raise ValueError("Expected exactly one PDF hex signature")
    cms = bytes.fromhex(contents[0].decode("ascii"))
    with tempfile.TemporaryDirectory() as d:
        source, dest = Path(d)/"cms.der", Path(d)/"certs.pem"
        source.write_bytes(cms)
        result = subprocess.run(["openssl", "cms", "-cmsout", "-inform", "DER", "-in", str(source), "-certsout", str(dest), "-out", "/dev/null"], capture_output=True, timeout=20)
        if result.returncode != 0: raise ValueError("Unable to parse CMS certificates")
        pem = dest.read_bytes()
    embedded = [base64.b64decode(re.sub(rb"\s", b"", part)) for part in re.findall(rb"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem, re.S)]
    data = Path(tsl).read_bytes()
    if not data or len(data) > 8388608 or b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper(): raise ValueError("Unsafe TSL XML")
    root = ET.fromstring(data)
    matches = []
    for tsp in root.findall(".//t:TrustServiceProvider", NS):
        provider = tsp.findtext("t:TSPInformation/t:TSPName/t:Name", default="", namespaces=NS)
        for service in tsp.findall("t:TSPServices/t:TSPService", NS):
            info = service.find("t:ServiceInformation", NS)
            if info is None: continue
            name = info.findtext("t:ServiceName/t:Name", default="", namespaces=NS)
            for node in info.iter():
                if node.tag.endswith("}X509Certificate") and node.text:
                    raw = base64.b64decode("".join(node.text.split()), validate=True)
                    if raw in embedded:
                        matches.append({"provider_unverified": provider, "service_unverified": name,
                                        "ca_certificate_sha256": hashlib.sha256(raw).hexdigest(),
                                        "status_unverified": info.findtext("t:ServiceStatus", default="", namespaces=NS),
                                        "history_entries": len(service.findall("t:ServiceHistory/t:ServiceHistoryInstance", NS))})
    return {"exact_der_matches": matches, "tsl_authenticated": False, "qualified_signature": "Indeterminate"}
if __name__ == "__main__":
    if len(sys.argv) != 3: raise SystemExit("usage: eidas_match_pdf_ca.py signed.pdf bg-tsl.xml")
    print(json.dumps(match(sys.argv[1], sys.argv[2]), indent=2))
