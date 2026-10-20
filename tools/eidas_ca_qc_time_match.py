#!/usr/bin/env python3
"""Fail-closed, untrusted TSL CA/QC time-scoped candidate matching.
This is not a qualified signature verdict or a trusted-list authenticator."""
import base64, datetime as dt, hashlib, json, sys, xml.etree.ElementTree as ET
from pathlib import Path
from eidas_match_pdf_ca import match
NS = {"t": "http://uri.etsi.org/02231/v2#"}
CA_QC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"
GRANTED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
def parse_time(value):
    value = value.replace("Z", "+00:00")
    result = dt.datetime.fromisoformat(value)
    if result.tzinfo is None: raise ValueError("Timestamp must include timezone")
    return result.astimezone(dt.timezone.utc)
def evaluate(pdf, tsl, instant):
    at = parse_time(instant)
    candidate_hashes = {x["ca_certificate_sha256"] for x in match(pdf, tsl)["exact_der_matches"]}
    raw = Path(tsl).read_bytes()
    if not raw or len(raw) > 8388608 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("Unsafe TSL")
    root = ET.fromstring(raw)
    candidates = []
    for provider in root.findall(".//t:TrustServiceProvider", NS):
        provider_name = provider.findtext("t:TSPInformation/t:TSPName/t:Name", default="", namespaces=NS)
        for service in provider.findall("t:TSPServices/t:TSPService", NS):
            current = service.find("t:ServiceInformation", NS)
            if current is None: continue
            if current.findtext("t:ServiceTypeIdentifier", default="", namespaces=NS) != CA_QC: continue
            name = current.findtext("t:ServiceName/t:Name", default="", namespaces=NS)
            states = [current] + service.findall("t:ServiceHistory/t:ServiceHistoryInstance", NS)
            states = sorted(states, key=lambda s: parse_time(s.findtext("t:StatusStartingTime", namespaces=NS)), reverse=True)
            state = next((s for s in states if parse_time(s.findtext("t:StatusStartingTime", namespaces=NS)) <= at), None)
            if state is None: continue
            # Compare exact certificate bytes in the effective historical state, not only current identity.
            identities = []
            for node in state.iter():
                if node.tag.endswith("}X509Certificate") and node.text:
                    identities.append(hashlib.sha256(base64.b64decode("".join(node.text.split()), validate=True)).hexdigest())
            # Historical records may contain only X509SubjectName/SKI; never infer DER match.
            matched = sorted(candidate_hashes.intersection(identities))
            if matched:
                candidates.append({"provider_unverified": provider_name, "service_unverified": name,
                                   "ca_qc": True, "matched_der_sha256": matched,
                                   "status_at_requested_time_unverified": state.findtext("t:ServiceStatus", default="", namespaces=NS),
                                   "granted_at_requested_time_unverified": state.findtext("t:ServiceStatus", default="", namespaces=NS) == GRANTED,
                                   "state_start": state.findtext("t:StatusStartingTime", default="", namespaces=NS)})
    return {"requested_time": at.isoformat(), "ca_qc_candidates_unverified": candidates,
            "time_source_trusted": False, "trusted_list_authenticated": False,
            "qscd_confirmed": False, "qualification": "Indeterminate"}
if __name__ == "__main__":
    if len(sys.argv) != 4: raise SystemExit("usage: eidas_ca_qc_time_match.py signed.pdf bg-tsl.xml ISO8601_UTC")
    print(json.dumps(evaluate(*sys.argv[1:]), indent=2))
