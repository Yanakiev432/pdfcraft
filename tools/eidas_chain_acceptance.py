#!/usr/bin/env python3
"""Conservative EU LOTL -> national TSL acceptance with expiry and sequence checks.
An authenticated EU LOTL alone is not a complete QES determination."""
import datetime as dt, json, os, sys, xml.etree.ElementTree as ET
from pathlib import Path
from eidas_lotl_oj_anchor import verify as verify_eu
from eidas_lotl_national_signer_match import match as match_national
from eidas_xmlsig_crypto_check import verify as verify_xml
NS = {"t": "http://uri.etsi.org/02231/v2#"}
def timestamp(value):
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None: raise ValueError("Timezone required")
    return parsed.astimezone(dt.timezone.utc)
def metadata(path, at):
    root = ET.parse(path).getroot()
    info = root.find("t:SchemeInformation", NS)
    if info is None: raise ValueError("Missing scheme information")
    seq = int(info.findtext("t:TSLSequenceNumber", namespaces=NS))
    issued = timestamp(info.findtext("t:ListIssueDateTime", namespaces=NS))
    next_update = timestamp(info.findtext("t:NextUpdate/t:dateTime", namespaces=NS))
    if seq < 1 or next_update <= issued: raise ValueError("Invalid sequence or time range")
    return {"sequence": seq, "issued": issued.isoformat(), "next_update": next_update.isoformat(),
            "within_publication_window": issued <= at < next_update}
def acceptance(eu_path, national_path, at_text):
    at = timestamp(at_text)
    eu = verify_eu(eu_path)
    bg = verify_xml(national_path)
    links = match_national(eu_path, national_path)
    eu_meta, bg_meta = metadata(eu_path, at), metadata(national_path, at)
    # A national TSL must explicitly identify the expected member-state territory.
    bg_root = ET.parse(national_path).getroot()
    territory = bg_root.findtext("t:SchemeInformation/t:SchemeTerritory", default="", namespaces=NS)
    if territory != "BG": raise ValueError("National TSL territory mismatch")
    national_pinned = any(p["matching_signer_certificate"] and p["location_unverified"].endswith("/TSL_BG.xml") for p in links["pointers_unverified"])
    eu_ok = bool(eu["lotl_authenticated"] and eu_meta["within_publication_window"])
    bg_ok = bool(eu_ok and bg["cryptography_verified_with_untrusted_embedded_key"] and national_pinned and bg_meta["within_publication_window"])
    return {"evaluation_time": at.isoformat(), "eu": eu_meta, "national": bg_meta,
            "eu_lotl_authenticated_at_evaluation_time": eu_ok,
            "national_tsl_authenticated_via_lotl": bg_ok,
            "rollback_protection_verified": False, "pivot_policy_verified": False,
            "qscd_verified": False, "revocation_verified": False, "qualification": "Indeterminate"}
if __name__ == "__main__":
    if len(sys.argv) != 4: raise SystemExit("usage: eidas_chain_acceptance.py EU.xml BG.xml ISO8601")
    print(json.dumps(acceptance(*sys.argv[1:]), indent=2))
