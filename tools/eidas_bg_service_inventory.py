#!/usr/bin/env python3
"""Read-only inventory of UNTRUSTED Bulgarian TSL service metadata."""
import json, sys, xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
NS = {"t": "http://uri.etsi.org/02231/v2#"}
def inventory(path):
    raw = Path(path).read_bytes()
    if not raw or len(raw) > 8388608 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("Unsafe XML")
    root = ET.fromstring(raw)
    if root.tag != "{http://uri.etsi.org/02231/v2#}TrustServiceStatusList":
        raise ValueError("Wrong root")
    providers = []
    counts = Counter()
    for tsp in root.findall(".//t:TrustServiceProvider", NS):
        name = tsp.findtext("t:TSPInformation/t:TSPName/t:Name", default="", namespaces=NS)
        services = []
        for service in tsp.findall("t:TSPServices/t:TSPService", NS):
            info = service.find("t:ServiceInformation", NS)
            if info is None: continue
            kind = info.findtext("t:ServiceTypeIdentifier", default="", namespaces=NS)
            status = info.findtext("t:ServiceStatus", default="", namespaces=NS)
            start = info.findtext("t:StatusStartingTime", default="", namespaces=NS)
            history = service.findall("t:ServiceHistory/t:ServiceHistoryInstance", NS)
            counts[kind] += 1
            services.append({"type_unverified": kind, "status_unverified": status,
                             "status_start_unverified": start, "history_entries": len(history)})
        providers.append({"name_unverified": name, "services": services})
    return {"providers": len(providers), "services": sum(counts.values()),
            "service_types": dict(sorted(counts.items())),
            "btrust_candidates_unverified": [p for p in providers if "BORICA" in p["name_unverified"].upper() or "B-TRUST" in p["name_unverified"].upper()],
            "tl_authenticated": False, "qualification": "Indeterminate"}
if __name__ == "__main__":
    print(json.dumps(inventory(sys.argv[1]), indent=2))
