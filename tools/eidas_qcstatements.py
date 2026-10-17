#!/usr/bin/env python3
"""Strict structural QCStatements OID inventory; no eIDAS verdict."""
import json, re, sys
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier
QC = ObjectIdentifier("1.3.6.1.5.5.7.1.3")
KNOWN = {"0.4.0.1862.1.1": "QcCompliance", "0.4.0.1862.1.4": "QcSSCD",
         "0.4.0.1862.1.5": "QcPDS", "0.4.0.1862.1.6": "QcType",
         "0.4.0.1862.1.6.1": "QcType_eSign", "0.4.0.1862.1.6.2": "QcType_eSeal",
         "0.4.0.1862.1.6.3": "QcType_web", "1.3.6.1.5.5.7.11.2": "id_etsi_qcs_QcComplianceLegacy"}
def tlv(data, offset):
    if offset + 2 > len(data): raise ValueError("Truncated ASN.1")
    tag = data[offset]; length = data[offset + 1]; start = offset + 2
    if length & 128:
        n = length & 127
        if n == 0 or n > 4 or start + n > len(data): raise ValueError("Unsupported ASN.1 length")
        length = int.from_bytes(data[start:start+n], "big"); start += n
        if length < 128: raise ValueError("Noncanonical length")
    end = start + length
    if end > len(data): raise ValueError("Truncated ASN.1 value")
    return tag, data[start:end], end
def oid(raw):
    if not raw: raise ValueError("Empty OID")
    vals=[]; val=0
    for byte in raw:
        val = (val << 7) | (byte & 127)
        if val.bit_length() > 128: raise ValueError("OID arc too long")
        if not byte & 128: vals.append(val);val=0
    if raw[-1] & 128 or not vals: raise ValueError("Invalid OID")
    first=vals.pop(0)
    arcs=[min(first//40,2), first-min(first//40,2)*40]+vals
    return ".".join(map(str,arcs))
def parse_qc(data):
    tag, body, end = tlv(data, 0)
    if tag != 0x30 or end != len(data): raise ValueError("QCStatements must be SEQUENCE")
    items=[]; pos=0
    while pos < len(body):
        tag, statement, pos = tlv(body, pos)
        if tag != 0x30: raise ValueError("QCStatement must be SEQUENCE")
        t, raw, next_pos = tlv(statement, 0)
        if t != 0x06: raise ValueError("QCStatement missing OID")
        identifier=oid(raw)
        items.append({"oid": identifier, "name": KNOWN.get(identifier, "unknown"),
                      "statement_info_present": next_pos < len(statement)})
        if identifier == "0.4.0.1862.1.6":
            if next_pos == len(statement): raise ValueError("QcType missing statementInfo")
            info_tag, info, info_end = tlv(statement, next_pos)
            if info_tag != 0x30 or info_end != len(statement): raise ValueError("QcType malformed statementInfo")
            types=[]; i=0
            while i < len(info):
                kind, encoded, i = tlv(info, i)
                if kind != 0x06: raise ValueError("QcType requires OID entries")
                types.append(oid(encoded))
            if not types or len(types) != len(set(types)): raise ValueError("QcType missing or duplicated types")
            items[-1]["certificate_types"] = [{"oid": t, "name": KNOWN.get(t,"unknown")} for t in types]
    return items
def inspect(path):
    data=Path(path).read_bytes()
    blocks=re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",data,re.S)
    if not blocks: raise ValueError("No PEM certificates")
    results=[]
    for block in blocks:
        cert=x509.load_pem_x509_certificate(block)
        try: extension=cert.extensions.get_extension_for_oid(QC)
        except x509.ExtensionNotFound: continue
        items=parse_qc(extension.value.value)
        results.append({"qc_statements": items, "qc_compliance_declared": any(x["oid"]=="0.4.0.1862.1.1" for x in items),
                        "qscd_declared": any(x["oid"]=="0.4.0.1862.1.4" for x in items),
                        "qc_esign_type_declared": any(t["oid"]=="0.4.0.1862.1.6.1" for x in items for t in x.get("certificate_types", [])),
                        "qscd_independently_verified": False, "qualification": "Indeterminate"})
    return results
if __name__ == "__main__":
    if len(sys.argv)!=2: raise SystemExit("usage: eidas_qcstatements.py embedded-certs.pem")
    print(json.dumps(inspect(sys.argv[1]),indent=2))
