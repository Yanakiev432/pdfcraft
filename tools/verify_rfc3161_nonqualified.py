#!/usr/bin/env python3
"""Independently check the NONQUALIFIED clean-fixture RFC3161 PDF output.

Requires pinned pypdf/asn1crypto plus OpenSSL and Poppler pdfsig.
Never claims an eIDAS-qualified time stamp, trusted certificate, QES or EU DSS.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from asn1crypto import cms, tsp
from pypdf import PdfReader


def verify(pdf: Path) -> dict:
    raw = pdf.read_bytes()
    document = PdfReader(str(pdf), strict=True)
    assert not document.is_encrypted and len(document.pages) == 1
    assert document.pages[0].extract_text().strip() == "PdfCraft RFC3161 synthetic signing acceptance"
    fields = document.get_fields() or {}
    signed = [f["/V"].get_object() for f in fields.values()
              if f.get("/FT") == "/Sig" and f.get("/V")]
    assert len(signed) == 1, "Clean fixture must have exactly one signature"
    signature = signed[0]
    assert str(signature["/SubFilter"]) == "/ETSI.CAdES.detached"
    byte_range = [int(n) for n in signature["/ByteRange"]]
    assert (len(byte_range) == 4 and byte_range[0] == 0
            and byte_range[1] > 0 and byte_range[2] > byte_range[1])
    assert byte_range[2] + byte_range[3] == len(raw)
    signed_data = cms.ContentInfo.load(signature["/Contents"].original_bytes.rstrip(b"\0"))
    assert signed_data["content_type"].native == "signed_data"
    signer_infos = signed_data["content"]["signer_infos"]
    assert len(signer_infos) == 1
    signer = signer_infos[0]
    attrs = [a for a in signer["unsigned_attrs"]
             if a["type"].dotted == "1.2.840.113549.1.9.16.2.14"]
    assert len(attrs) == 1 and len(attrs[0]["values"]) == 1
    token_der = attrs[0]["values"][0].dump()
    token_cms = cms.ContentInfo.load(token_der)
    assert token_cms["content_type"].native == "signed_data"
    assert len(token_cms["content"]["signer_infos"]) == 1
    tst = tsp.TSTInfo.load(token_cms["content"]["encap_content_info"]["content"].contents)
    assert tst["message_imprint"]["hash_algorithm"]["algorithm"].native == "sha256"
    digest = hashlib.sha256(signer["signature"].native).digest()
    assert digest == tst["message_imprint"]["hashed_message"].native, "Wrong TSA message imprint"
    with tempfile.TemporaryDirectory(prefix="pdfcraft-independent-rfc3161-") as folder:
        token = Path(folder) / "timestamp.der"
        token.write_bytes(token_der)
        proc = subprocess.run(["openssl", "cms", "-verify", "-inform", "DER",
                               "-in", str(token), "-noverify",
                               "-out", str(Path(folder) / "tstinfo.der")],
                              capture_output=True, text=True, timeout=20, check=False)
        assert proc.returncode == 0, "OpenSSL RFC3161 cryptographic signature FAIL"
    pdfsig = subprocess.run(["pdfsig", str(pdf)], capture_output=True, text=True, timeout=20)
    assert pdfsig.returncode == 0
    assert pdfsig.stdout.count("Signature Validation: Signature is Valid.") == 1
    assert "Total document signed" in pdfsig.stdout
    assert "Certificate issuer isn't Trusted." in pdfsig.stdout
    return {
        "schema": "pdfcraft.rfc3161.clean-fixture-independent.v1",
        "pdf_sha256": hashlib.sha256(raw).hexdigest(),
        "pdf_bytes": len(raw),
        "pdf_signatures": 1,
        "pdf_byte_range_covers_full_revision": True,
        "poppler_pdfsig_cryptographic_signature": "PASS",
        "openssl_timestamp_cms_signature": "PASS",
        "rfc3161_imprint_matches_cms_signature_sha256": "PASS",
        "timestamp_generation_utc": tst["gen_time"].native.isoformat(),
        "timestamp_policy_oid": tst["policy"].dotted,
        "certificate_trust": "UNTRUSTED_TEST_ONLY",
        "eidas_qualified_tsa": False,
        "independent_eu_dss_qes_verdict": "NOT_CHECKED",
        "release_ready": False
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("pdf", type=Path)
    p.add_argument("--json", type=Path)
    options = p.parse_args()
    output = json.dumps(verify(options.pdf), sort_keys=True, indent=2) + "\n"
    if options.json:
        with options.json.open("x", encoding="utf-8") as report:
            report.write(output)
    print(output)


if __name__ == "__main__":
    main()
