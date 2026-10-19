#!/usr/bin/env python3
"""Create a deterministic, well-formed unsigned one-page PDF test fixture.

Public synthetic input only; no customer PDF, key, credential, random value or
network access. Does not claim PDF/A or eIDAS conformance.
"""
from __future__ import annotations

import argparse
from pathlib import Path


def make_fixture() -> bytes:
    content = b"BT /F1 12 Tf 50 740 Td (PdfCraft RFC3161 synthetic signing acceptance) Tj ET\n"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + content + b"endstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    pdf = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, value in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{i} 0 obj\n".encode("ascii"))
        pdf.extend(value)
        pdf.extend(b"\nendobj\n")
    xref_at = len(pdf)
    pdf.extend(f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n".encode("ascii"))
    for offset in offsets:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n".encode("ascii"))
    return bytes(pdf)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    data = make_fixture()
    with args.out.open("xb") as f:
        f.write(data)
        f.flush()
    print("CLEAN_UNSIGNED_PDF_FIXTURE bytes=" + str(len(data)))


if __name__ == "__main__":
    main()
