#!/usr/bin/env python3
"""Offline RFC3161 TSQ/TSR pair check. No eIDAS/QTSA qualification or PDF embedding.
Requires asn1crypto==1.5.1 and OpenSSL. NEVER accesses the network.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from asn1crypto import tsp

SHA256_OID = "2.16.840.1.101.3.4.2.1"
MAX_TSQ = 1024 * 1024
MAX_TSR = 4 * 1024 * 1024


class EvidenceError(ValueError):
    pass


def require(value, reason):
    if not value:
        raise EvidenceError(reason)


def bounded(path, maximum):
    if not path.is_file() or not 10 <= path.stat().st_size <= maximum:
        raise EvidenceError("Missing or oversized DER file")
    value = path.read_bytes()
    require(value[0] == 0x30, "DER top-level sequence missing")
    return value


def verify_pair(tsq_der, tsr_der, signature_sha256=None):
    require(10 <= len(tsq_der) <= MAX_TSQ and tsq_der[0] == 0x30, "Invalid TSQ")
    require(10 <= len(tsr_der) <= MAX_TSR and tsr_der[0] == 0x30, "Invalid TSR")
    try:
        q = tsp.TimeStampReq.load(tsq_der, strict=True)
        r = tsp.TimeStampResp.load(tsr_der, strict=True)
        require(q["version"].native == "v1", "Expected RFC3161 version 1")
        qm = q["message_imprint"]
        require(qm["hash_algorithm"]["algorithm"].dotted == SHA256_OID, "Only SHA256 permitted")
        digest = qm["hashed_message"].native
        require(len(digest) == 32, "Invalid imprint length")
        nonce = q["nonce"].native
        require(isinstance(nonce, int) and nonce > 0, "Positive nonce required")
        require(q["cert_req"].native is True, "certReq=true required")
        require(q["extensions"].native is None, "Extensions prohibited")
        if signature_sha256 is not None:
            require(len(signature_sha256) == 64, "Expected CMS signature SHA256 as 64 hex digits")
            try:
                expected = bytes.fromhex(signature_sha256)
            except ValueError:
                raise EvidenceError("Expected CMS signature SHA256 malformed") from None
            require(expected == digest, "Imprint differs from actual CMS signature hash")
        require(r["status"]["status"].native in ("granted", "granted_with_mods"), "TSA status not granted")
        token = r["time_stamp_token"]
        require(token.native is not None and token["content_type"].native == "signed_data", "Missing CMS token")
        signed = token["content"]
        require(len(signed["signer_infos"]) == 1, "Expected one CMS signer")
        actual = signed["encap_content_info"]["content"].contents
        info = tsp.TSTInfo.load(actual, strict=True)
        mi = info["message_imprint"]
        require(mi["hash_algorithm"]["algorithm"].dotted == SHA256_OID, "TSA hash algorithm mismatch")
        require(mi["hashed_message"].native == digest, "TSA digest mismatch")
        require(info["nonce"].native == nonce, "TSA nonce mismatch")
        if q["req_policy"].native is not None:
            require(q["req_policy"].dotted == info["policy"].dotted, "TSA policy mismatch")
        require(info["serial_number"].native > 0, "Invalid token serial")
        with tempfile.TemporaryDirectory(prefix="rfc3161-tst-") as directory:
            token_path = Path(directory) / "token.der"
            out_path = Path(directory) / "verified-tst.der"
            token_path.write_bytes(token.dump())
            proc = subprocess.run(
                ["openssl", "cms", "-verify", "-inform", "DER", "-in",
                 str(token_path), "-noverify", "-out", str(out_path)],
                capture_output=True, timeout=20, check=False
            )
            require(proc.returncode == 0, "Invalid TSA CMS cryptographic signature")
            require(out_path.read_bytes() == actual, "CMS verified content not equal to TSTInfo")
        return {
            "schema": "craft.rfc3161.offline-pair.v1",
            "tsq_sha256": hashlib.sha256(tsq_der).hexdigest(),
            "tsr_sha256": hashlib.sha256(tsr_der).hexdigest(),
            "imprint_sha256": digest.hex(),
            "generation_time": info["gen_time"].native.isoformat(),
            "policy": info["policy"].dotted,
            "nonce": str(nonce),
            "cms_crypto_signature": "PASS",
            "tsq_tsr_pair_binding": "PASS",
            "eidas_qtsa": "NOT_CHECKED",
            "trusted_chain_and_revocation": "NOT_CHECKED",
            "final_pades_b_t_lt_lta": "NOT_CHECKED",
            "release_ready": False,
        }
    except (ValueError, TypeError, KeyError, IndexError, AttributeError) as exc:
        if isinstance(exc, EvidenceError):
            raise
        raise EvidenceError("Invalid RFC3161 ASN.1/CMS structure") from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tsq", type=Path, required=True)
    parser.add_argument("--tsr", type=Path, required=True)
    parser.add_argument("--cms-signature-sha256")
    parser.add_argument("--report", type=Path)
    opts = parser.parse_args()
    try:
        require(opts.tsq.resolve() != opts.tsr.resolve(), "Source and response must differ")
        if opts.report:
            require(not opts.report.exists(), "Refusing overwrite of existing evidence report")
        report = verify_pair(
            bounded(opts.tsq, MAX_TSQ), bounded(opts.tsr, MAX_TSR),
            signature_sha256=opts.cms_signature_sha256,
        )
        output = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if opts.report:
            with opts.report.open("x", encoding="utf-8") as fh:
                fh.write(output)
                fh.flush()
                os.fsync(fh.fileno())
        print(output)
        return 0
    except (EvidenceError, OSError, subprocess.TimeoutExpired):
        print("RFC3161_MANUAL_PAIR_NO_GO", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
