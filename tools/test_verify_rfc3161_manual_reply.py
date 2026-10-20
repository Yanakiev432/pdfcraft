#!/usr/bin/env python3
"""Synthetic, NO-NETWORK CMS TimeStampResp acceptance and negative regressions."""
from __future__ import annotations
import importlib.util
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import tempfile
import unittest
from asn1crypto import cms, tsp

spec = importlib.util.spec_from_file_location("manual", Path(__file__).with_name("verify_rfc3161_manual_reply.py"))
assert spec and spec.loader
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


class OfflinePairTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="NONQUALIFIED-RFC3161-")
        directory = Path(cls.directory.name)
        cls.digest = bytes.fromhex("ab" * 32)
        cls.nonce = 81223001
        cls.policy = "1.2.3.4.5"
        tst = tsp.TSTInfo({
            "version": "v1", "policy": cls.policy,
            "message_imprint": {
                "hash_algorithm": {"algorithm": "sha256"}, "hashed_message": cls.digest
            },
            "serial_number": 712,
            "gen_time": datetime.now(timezone.utc),
            "nonce": cls.nonce,
        })
        (directory / "tst.der").write_bytes(tst.dump())

        def run(command):
            result = subprocess.run(command, capture_output=True, timeout=20, check=False)
            if result.returncode != 0:
                raise RuntimeError("Synthetic test-only OpenSSL fixture generation failed")

        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-noenc",
             "-days", "1", "-subj", "/CN=NONQUALIFIED-SYNTHETIC-TSA",
             "-keyout", str(directory / "secret.key"), "-out", str(directory / "cert.pem")])
        run(["openssl", "cms", "-sign", "-binary", "-nodetach",
             "-in", str(directory / "tst.der"), "-signer", str(directory / "cert.pem"),
             "-inkey", str(directory / "secret.key"), "-outform", "DER",
             "-out", str(directory / "token.der"), "-md", "sha256",
             "-econtent_type", "1.2.840.113549.1.9.16.1.4"])

        cls.token = cms.ContentInfo.load((directory / "token.der").read_bytes(), strict=True)
        cls.request = tsp.TimeStampReq({
            "version": "v1",
            "message_imprint": {
                "hash_algorithm": {"algorithm": "sha256"}, "hashed_message": cls.digest
            },
            "nonce": cls.nonce,
            "req_policy": cls.policy,
            "cert_req": True,
        }).dump()
        cls.response = tsp.TimeStampResp({
            "status": {"status": "granted"}, "time_stamp_token": cls.token,
        }).dump()

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_valid_cryptographic_token_still_cannot_claim_qtsa(self):
        data = v.verify_pair(self.request, self.response, signature_sha256=self.digest.hex())
        self.assertEqual(data["cms_crypto_signature"], "PASS")
        self.assertEqual(data["tsq_tsr_pair_binding"], "PASS")
        self.assertEqual(data["eidas_qtsa"], "NOT_CHECKED")
        self.assertEqual(data["final_pades_b_t_lt_lta"], "NOT_CHECKED")
        self.assertFalse(data["release_ready"])

    def test_wrong_imprint_rejected(self):
        q = tsp.TimeStampReq.load(self.request)
        q["message_imprint"]["hashed_message"] = bytes(32)
        with self.assertRaises(v.EvidenceError):
            v.verify_pair(q.dump(), self.response)

    def test_wrong_nonce_rejected(self):
        q = tsp.TimeStampReq.load(self.request)
        q["nonce"] = self.nonce + 1
        with self.assertRaises(v.EvidenceError):
            v.verify_pair(q.dump(), self.response)

    def test_wrong_policy_rejected(self):
        q = tsp.TimeStampReq.load(self.request)
        q["req_policy"] = "1.2.3.4.6"
        with self.assertRaises(v.EvidenceError):
            v.verify_pair(q.dump(), self.response)

    def test_certreq_false_rejected(self):
        q = tsp.TimeStampReq.load(self.request)
        q["cert_req"] = False
        with self.assertRaises(v.EvidenceError):
            v.verify_pair(q.dump(), self.response)

    def test_unrelated_pdf_signature_digest_rejected(self):
        with self.assertRaises(v.EvidenceError):
            v.verify_pair(self.request, self.response, signature_sha256="00" * 32)

    def test_provider_rejection_rejected(self):
        r = tsp.TimeStampResp.load(self.response)
        r["status"]["status"] = "rejection"
        with self.assertRaises(v.EvidenceError):
            v.verify_pair(self.request, r.dump())

    def test_tampered_cms_signature_rejected(self):
        signature = self.token["content"]["signer_infos"][0]["signature"].native
        i = self.response.rfind(signature)
        self.assertGreater(i, 0)
        data = bytearray(self.response)
        data[i + 1] ^= 1
        with self.assertRaises(v.EvidenceError):
            v.verify_pair(self.request, bytes(data))

    def test_non_tstinfo_cms_content_type_rejected(self):
        token = cms.ContentInfo.load(self.token.dump(), strict=True)
        token["content"]["encap_content_info"]["content_type"] = "data"
        wrong = tsp.TimeStampResp({
            "status": {"status": "granted"}, "time_stamp_token": token,
        }).dump()
        with self.assertRaises(v.EvidenceError):
            v.verify_pair(self.request, wrong)

    def test_trailing_der_bytes_rejected(self):
        with self.assertRaises(v.EvidenceError):
            v.verify_pair(self.request, self.response + b"bad")


if __name__ == "__main__":
    unittest.main(verbosity=2)
