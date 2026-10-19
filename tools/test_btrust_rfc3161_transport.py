#!/usr/bin/env python3
"""No-network regression tests for the B-Trust RFC 3161 transport boundary."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("btrust_rfc3161_transport.py")
spec = importlib.util.spec_from_file_location("btrust_rfc3161_transport", SCRIPT)
assert spec and spec.loader
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)


class FakeResponse:
    status = 200

    def __init__(self, payload=b"\x30\x00", mime="application/timestamp-reply"):
        self.payload = payload
        self.headers = {"Content-Type": mime}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, limit):
        assert limit == t.MAX_RESPONSE + 1
        return self.payload


class TransportTests(unittest.TestCase):
    DER = b"\x30\x00"

    def test_only_exact_provider_profiles(self):
        self.assertEqual(t.prepare_request(self.DER, server="test").full_url, t.TEST_URL)
        with self.assertRaises(t.TimestampTransportError):
            t.prepare_request(self.DER, server="https://evil.example/")
        with self.assertRaises(t.TimestampTransportError):
            t.prepare_request(self.DER, server="production")

    def test_production_requires_opt_in(self):
        req = t.prepare_request(self.DER, server="production", allow_production=True)
        self.assertEqual(req.full_url, t.PRODUCTION_URL)
        self.assertEqual(req.get_method(), "POST")

    def test_credentials_cannot_travel_without_tls(self):
        with self.assertRaises(t.TimestampTransportError):
            t.prepare_request(self.DER, server="test", username="u", password="p")
        with self.assertRaises(t.TimestampTransportError):
            t.prepare_request(self.DER, server="production", allow_production=True, username="u")
        prod = t.prepare_request(self.DER, server="production", allow_production=True, username="u", password="p")
        self.assertIn("Basic", prod.get_header("Authorization"))

    def test_redirects_never_follow(self):
        with self.assertRaises(t.TimestampTransportError):
            t.RejectRedirects().redirect_request(
                None, None, 302, "redirect", {}, "https://untrusted.example/"
            )

    def test_request_uses_rfc3161_content_type(self):
        req = t.prepare_request(self.DER, server="test")
        self.assertEqual(req.get_header("Content-type"), "application/timestamp-query")
        self.assertEqual(req.data, self.DER)

    def test_fail_closed_on_input(self):
        for data in (b"", b"bad", b"\x30" * (t.MAX_REQUEST + 1)):
            with self.subTest(data_len=len(data)):
                with self.assertRaises(t.TimestampTransportError):
                    t.prepare_request(data, server="test")

    def test_receives_only_bounded_mime_approved_der(self):
        seen = []
        def fake_opener(req, timeout):
            seen.append((req.full_url, timeout))
            return FakeResponse()
        self.assertEqual(t.transport(self.DER, server="test", opener=fake_opener), self.DER)
        self.assertEqual(seen, [(t.TEST_URL, t.DEFAULT_TIMEOUT)])

        for resp in (
            FakeResponse(mime="text/html"),
            FakeResponse(payload=b"not der"),
            FakeResponse(payload=b"\x30" + b"x" * t.MAX_RESPONSE),
        ):
            with self.subTest(mime=resp.headers["Content-Type"], size=len(resp.payload)):
                with self.assertRaises(t.TimestampTransportError):
                    t.transport(self.DER, server="test", opener=lambda *_args, **_kwargs: resp)

    def test_never_delete_existing_output(self):
        with tempfile.TemporaryDirectory() as d:
            infile = Path(d) / "in.der"
            outfile = Path(d) / "out.der"
            infile.write_bytes(self.DER)
            outfile.write_bytes(b"KEEP-EXISTING")
            with patch.object(t, "transport", return_value=b"\x30\x00") as transport:
                self.assertEqual(t.main(["--server", "test", "--request", str(infile), "--response", str(outfile)]), 1)
                transport.assert_not_called()
            self.assertEqual(outfile.read_bytes(), b"KEEP-EXISTING")

    def test_cli_writes_only_after_successful_transport(self):
        with tempfile.TemporaryDirectory() as d:
            infile = Path(d) / "in.der"
            outfile = Path(d) / "out.der"
            infile.write_bytes(self.DER)
            with patch.object(t, "transport", side_effect=t.TimestampTransportError("test failure")):
                self.assertEqual(t.main(["--server", "test", "--request", str(infile), "--response", str(outfile)]), 1)
            self.assertFalse(outfile.exists())
            with patch.object(t, "transport", return_value=self.DER):
                self.assertEqual(t.main(["--server", "test", "--request", str(infile), "--response", str(outfile)]), 0)
            self.assertEqual(outfile.read_bytes(), self.DER)


if __name__ == "__main__":
    unittest.main()
