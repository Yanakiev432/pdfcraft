import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from eidas_dss_local_verify import validate

def report(level='QESig', indication='TOTAL_PASSED', count=1):
    return json.dumps({'SimpleReport': {
        'SignaturesCount': count, 'ValidSignaturesCount': 1,
        'ValidationTime': '2026-10-18T20:25:03Z',
        'signatureOrTimestampOrEvidenceRecord': [
            {'Signature': {'SignatureLevel': {'value': level}, 'Indication': indication,
                           'SignatureFormat': 'PAdES-BASELINE-B'}}]}}).encode()

class Response:
    status = 200
    def __init__(self, raw): self.raw = raw
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, count): return self.raw[:count]

class Tests(unittest.TestCase):
    def run_report(self, raw):
        with TemporaryDirectory() as temp:
            pdf = Path(temp)/'document.pdf'
            pdf.write_bytes(b'%PDF synthetic')
            with patch('eidas_dss_local_verify.urllib.request.OpenerDirector.open', return_value=Response(raw)):
                return validate(pdf)[0]

    def test_valid_qes(self):
        result = self.run_report(report())
        self.assertTrue(result['independent_dss_qes_pass'])
        self.assertFalse(result['native_qes_pass'])
        self.assertFalse(result['trusted_signing_time_proven_by_this_adapter'])

    def test_total_failed(self):
        self.assertFalse(self.run_report(report(indication='TOTAL_FAILED'))['independent_dss_qes_pass'])

    def test_advanced_not_qes(self):
        self.assertFalse(self.run_report(report(level='AdESig'))['independent_dss_qes_pass'])

    def test_multi_signature_fail_closed(self):
        with self.assertRaisesRegex(ValueError, 'single-signature'):
            self.run_report(report(count=2))

    def test_external_endpoint_rejected_before_network(self):
        with TemporaryDirectory() as temp:
            pdf = Path(temp)/'x.pdf'
            pdf.write_bytes(b'x')
            for url in ('https://example.com/services/rest/validation/validateSignature',
                        'http://127.0.0.1.evil.com:8080/services/rest/validation/validateSignature',
                        'http://127.0.0.1:8080/evil',
                        'http://127.0.0.1:8080/services/rest/validation/validateSignature?redirect=1'):
                with self.subTest(url=url), self.assertRaises(ValueError):
                    validate(pdf, url)

    def test_report_without_simple_report_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SimpleReport'):
            self.run_report(b'{}')

if __name__ == '__main__':
    unittest.main()
