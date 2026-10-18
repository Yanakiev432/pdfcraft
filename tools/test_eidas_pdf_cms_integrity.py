import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from eidas_pdf_cms_integrity import inspect

def pdf(payload=b'ABCD', bad_gap=False):
    gap = b'<3000>' if not bad_gap else b'not-cms'
    header = b'%PDF-1.7\n/ByteRange [0 000000 000000 000000]\n'
    prefix = header + payload
    suffix = b'\n%%EOF'
    header = b'%%PDF-1.7\n/ByteRange [0 %06d %06d %06d]\n' % (len(prefix), len(prefix)+len(gap), len(suffix))
    return header + payload + gap + suffix

class IntegrityTests(unittest.TestCase):
    def test_valid_range_calls_openssl_and_no_trust_promotion(self):
        with TemporaryDirectory() as folder:
            path = Path(folder)/'a.pdf'
            path.write_bytes(pdf())
            with patch('eidas_pdf_cms_integrity.subprocess.run') as run:
                run.return_value.returncode = 0
                result = inspect(path)
                self.assertTrue(result['cms_detached_signature_integrity_verified'])
                self.assertFalse(result['cms_signer_chain_trusted'])
                self.assertFalse(result['trusted_signing_time_verified'])
                self.assertEqual(run.call_count, 1)

    def test_failed_crypto_is_false(self):
        with TemporaryDirectory() as folder:
            path = Path(folder)/'a.pdf'
            path.write_bytes(pdf())
            with patch('eidas_pdf_cms_integrity.subprocess.run') as run:
                run.return_value.returncode = 4
                self.assertFalse(inspect(path)['cms_detached_signature_integrity_verified'])

    def test_expected_signer_requires_real_exported_certificate(self):
        with TemporaryDirectory() as folder:
            path = Path(folder)/'a.pdf'
            expected = Path(folder)/'expected.pem'
            path.write_bytes(pdf())
            expected.write_bytes(b'not a PEM certificate')
            with patch('eidas_pdf_cms_integrity.subprocess.run') as run:
                run.return_value.returncode = 0
                with self.assertRaisesRegex(ValueError, 'Expected signer certificate missing'):
                    inspect(path, expected)

    def test_gap_must_be_cms_hex(self):
        with TemporaryDirectory() as folder:
            path = Path(folder)/'a.pdf'
            path.write_bytes(pdf(bad_gap=True))
            with self.assertRaisesRegex(ValueError, 'gap'):
                inspect(path)

    def test_trailing_bytes_rejected(self):
        with TemporaryDirectory() as folder:
            path = Path(folder)/'a.pdf'
            path.write_bytes(pdf()+b'append')
            with self.assertRaisesRegex(ValueError, 'ByteRange'):
                inspect(path)

if __name__ == '__main__':
    unittest.main()
