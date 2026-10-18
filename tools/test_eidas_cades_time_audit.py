import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from eidas_cades_time_audit import inspect

class CadesAuditTests(unittest.TestCase):
    def test_attribute_presence_never_claims_trusted_time(self):
        with TemporaryDirectory() as d:
            path = Path(d) / 'signed.der'
            path.write_bytes(b'CMS')
            with patch('eidas_cades_time_audit.subprocess.run') as run:
                run.return_value.stdout = '''
                  object: signingTime (1.2.840.113549.1.9.5)
                  object: id-aa-signatureTimeStampToken (1.2.840.113549.1.9.16.2.14)
                  object: id-smime-aa-signingCertificateV2 (1.2.840.113549.1.9.16.2.47)
                '''
                result = inspect(path)
            self.assertTrue(result['attributes_present_unverified']['signature_timestamp'])
            self.assertTrue(result['attributes_present_unverified']['signing_time'])
            self.assertFalse(result['trusted_signing_time_verified'])
            self.assertEqual(result['qualification'], 'Indeterminate')

    def test_unrelated_text_does_not_count_as_attribute(self):
        with TemporaryDirectory() as d:
            path = Path(d) / 'signed.der'
            path.write_bytes(b'CMS')
            with patch('eidas_cades_time_audit.subprocess.run') as run:
                run.return_value.stdout = 'subject=1.2.840.113549.1.9.5'
                result = inspect(path)
            self.assertFalse(result['attributes_present_unverified']['signing_time'])

    def test_oversized_input_rejected(self):
        with TemporaryDirectory() as d:
            path = Path(d) / 'signed.der'
            with path.open('wb') as f:
                f.truncate(8*1024*1024 + 1)
            with self.assertRaisesRegex(ValueError, 'size limit'):
                inspect(path)

if __name__ == '__main__':
    unittest.main()
