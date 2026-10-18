import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from eidas_signed_checkpoint import verified_checkpoint, verified_checkpoint_bytes, check_signed_baseline

class SignedCheckpointTests(unittest.TestCase):
    def test_signature_pin_tamper_and_replay_boundary(self):
        with TemporaryDirectory() as d:
            d = Path(d)
            key = Ed25519PrivateKey.generate()
            public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            pin = hashlib.sha256(der).hexdigest()
            entry = {'sequence': 64, 'issued': '2026-06-01T11:07:50Z', 'sha256': 'a'*64, 'within_publication_window': True}
            baseline = {'schema': 'pdfcraft.eidas.rollback-snapshot.v1', 'eu': entry, 'national': entry}
            raw = json.dumps(baseline).encode()
            (d/'checkpoint.json').write_bytes(raw)
            (d/'checkpoint.sig').write_bytes(key.sign(raw))
            (d/'public.pem').write_bytes(public)
            args = (d/'checkpoint.json', d/'checkpoint.sig', d/'public.pem', pin)
            self.assertEqual(verified_checkpoint(*args), baseline)
            self.assertEqual(verified_checkpoint_bytes(*args), (baseline, raw))
            accepted = dict(baseline, eu_lotl_authenticated_at_evaluation_time=True, national_tsl_authenticated_via_lotl=True)
            finding = check_signed_baseline(accepted, *args)
            self.assertTrue(finding['baseline_signature_verified'])
            self.assertFalse(finding['rollback_protection_verified'])
            self.assertFalse(finding['baseline_provenance_verified'])
            with self.assertRaisesRegex(ValueError, 'pin'):
                verified_checkpoint(*args[:3], '0'*64)
            (d/'checkpoint.json').write_bytes(raw+b' ')
            with self.assertRaisesRegex(ValueError, 'signature'):
                verified_checkpoint(*args)
            (d/'checkpoint.json').write_bytes(raw)
            (d/'checkpoint.sig').write_bytes(b'0'*64)
            with self.assertRaisesRegex(ValueError, 'signature'):
                verified_checkpoint(*args)

if __name__ == '__main__': unittest.main()