import hashlib
import json
import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from eidas_checkpoint_store import record_signed_checkpoint, record_authenticated_acceptance

class CheckpointStoreTests(unittest.TestCase):
    def test_signed_checkpoint_must_match_authenticated_list_report(self):
        with TemporaryDirectory() as folder:
            d = Path(folder)
            key = Ed25519PrivateKey.generate()
            der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            pin = hashlib.sha256(der).hexdigest()
            (d/'key.pem').write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            entry = {'sequence': 11, 'issued': '2026-10-11T00:00:00Z', 'sha256': 'a'*64, 'within_publication_window': True}
            record = {'schema': 'pdfcraft.eidas.rollback-snapshot.v1', 'eu': entry, 'national': entry}
            raw = json.dumps(record).encode()
            (d/'checkpoint.json').write_bytes(raw)
            (d/'checkpoint.sig').write_bytes(key.sign(raw))
            args = (d/'state.db', d/'checkpoint.json', d/'checkpoint.sig', d/'key.pem', pin)
            accepted = dict(record, eu_lotl_authenticated_at_evaluation_time=True, national_tsl_authenticated_via_lotl=True)
            bad = dict(accepted, national=dict(entry, sha256='b'*64))
            with self.assertRaisesRegex(ValueError, 'does not match'):
                record_authenticated_acceptance(args[0], bad, *args[1:])
            self.assertFalse(args[0].exists())
            missing = dict(accepted, national_tsl_authenticated_via_lotl=False)
            with self.assertRaises(ValueError):
                record_authenticated_acceptance(args[0], missing, *args[1:])
            self.assertTrue(record_authenticated_acceptance(args[0], accepted, *args[1:])['current_list_report_consistency_checked'])
    def test_monotonic_updates_replay_equivocation_and_tamper(self):
        with TemporaryDirectory() as folder:
            d = Path(folder)
            key = Ed25519PrivateKey.generate()
            der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            pin = hashlib.sha256(der).hexdigest()
            (d/'key.pem').write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            args = (d/'state.db', d/'checkpoint.json', d/'checkpoint.sig', d/'key.pem', pin)
            def sign(seq, digest='a'*64):
                entry = {'sequence': seq, 'issued': f'2026-10-{seq:02d}T00:00:00Z', 'sha256': digest}
                raw = json.dumps({'schema': 'pdfcraft.eidas.rollback-snapshot.v1', 'eu': entry, 'national': entry}).encode()
                (d/'checkpoint.json').write_bytes(raw)
                (d/'checkpoint.sig').write_bytes(key.sign(raw))
            sign(10)
            first = record_signed_checkpoint(*args)
            self.assertFalse(first['compared_with_existing_local_state'])
            self.assertFalse(first['rollback_protection_verified'])
            sign(11)
            self.assertTrue(record_signed_checkpoint(*args)['compared_with_existing_local_state'])
            sign(10)
            with self.assertRaisesRegex(ValueError, 'rollback'):
                record_signed_checkpoint(*args)
            sign(11, 'b'*64)
            with self.assertRaisesRegex(ValueError, 'equivocation'):
                record_signed_checkpoint(*args)
            sign(12)
            (d/'checkpoint.sig').write_bytes(b'x'*64)
            with self.assertRaisesRegex(ValueError, 'signature'):
                record_signed_checkpoint(*args)
            sign(12)
            self.assertTrue(record_signed_checkpoint(*args)['local_monotonic_update_accepted'])
            self.assertFalse(record_signed_checkpoint(*args)['independent_state_integrity_verified'])
            other = Ed25519PrivateKey.generate()
            other_der = other.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            other_pin = hashlib.sha256(other_der).hexdigest()
            (d/'other.pem').write_bytes(other.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            raw = (d/'checkpoint.json').read_bytes()
            (d/'checkpoint.sig').write_bytes(other.sign(raw))
            with self.assertRaisesRegex(ValueError, 'rotation'):
                record_signed_checkpoint(*args[:3], d/'other.pem', other_pin)
            with sqlite3.connect(d/'state.db') as db:
                db.execute("UPDATE checkpoint_state SET payload=? WHERE id=1", ('{}',))
            (d/'checkpoint.sig').write_bytes(key.sign(raw))
            with self.assertRaises(ValueError):
                record_signed_checkpoint(*args)

if __name__ == '__main__': unittest.main()