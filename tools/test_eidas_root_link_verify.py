import datetime as dt
import hashlib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from eidas_root_link_verify import inspect

def make_cert(name, issuer, key, signer, is_ca, aki=None):
    start = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    end = dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(start).not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=is_ca, crl_sign=is_ca, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    if aki is not None:
        builder = builder.add_extension(x509.AuthorityKeyIdentifier(aki, None, None), critical=False)
    return builder.sign(signer, hashes.SHA256())

class RootLinkTests(unittest.TestCase):
    def test_three_certificate_link_requires_pin_and_valid_signature(self):
        keys = [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(4)]
        names = [x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)]) for value in ('Root', 'Issuer', 'Leaf')]
        root = make_cert(names[0], names[0], keys[0], keys[0], True)
        root_ski = root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        issuer = make_cert(names[1], names[0], keys[1], keys[0], True, root_ski)
        issuer_ski = issuer.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        leaf = make_cert(names[2], names[1], keys[2], keys[1], False, issuer_ski)
        bad_issuer = make_cert(names[1], names[0], keys[1], keys[3], True, root_ski)
        with TemporaryDirectory() as folder:
            d = Path(folder)
            root_path, bundle_path = d/'root.pem', d/'bundle.pem'
            root_der = root.public_bytes(serialization.Encoding.DER)
            root_path.write_bytes(root.public_bytes(serialization.Encoding.PEM))
            pin = hashlib.sha256(root_der).hexdigest()
            def run(intermediate, selected_pin=pin):
                bundle_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM) +
                                        intermediate.public_bytes(serialization.Encoding.PEM))
                return inspect(bundle_path, root_path, selected_pin, '2026-10-18T14:30:00Z')
            good = run(issuer)
            self.assertTrue(good['local_three_certificate_link_verified'])
            self.assertFalse(good['independent_root_pin_provenance_verified'])
            self.assertFalse(good['full_certificate_path_verified'])
            self.assertFalse(run(issuer, '0'*64)['caller_root_pin_matches'])
            self.assertFalse(run(bad_issuer)['issuer_signature_by_root_verified'])
            with self.assertRaisesRegex(ValueError, 'pin'):
                run(issuer, '')

if __name__ == '__main__': unittest.main()
