import datetime as dt
import unittest
from tempfile import TemporaryDirectory
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from eidas_certificate_path_verify import inspect

UTC = dt.timezone.utc
def certificate(subject, issuer_name, key, signing_key, ca, aki, start, end):
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(start).not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False), critical=True))
    if aki is not None:
        builder = builder.add_extension(x509.AuthorityKeyIdentifier(aki, None, None), critical=False)
    if ca:
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    return builder.sign(signing_key, hashes.SHA256())

class CertificateLinkTests(unittest.TestCase):
    def test_verified_link_and_negative_signature_ca_and_key_id(self):
        now = dt.datetime(2026, 10, 18, tzinfo=UTC)
        start, end = now - dt.timedelta(days=10), now + dt.timedelta(days=10)
        issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test CA')])
        leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test Leaf')])
        issuer = certificate(issuer_name, issuer_name, issuer_key, issuer_key, True, None, start, end)
        ski = issuer.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        def run(leaf, parent=issuer):
            with TemporaryDirectory() as folder:
                path = Path(folder) / 'bundle.pem'
                path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM) +
                                 parent.public_bytes(serialization.Encoding.PEM))
                return inspect(path, '2026-10-18T14:30:00Z')
        leaf = certificate(leaf_name, issuer_name, leaf_key, issuer_key, False, ski, start, end)
        valid = run(leaf)
        self.assertTrue(valid['local_link_verified'])
        self.assertFalse(valid['full_certificate_path_verified'])
        self.assertEqual(valid['qualification'], 'Indeterminate')
        tampered = certificate(leaf_name, issuer_name, leaf_key, wrong_key, False, ski, start, end)
        self.assertFalse(run(tampered)['leaf_certificate_signature_verified'])
        self.assertFalse(run(tampered)['local_link_verified'])
        wrong_aki = certificate(leaf_name, issuer_name, leaf_key, issuer_key, False, b'x'*20, start, end)
        self.assertFalse(run(wrong_aki)['authority_key_identifier_matches'])
        non_ca = certificate(issuer_name, issuer_name, issuer_key, issuer_key, False, None, start, end)
        self.assertFalse(run(leaf, non_ca)['issuer_ca_constraints_verified'])
        expired = certificate(leaf_name, issuer_name, leaf_key, issuer_key, False, ski,
                              start - dt.timedelta(days=40), start - dt.timedelta(days=20))
        self.assertFalse(run(expired)['both_certificates_valid_at_evaluation_time'])

if __name__ == '__main__': unittest.main()
