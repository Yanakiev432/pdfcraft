import datetime as dt, unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from eidas_crl_verify import inspect, utc
class CRLTests(unittest.TestCase):
    def test_reject_naive_time(self):
        with self.assertRaises(ValueError): utc("2026-10-17T20:00:00")
    def test_good_and_revoked_and_bad_signature(self):
        now=dt.datetime(2026,10,17,12,0,0)
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        attacker=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"Test CA")])
        leaf_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"Test signer")])
        ca=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(now-dt.timedelta(days=10)).not_valid_after(now+dt.timedelta(days=10)).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).add_extension(x509.KeyUsage(digital_signature=False,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=False,decipher_only=False),critical=True).add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False).sign(key,hashes.SHA256())
        leaf=x509.CertificateBuilder().subject_name(leaf_name).issuer_name(name).public_key(key.public_key()).serial_number(2).not_valid_before(now-dt.timedelta(days=10)).not_valid_after(now+dt.timedelta(days=10)).sign(key,hashes.SHA256())
        with TemporaryDirectory() as folder:
            pem=Path(folder)/"certs.pem";pem.write_bytes(leaf.public_bytes(serialization.Encoding.PEM)+ca.public_bytes(serialization.Encoding.PEM))
            crl_file=Path(folder)/"test.crl"
            def make_crl(signing_key, revoked=False):
                builder=x509.CertificateRevocationListBuilder().issuer_name(name).last_update(now-dt.timedelta(days=1)).next_update(now+dt.timedelta(days=1)).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),critical=False)
                if revoked:
                    entry=x509.RevokedCertificateBuilder().serial_number(2).revocation_date(now-dt.timedelta(hours=1)).build()
                    builder=builder.add_revoked_certificate(entry)
                crl_file.write_bytes(builder.sign(signing_key,hashes.SHA256()).public_bytes(serialization.Encoding.DER))
            make_crl(key)
            self.assertEqual(inspect(pem,crl_file,"2026-10-17T12:00:00Z")["revocation_status"],"GoodAtEvaluationTime")
            make_crl(key,True)
            self.assertEqual(inspect(pem,crl_file,"2026-10-17T12:00:00Z")["revocation_status"],"Revoked")
            make_crl(attacker)
            self.assertEqual(inspect(pem,crl_file,"2026-10-17T12:00:00Z")["revocation_status"],"Unavailable")
            make_crl(key)
            self.assertEqual(inspect(pem,crl_file,"2026-10-19T12:00:00Z")["revocation_status"],"Unavailable")
            future=x509.RevokedCertificateBuilder().serial_number(2).revocation_date(now+dt.timedelta(hours=1)).build()
            builder=x509.CertificateRevocationListBuilder().issuer_name(name).last_update(now-dt.timedelta(days=1)).next_update(now+dt.timedelta(days=1)).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),critical=False).add_revoked_certificate(future)
            crl_file.write_bytes(builder.sign(key,hashes.SHA256()).public_bytes(serialization.Encoding.DER))
            self.assertEqual(inspect(pem,crl_file,"2026-10-17T12:00:00Z")["revocation_status"],"IndeterminateHistorical")
if __name__=='__main__': unittest.main()
