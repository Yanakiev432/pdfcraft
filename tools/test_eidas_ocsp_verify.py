import datetime as dt
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from eidas_ocsp_verify import inspect

class OCSPTests(unittest.TestCase):
    def test_good_revoked_wrong_certificate_and_stale(self):
        now=dt.datetime.now(dt.timezone.utc).replace(tzinfo=None,microsecond=0)
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        signer_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"Synthetic CA")])
        responder_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"Synthetic OCSP")])
        ca=x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(key.public_key()).serial_number(100).not_valid_before(now-dt.timedelta(days=10)).not_valid_after(now+dt.timedelta(days=10)).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(key,hashes.SHA256())
        leaf=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"Leaf")])).issuer_name(ca_name).public_key(key.public_key()).serial_number(101).not_valid_before(now-dt.timedelta(days=2)).not_valid_after(now+dt.timedelta(days=2)).sign(key,hashes.SHA256())
        other=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"Other")])).issuer_name(ca_name).public_key(key.public_key()).serial_number(102).not_valid_before(now-dt.timedelta(days=2)).not_valid_after(now+dt.timedelta(days=2)).sign(key,hashes.SHA256())
        responder=x509.CertificateBuilder().subject_name(responder_name).issuer_name(ca_name).public_key(signer_key.public_key()).serial_number(103).not_valid_before(now-dt.timedelta(days=2)).not_valid_after(now+dt.timedelta(days=2)).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),critical=False).add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,encipher_only=False,decipher_only=False),critical=True).sign(key,hashes.SHA256())
        # OCSP producedAt is assigned when each response is signed, not at test setup.
        evaluation=(now+dt.timedelta(minutes=2)).isoformat()+"Z"
        with TemporaryDirectory() as folder:
            pem=Path(folder)/"certs.pem";pem.write_bytes(leaf.public_bytes(serialization.Encoding.PEM)+ca.public_bytes(serialization.Encoding.PEM))
            path=Path(folder)/"response.der"
            def make(target=leaf,status=ocsp.OCSPCertStatus.GOOD,signing_key=signer_key,signing_cert=responder):
                revtime=now-dt.timedelta(hours=1) if status==ocsp.OCSPCertStatus.REVOKED else None
                reason=x509.ReasonFlags.key_compromise if revtime else None
                builder=ocsp.OCSPResponseBuilder().add_response(target,ca,hashes.SHA1(),status,now-dt.timedelta(minutes=1),now+dt.timedelta(days=1),revtime,reason).responder_id(ocsp.OCSPResponderEncoding.HASH,signing_cert).certificates([signing_cert])
                path.write_bytes(builder.sign(signing_key,hashes.SHA256()).public_bytes(serialization.Encoding.DER))
            make()
            self.assertEqual(inspect(pem,path,evaluation)["revocation_status"],"GoodAtEvaluationTime")
            make(status=ocsp.OCSPCertStatus.REVOKED)
            self.assertEqual(inspect(pem,path,evaluation)["revocation_status"],"Revoked")
            make(target=other)
            self.assertEqual(inspect(pem,path,evaluation)["revocation_status"],"Unavailable")
            make()
            self.assertEqual(inspect(pem,path,(now+dt.timedelta(days=3)).isoformat()+"Z")["revocation_status"],"Unavailable")
            attacker=rsa.generate_private_key(public_exponent=65537,key_size=2048)
            forged=x509.CertificateBuilder().subject_name(responder_name).issuer_name(ca_name).public_key(attacker.public_key()).serial_number(104).not_valid_before(now-dt.timedelta(days=2)).not_valid_after(now+dt.timedelta(days=2)).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),critical=False).add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,encipher_only=False,decipher_only=False),critical=True).sign(attacker,hashes.SHA256())
            make(signing_key=attacker,signing_cert=forged)
            self.assertEqual(inspect(pem,path,evaluation)["revocation_status"],"Unavailable")

if __name__=="__main__": unittest.main()
