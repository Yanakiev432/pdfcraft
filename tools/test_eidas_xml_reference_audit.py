import tempfile, unittest
from pathlib import Path
from eidas_xml_reference_audit import audit
TSL = "http://uri.etsi.org/02231/v2#"
DS = "http://www.w3.org/2000/09/xmldsig#"
def sample(uri="#target", duplicate=False):
    extra = '<Other Id="target"/>' if duplicate else ""
    return (f'<TrustServiceStatusList xmlns="{TSL}" xmlns:ds="{DS}">'
            f'<Node Id="target"/>{extra}<ds:Signature><ds:SignedInfo>'
            f'<ds:Reference URI=""><ds:DigestMethod Algorithm="x"/><ds:DigestValue>1</ds:DigestValue></ds:Reference>'
            f'<ds:Reference URI="{uri}"><ds:DigestMethod Algorithm="x"/><ds:DigestValue>2</ds:DigestValue></ds:Reference>'
            f'</ds:SignedInfo></ds:Signature></TrustServiceStatusList>').encode()
class AuditTests(unittest.TestCase):
    def check(self, data):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.xml"; p.write_bytes(data); return audit(p)
    def test_valid_shape_is_not_verified(self):
        self.assertFalse(self.check(sample())["xml_signature_verified"])
    def test_duplicate_id_rejected(self):
        with self.assertRaises(ValueError): self.check(sample(duplicate=True))
    def test_external_uri_rejected(self):
        with self.assertRaises(ValueError): self.check(sample(uri="https://example.org/evil"))
    def test_unresolved_uri_rejected(self):
        with self.assertRaises(ValueError): self.check(sample(uri="#missing"))
    def test_dtd_rejected(self):
        with self.assertRaises(ValueError): self.check(b"<!DOCTYPE a><a/>")
if __name__ == '__main__': unittest.main()
