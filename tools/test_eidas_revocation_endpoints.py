import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from eidas_revocation_endpoints import inventory
class RevocationEndpointTests(unittest.TestCase):
    def test_missing_certificate_rejected(self):
        with TemporaryDirectory() as folder:
            path=Path(folder)/"empty.pem";path.write_text("")
            with self.assertRaises(ValueError): inventory(path)
if __name__ == '__main__': unittest.main()
