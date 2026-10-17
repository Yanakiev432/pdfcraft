import unittest
from eidas_lotl_oj_anchor import PINS
class JournalPins(unittest.TestCase):
    def test_six_unique_sha256_pins(self):
        self.assertEqual(len(PINS), 6)
        self.assertTrue(all(len(x) == 64 and all(c in "0123456789abcdef" for c in x) for x in PINS))
    def test_current_signer_is_officially_pinned(self):
        self.assertIn("e0a620fbb6747362bb933ac44169d676a553444716cf5f31605f12a22b8396b1", PINS)
if __name__ == '__main__': unittest.main()
