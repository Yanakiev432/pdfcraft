import unittest
from eidas_chain_acceptance import timestamp
class AcceptanceTests(unittest.TestCase):
    def test_timezone(self):
        self.assertEqual(timestamp("2026-10-17T23:00:00+03:00").isoformat(), "2026-10-17T20:00:00+00:00")
    def test_naive_rejected(self):
        with self.assertRaises(ValueError): timestamp("2026-10-17T20:00:00")
if __name__ == '__main__': unittest.main()
