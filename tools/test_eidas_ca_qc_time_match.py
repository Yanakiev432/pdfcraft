import unittest
from eidas_ca_qc_time_match import parse_time
class TimeMatchTests(unittest.TestCase):
    def test_utc(self):
        self.assertEqual(parse_time("2026-10-17T12:00:00Z").isoformat(), "2026-10-17T12:00:00+00:00")
    def test_offset_normalization(self):
        self.assertEqual(parse_time("2026-10-17T15:00:00+03:00").isoformat(), "2026-10-17T12:00:00+00:00")
    def test_naive_timestamp_rejected(self):
        with self.assertRaises(ValueError): parse_time("2026-10-17T12:00:00")
if __name__ == '__main__': unittest.main()
