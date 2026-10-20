import unittest
from eidas_revocation_report import combine

class ReportTests(unittest.TestCase):
    def test_two_good_observations(self):
        self.assertEqual(combine({"revocation_status":"GoodAtEvaluationTime"},{"revocation_status":"GoodAtEvaluationTime"}),"ConcordantGoodAtEvaluationTime")
    def test_revoked_takes_precedence(self):
        self.assertEqual(combine({"revocation_status":"Revoked"},{"revocation_status":"GoodAtEvaluationTime"}),"RevokedObserved")
        self.assertEqual(combine({"revocation_status":"Unavailable"},{"revocation_status":"Revoked"}),"RevokedObserved")
    def test_historical_ambiguity(self):
        self.assertEqual(combine({"revocation_status":"IndeterminateHistorical"},{"revocation_status":"GoodAtEvaluationTime"}),"IndeterminateHistorical")
    def test_missing_observation(self):
        self.assertEqual(combine({"revocation_status":"GoodAtEvaluationTime"},{"revocation_status":"Unavailable"}),"InsufficientOrDiscordant")

if __name__=="__main__": unittest.main()
