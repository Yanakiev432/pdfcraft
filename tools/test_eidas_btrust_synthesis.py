import unittest
from unittest.mock import patch
from eidas_btrust_synthesis import synthesize

class SynthesisTests(unittest.TestCase):
    @patch('eidas_btrust_synthesis.revocation_inspect')
    @patch('eidas_btrust_synthesis.ca_evaluate')
    @patch('eidas_btrust_synthesis.acceptance')
    def test_synthesis_never_infers_qes_from_good_crl_ocsp_and_ca(self, lists, ca, rev):
        lists.return_value = {'eu_lotl_authenticated_at_evaluation_time': True,
                              'national_tsl_authenticated_via_lotl': True,
                              'eu': {'sequence': 397}, 'national': {'sequence': 64}}
        ca.return_value = {'ca_qc_candidates_unverified': [{'ca_qc': True,
            'granted_at_requested_time_unverified': True, 'matched_der_sha256': ['a'*64]}]}
        rev.return_value = {'schema': 'pdfcraft.eidas.revocation-evidence.v1',
                            'combined_observation': 'ConcordantGoodAtEvaluationTime',
                            'inputs_sha256': {'crl': 'b'*64}}
        result = synthesize('pdf', 'eu', 'bg', 'pem', 'crl', 'ocsp', '2026-10-18T14:30:00Z')
        self.assertEqual(result['ca_qc_service_candidates_at_evaluation_time'], 1)
        self.assertEqual(result['qualification'], 'Indeterminate')
        self.assertFalse(result['qes_pass'])
        self.assertFalse(result['trusted_signing_time_verified'])
        lists.return_value['national_tsl_authenticated_via_lotl'] = False
        with self.assertRaises(ValueError):
            synthesize('pdf', 'eu', 'bg', 'pem', 'crl', 'ocsp', '2026-10-18T14:30:00Z')

if __name__ == '__main__': unittest.main()