import unittest
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from eidas_btrust_synthesis import synthesize

class SynthesisTests(unittest.TestCase):
    @patch('eidas_btrust_synthesis.certificate_link_inspect', return_value={'local_link_verified': True, 'full_certificate_path_verified': False})
    @patch('eidas_btrust_synthesis.revocation_inspect')
    @patch('eidas_btrust_synthesis.ca_evaluate')
    @patch('eidas_btrust_synthesis.acceptance')
    def test_synthesis_never_infers_qes_from_good_crl_ocsp_and_ca(self, lists, ca, rev, cert):
        with TemporaryDirectory() as directory:
            bg = Path(directory) / 'bg.xml'
            bg.write_bytes(b'original national list')
            digest = hashlib.sha256(bg.read_bytes()).hexdigest()
            self._exercise_synthesis(lists, ca, rev, str(bg), digest)

    def _exercise_synthesis(self, lists, ca, rev, bg, digest):
        lists.return_value = {'eu_lotl_authenticated_at_evaluation_time': True,
                              'national_tsl_authenticated_via_lotl': True,
                              'eu': {'sequence': 397}, 'national': {'sequence': 64, 'sha256': digest}}
        ca.return_value = {'ca_qc_candidates_unverified': [{'ca_qc': True,
            'granted_at_requested_time_unverified': True, 'matched_der_sha256': ['a'*64]}]}
        rev.return_value = {'schema': 'pdfcraft.eidas.revocation-evidence.v1',
                            'combined_observation': 'ConcordantGoodAtEvaluationTime',
                            'inputs_sha256': {'crl': 'b'*64}}
        result = synthesize('pdf', 'eu', bg, 'pem', 'crl', 'ocsp', '2026-10-18T14:30:00Z')
        self.assertEqual(result['ca_qc_service_candidates_at_evaluation_time'], 1)
        self.assertEqual(result['qualification'], 'Indeterminate')
        self.assertFalse(result['qes_pass'])
        self.assertFalse(result['trusted_signing_time_verified'])
        lists.return_value['national_tsl_authenticated_via_lotl'] = False
        with self.assertRaises(ValueError):
            synthesize('pdf', 'eu', 'bg', 'pem', 'crl', 'ocsp', '2026-10-18T14:30:00Z')

    @patch('eidas_btrust_synthesis.certificate_link_inspect', return_value={'local_link_verified': True})
    @patch('eidas_btrust_synthesis.revocation_inspect')
    @patch('eidas_btrust_synthesis.ca_evaluate')
    @patch('eidas_btrust_synthesis.acceptance')
    def test_national_tsl_swap_is_rejected(self, lists, ca, rev, cert):
        with TemporaryDirectory() as directory:
            bg = Path(directory) / 'bg.xml'
            bg.write_bytes(b'original')
            digest = hashlib.sha256(bg.read_bytes()).hexdigest()
            lists.return_value = {'eu_lotl_authenticated_at_evaluation_time': True,
                                  'national_tsl_authenticated_via_lotl': True,
                                  'eu': {}, 'national': {'sha256': digest}}
            def swap(*args):
                bg.write_bytes(b'substituted')
                return {'ca_qc_candidates_unverified': []}
            ca.side_effect = swap
            with self.assertRaisesRegex(ValueError, 'changed during CA/QC'):
                synthesize('pdf', 'eu', str(bg), 'pem', 'crl', 'ocsp', '2026-10-18T14:30:00Z')
            rev.assert_not_called()

if __name__ == '__main__': unittest.main()