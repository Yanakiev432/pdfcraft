#!/usr/bin/env python3
"""Single-run offline B-Trust eIDAS evidence synthesis, conservative by construction."""
import argparse
import json
from eidas_chain_acceptance import acceptance
from eidas_ca_qc_time_match import evaluate as ca_evaluate
from eidas_revocation_report import inspect as revocation_inspect

SCHEMA = 'pdfcraft.eidas.btrust-evidence-synthesis.v1'

def synthesize(pdf, eu_xml, bg_xml, pem, crl, ocsp, evaluation_time):
    lists = acceptance(eu_xml, bg_xml, evaluation_time)
    if lists.get('eu_lotl_authenticated_at_evaluation_time') is not True or lists.get('national_tsl_authenticated_via_lotl') is not True:
        raise ValueError('EU LOTL / BG TSL chain not authenticated')
    ca = ca_evaluate(pdf, bg_xml, evaluation_time)
    revocation = revocation_inspect(pem, crl, ocsp, evaluation_time)
    if revocation.get('schema') != 'pdfcraft.eidas.revocation-evidence.v1':
        raise ValueError('Unexpected revocation evidence schema')
    candidates = ca.get('ca_qc_candidates_unverified')
    if not isinstance(candidates, list):
        raise ValueError('Missing CA/QC candidates')
    matched = [x for x in candidates if x.get('ca_qc') is True and x.get('granted_at_requested_time_unverified') is True]
    # No caller-supplied or document-declared time is a trusted signing time.
    return {
        'schema': SCHEMA,
        'evaluation_time_claim': evaluation_time,
        'eu_lotl_authenticated': True,
        'bg_tsl_authenticated_via_lotl': True,
        'trusted_lists': {'eu': lists['eu'], 'national': lists['national']},
        'ca_qc_service_candidates_at_evaluation_time': len(matched),
        'ca_qc_candidate_cert_sha256': sorted({digest for x in matched for digest in x.get('matched_der_sha256', [])}),
        'revocation_observation': revocation['combined_observation'],
        'revocation_evidence_sha256': revocation['inputs_sha256'],
        'trusted_signing_time_verified': False,
        'full_certificate_path_verified': False,
        'qscd_independently_verified': False,
        'revocation_at_trusted_signing_time_verified': False,
        'rollback_protection_verified': False,
        'qes_pass': False,
        'qualification': 'Indeterminate',
    }

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ('pdf', 'eu_xml', 'bg_xml', 'pem', 'crl', 'ocsp', 'evaluation_time'):
        parser.add_argument(arg)
    args = parser.parse_args()
    print(json.dumps(synthesize(args.pdf, args.eu_xml, args.bg_xml, args.pem,
                                args.crl, args.ocsp, args.evaluation_time), indent=2))