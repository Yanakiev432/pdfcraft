#!/usr/bin/env python3
"""Single-run offline B-Trust eIDAS evidence synthesis, conservative by construction."""
import argparse
import json
import hashlib
from pathlib import Path
from eidas_chain_acceptance import acceptance
from eidas_ca_qc_time_match import evaluate as ca_evaluate
from eidas_revocation_report import inspect as revocation_inspect
from eidas_certificate_path_verify import inspect as certificate_link_inspect
from eidas_root_link_verify import inspect as root_link_inspect
from eidas_pdf_cms_integrity import inspect as pdf_cms_inspect

SCHEMA = 'pdfcraft.eidas.btrust-evidence-synthesis.v1'

def synthesize(pdf, eu_xml, bg_xml, pem, crl, ocsp, evaluation_time, root_pem=None, root_sha256=None, verify_pdf_cms=False):
    lists = acceptance(eu_xml, bg_xml, evaluation_time)
    if lists.get('eu_lotl_authenticated_at_evaluation_time') is not True or lists.get('national_tsl_authenticated_via_lotl') is not True:
        raise ValueError('EU LOTL / BG TSL chain not authenticated')
    # Bind CA/QC matching to the exact national TSL bytes authenticated above.
    if hashlib.sha256(Path(bg_xml).read_bytes()).hexdigest() != lists['national']['sha256']:
        raise ValueError('National TSL changed after authentication')
    ca = ca_evaluate(pdf, bg_xml, evaluation_time)
    if hashlib.sha256(Path(bg_xml).read_bytes()).hexdigest() != lists['national']['sha256']:
        raise ValueError('National TSL changed during CA/QC matching')
    certificate_link = certificate_link_inspect(pem, evaluation_time)
    root_link = None
    if root_pem is not None or root_sha256 is not None:
        if not root_pem or not root_sha256:
            raise ValueError('Root PEM and root SHA-256 must be provided together')
        root_link = root_link_inspect(pem, root_pem, root_sha256, evaluation_time)
    pdf_cms = pdf_cms_inspect(pdf) if verify_pdf_cms else None
    revocation = revocation_inspect(pem, crl, ocsp, evaluation_time)
    if revocation.get('schema') != 'pdfcraft.eidas.revocation-evidence.v1':
        raise ValueError('Unexpected revocation evidence schema')
    candidates = ca.get('ca_qc_candidates_unverified')
    if not isinstance(candidates, list):
        raise ValueError('Missing CA/QC candidates')
    matched = [x for x in candidates if x.get('ca_qc') is True and x.get('granted_at_requested_time_unverified') is True]
    candidate_digests = {digest for x in matched for digest in x.get('matched_der_sha256', [])}
    issuer_tsl_bound = bool(certificate_link.get('local_link_verified') is True and
                            certificate_link.get('issuer_der_sha256') in candidate_digests)
    # The authenticated national TSL can itself identify a CA/QC service certificate.
    # This is distinct from a self-signed root or a caller-supplied root pin.
    # No caller-supplied or document-declared time is a trusted signing time.
    return {
        'schema': SCHEMA,
        'evaluation_time_claim': evaluation_time,
        'eu_lotl_authenticated': True,
        'bg_tsl_authenticated_via_lotl': True,
        'trusted_lists': {'eu': lists['eu'], 'national': lists['national']},
        'ca_qc_service_candidates_at_evaluation_time': len(matched),
        'ca_qc_candidate_cert_sha256': sorted({digest for x in matched for digest in x.get('matched_der_sha256', [])}),
        'certificate_link': certificate_link,
        'issuer_ca_qc_identity_bound_to_authenticated_tsl': issuer_tsl_bound,
        'root_link': root_link,
        'pdf_cms_integrity': pdf_cms,
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
    parser.add_argument('--root-pem', default=None)
    parser.add_argument('--root-sha256', default=None)
    parser.add_argument('--verify-pdf-cms', action='store_true')
    args = parser.parse_args()
    print(json.dumps(synthesize(args.pdf, args.eu_xml, args.bg_xml, args.pem,
                                args.crl, args.ocsp, args.evaluation_time, args.root_pem, args.root_sha256, args.verify_pdf_cms), indent=2))