#!/usr/bin/env python3
"""Local transactional high-water marks for externally signed eIDAS checkpoints.

A SQLite file can be replaced or rolled back by a privileged local actor.
Never equate this local diagnostic with independently protected monotonic storage.
"""
import hashlib
import json
import sqlite3
from pathlib import Path
from eidas_rollback_guard import check, check_authenticated_acceptance
from eidas_signed_checkpoint import verified_checkpoint_bytes

SCHEMA = 'pdfcraft.eidas.rollback-snapshot.v1'

def record_signed_checkpoint(db_path, checkpoint_path, signature_path, public_key_path, pinned_key_sha256):
    """Atomically refuse older or equivocated signed checkpoints, then store high-water mark."""
    checkpoint, raw = verified_checkpoint_bytes(checkpoint_path, signature_path, public_key_path, pinned_key_sha256)
    # Validate the entire candidate before opening the database.
    check(checkpoint, checkpoint)
    digest = hashlib.sha256(raw).hexdigest()
    db_path = Path(db_path)
    if not db_path.parent.is_dir():
        raise ValueError('Database parent directory does not exist')
    with sqlite3.connect(db_path, timeout=10, isolation_level=None) as db:
        db.execute('BEGIN IMMEDIATE')
        try:
            db.execute('CREATE TABLE IF NOT EXISTS checkpoint_state (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL, sha256 TEXT NOT NULL, key_pin TEXT NOT NULL)')
            previous = db.execute('SELECT payload, sha256, key_pin FROM checkpoint_state WHERE id=1').fetchone()
            if previous:
                prior = json.loads(previous[0])
                check(prior, prior)
                if hashlib.sha256(previous[0].encode()).hexdigest() != previous[1]:
                    raise ValueError('Local checkpoint state content digest mismatch')
                if previous[2] != pinned_key_sha256:
                    raise ValueError('Checkpoint key pin changed; explicit rotation required')
                finding = check(checkpoint, prior)
                if any(not finding[name]['not_older_than_checkpoint'] for name in ('eu', 'national')):
                    raise ValueError('Signed checkpoint rollback or equivocation detected')
            else:
                finding = None
            canonical = json.dumps(checkpoint, sort_keys=True, separators=(',', ':'))
            db.execute('INSERT INTO checkpoint_state(id,payload,sha256,key_pin) VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,sha256=excluded.sha256,key_pin=excluded.key_pin',
                       (canonical, hashlib.sha256(canonical.encode()).hexdigest(), pinned_key_sha256))
            db.execute('COMMIT')
        except BaseException:
            db.execute('ROLLBACK')
            raise
    return {'schema': 'pdfcraft.eidas.local-high-water.v1',
            'signed_checkpoint_sha256': digest,
            'baseline_signature_verified': True,
            'baseline_signing_key_pin_verified': True,
            'compared_with_existing_local_state': previous is not None,
            'local_monotonic_update_accepted': True,
            'independent_state_integrity_verified': False,
            'rollback_protection_verified': False,
            'qualification': 'Indeterminate'}
def record_authenticated_acceptance(db_path, acceptance_report, checkpoint_path, signature_path, public_key_path, pinned_key_sha256):
    """Admit only a signed checkpoint matching both authenticated current XML lists.

    Caller must obtain acceptance_report from the actual chain verifier, not JSON
    supplied by an untrusted third party. This API cannot prove its provenance.
    """
    signed, _ = verified_checkpoint_bytes(checkpoint_path, signature_path, public_key_path, pinned_key_sha256)
    finding = check_authenticated_acceptance(acceptance_report, signed)
    for name in ('eu', 'national'):
        actual, expected = acceptance_report[name], signed[name]
        for field in ('sequence', 'issued', 'sha256'):
            if actual.get(field) != expected.get(field):
                raise ValueError('Signed checkpoint does not match authenticated current lists')
        if not finding[name]['not_older_than_checkpoint']:
            raise ValueError('Signed checkpoint mismatch or rollback')
    result = record_signed_checkpoint(db_path, checkpoint_path, signature_path, public_key_path, pinned_key_sha256)
    result['current_list_report_consistency_checked'] = True
    result['acceptance_report_provenance_verified_by_store'] = False
    return result