#!/usr/bin/env python3
"""Read-only rollback guard against a previously authenticated local checkpoint.
Checkpoint integrity and provenance MUST be protected by the caller; no auto-trust."""
import datetime as dt, hashlib, json, sys
from pathlib import Path
from eidas_chain_acceptance import metadata
def parse(value):
    result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None: raise ValueError("Timestamp without timezone")
    return result.astimezone(dt.timezone.utc)
def snapshot(eu_path, national_path, at_text):
    """Produce a reproducible, UNTRUSTED baseline; caller must authenticate and protect it."""
    at = parse(at_text)
    def entry(path):
        item = metadata(path, at)
        item["sha256"] = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        return item
    return {"schema": "pdfcraft.eidas.rollback-snapshot.v1",
            "eu": entry(eu_path), "national": entry(national_path),
            "checkpoint_provenance_verified": False,
            "rollback_protection_verified": False,
            "qualification": "Indeterminate"}
def compare(current, previous):
    if not isinstance(current["sequence"], int) or not isinstance(previous["sequence"], int): raise ValueError("Invalid sequence")
    if current["sequence"] < 1 or previous["sequence"] < 1: raise ValueError("Invalid sequence")
    old_date, new_date = parse(previous["issued"]), parse(current["issued"])
    rollback = current["sequence"] < previous["sequence"] or new_date < old_date
    # Identical sequence and issue date are not sufficient to establish
    # identical list contents. Detect substitution when both digests exist.
    old_hash, new_hash = previous.get("sha256"), current.get("sha256")
    for digest in (old_hash, new_hash):
        if digest is not None and (not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)):
            raise ValueError("Invalid SHA-256 digest")
    same_version = current["sequence"] == previous["sequence"]
    equivocation = same_version and (new_date != old_date or (old_hash is not None and new_hash is not None and old_hash != new_hash))
    return {"rollback_detected": rollback, "sequence_equivocation_detected": equivocation,
            "not_older_than_checkpoint": not rollback and not equivocation,
            "checkpoint_provenance_verified": False,
            "content_identity_compared": old_hash is not None and new_hash is not None}
def check(current, baseline):
    return {"eu": compare(current["eu"], baseline["eu"]),
            "national": compare(current["national"], baseline["national"]),
            "rollback_protection_verified": False, "qualification": "Indeterminate"}
if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--snapshot":
        print(json.dumps(snapshot(*sys.argv[2:]), indent=2))
        raise SystemExit(0)
    if len(sys.argv) != 3: raise SystemExit("usage: eidas_rollback_guard.py CURRENT.json PREVIOUS_TRUSTED.json | --snapshot EU.xml BG.xml ISO8601")
    print(json.dumps(check(json.loads(Path(sys.argv[1]).read_text()), json.loads(Path(sys.argv[2]).read_text())), indent=2))
