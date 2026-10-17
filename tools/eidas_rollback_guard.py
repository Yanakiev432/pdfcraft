#!/usr/bin/env python3
"""Read-only rollback guard against a previously authenticated local checkpoint.
Checkpoint integrity and provenance MUST be protected by the caller; no auto-trust."""
import datetime as dt, json, sys
from pathlib import Path
def parse(value):
    result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None: raise ValueError("Timestamp without timezone")
    return result.astimezone(dt.timezone.utc)
def compare(current, previous):
    if not isinstance(current["sequence"], int) or not isinstance(previous["sequence"], int): raise ValueError("Invalid sequence")
    if current["sequence"] < 1 or previous["sequence"] < 1: raise ValueError("Invalid sequence")
    old_date, new_date = parse(previous["issued"]), parse(current["issued"])
    rollback = current["sequence"] < previous["sequence"] or new_date < old_date
    equivocation = current["sequence"] == previous["sequence"] and new_date != old_date
    return {"rollback_detected": rollback, "sequence_equivocation_detected": equivocation,
            "not_older_than_checkpoint": not rollback and not equivocation,
            "checkpoint_provenance_verified": False}
def check(current, baseline):
    return {"eu": compare(current["eu"], baseline["eu"]),
            "national": compare(current["national"], baseline["national"]),
            "rollback_protection_verified": False, "qualification": "Indeterminate"}
if __name__ == "__main__":
    if len(sys.argv) != 3: raise SystemExit("usage: eidas_rollback_guard.py CURRENT.json PREVIOUS_TRUSTED.json")
    print(json.dumps(check(json.loads(Path(sys.argv[1]).read_text()), json.loads(Path(sys.argv[2]).read_text())), indent=2))
