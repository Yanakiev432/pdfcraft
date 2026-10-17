# Trusted-list rollback guard: security boundary

`tools/eidas_rollback_guard.py` is a read-only comparator for a previously recorded, **independently protected and authenticated** checkpoint. It does not create, authenticate, persist, or approve that checkpoint.

The comparator rejects lower sequence numbers, earlier issue dates, and inconsistent dates at an unchanged sequence number. Equal sequence/date does not establish byte-for-byte equality, and a higher sequence is not by itself evidence of authenticity.

Production requirements before setting `rollback_protection_verified=true`: store an authenticated checkpoint in tamper-resistant or authenticated storage, bind the checkpoint to a canonical list identity and territory, preserve hashes of authenticated XML bytes, require monotonic update rules, verify update signature and certificate pivots, and handle clock trust and recovery procedures. Until then the reported flag remains false.

No eIDAS qualified signature verdict is produced.
