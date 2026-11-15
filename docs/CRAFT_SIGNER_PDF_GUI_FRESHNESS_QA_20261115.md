# PdfCraft Craft Signer — asynchronous GUI freshness acceptance

Date: 2026-11-15
Branch: qa/pdfcraft-signer-view-freshness-20261115
Base: 606fc58ea2d45d82413cf92d06c5ab6800d323bf
Status: WINDOWS CPU-ONLY SOURCE QA PASS. NOT a production QES acceptance.

## What was already available

The PdfCraft Signatures right-hand panel already had a Windows QA button
which dispatched read-only PDF verification through pdfcraft-sign's
craft_signer_client. That code uses the shared, signed, publisher-approved
Craft Signer v0.2.2-or-newer module resolver (same as WordCraft/GridCraft),
and binds the independent EU DSS verdict to the saved PDF SHA-256.
The previous version had verified UI source integration and CLI smoke,
but this does NOT mean an approved module was installed.

## Defects identified

1. The Signatures panel invoked FileStamp::read on every UI repaint
   through State::unchanged. This re-hashed the entire PDF (up to 64 MiB)
   on the UI thread at frame rate, causing avoidable I/O, CPU load and
   potentially visible rendering stalls.
2. Async verification could finish after a document switch. A switch
   away and back to the original path could allow the old result to be
   displayed again. Polling only inside the visible Signatures panel
   could also defer processing until the panel was reopened.

## Changes

- The per-frame freshness predicate now checks metadata only and
  rejects missing files, reparse points and observed length/mtime changes.
- The already authenticated verify_pdf broker path retains its pre/post
  full-file SHA-256. The UI never performs that hash during painting.
- While the Signatures panel is visible, a separate background worker
  re-hashes saved bytes at most once every 5 seconds; if the digest or
  metadata changed, cached evidence is permanently invalidated.
- Failure, panic or a freshness worker running for 30 seconds causes a
  fail-closed result (checked by the UI logic on subsequent frames).
- Document changes are observed from PdfCraftApp logic even if the
  Signatures panel is hidden. An observed tab switch or unsaved edit
  invalidates pending and completed verdicts until explicit recheck.
- The old verified result is never reinstated simply because the
  user returns to the previously active document.
- Native PDF signing, personal certificate trust, installed Craft
  products, owner approval policy, QES token PIN and Windows root stores
  are NOT modified.

## Windows acceptance evidence

All executions on authorized Lenovo, offline/locked Cargo and CPU only.

1. cargo check -p pdfcraft-ui-egui -p pdfcraft-sign --locked --offline
   PASS; exit 0.
2. cargo test -p pdfcraft-ui-egui craft_signer::tests --lib --locked --offline
   4 passed; 0 failed; exit 0. Tests:
   - switching tabs away and back never restores old QES status
   - external disk edit invalidates the displayed evidence
   - pending worker success is rejected after document change
   - asynchronous SHA-256 comparison rejects same-size byte substitution
3. cargo test -p pdfcraft-sign craft_signer_client --lib --locked --offline
   10 passed; 0 failed; 1 ignored; exit 0.
   The ignored opt-in .NET signed-catalog fixture was not executed in
   this run and is not described as PASS.
4. Pre-existing Cargo patch warnings and one unrelated vendored
   hayro-interpret unused import were observed; no new source errors.

The tests use synthetic PDF-like saved byte fixtures for UI-state and
digest behavior. None of the tests obtains a B-Trust PIN or confirms
an actual QES qualification against a live installed module.

## Residual security and release gates

- A displayed verifier result is evidence for the saved bytes at the
  completed check, NOT immutable proof of the current file forever.
  Between the 5-second background rehashes, an attacker able to forge
  both file size and modified time could temporarily evade the cheap
  metadata check. A later completed SHA-256 mismatch invalidates it.
- This does not provide an atomic Windows immutable file snapshot, a
  kernel-level watcher, a privileged anti-rollback ledger or a trusted
  production QES signer.
- No performance benchmark is claimed; the removal of synchronous
  frame-rate rehashing is verified from code paths and CPU-only tests.
- Before production, explicitly approve the module publisher key;
  install the signed module under the owner-controlled policy; verify
  real B-Trust PDF through independently pinned HTTPS EU DSS; test
  genuine native GUI and CLI workflows, updates, rollback and UX.
- No Windows certificate trust-store changes, GPU renderer, document
  modifications or production installation are authorized by this QA.