# Craft Signer shared verification adapter — headless and GUI QA

Date: 2026-11-13
Status: **isolated source QA, not installed or released**
Base: PdfCraft 0.21.1, `qa/craft-signer-certificates-v0211-20261113`
Signer package: locally signed Craft Signer Module 0.2.1-qa, accepted in disposable install QA.

## Implemented architecture

* The verified Windows broker client is now `pdfcraft-sign::craft_signer_client`.
* PdfCraft's existing Signatures panel calls the same client asynchronously; the GUI
  remains unchanged except for the opt-in **Check QES with Craft Signer (QA)** action.
* `pdfcraft-automation` registers `sign_craft_qes_check` as a read-only tool,
  dispatched through the ordinary PdfCraft automation table. Its `path` argument
  is resolved under existing `--root` and agent read-root restrictions before any
  module interaction.
* `pdfcraft-cli run sign_craft_qes_check path=<saved.pdf> --root <allowed-dir>`
  and opt-in MCP clients invoke that same action. The tool reports
  `qes_passed`, `code`, `message`, `source_sha256`, and
  `native_pdfcraft_validation_unchanged`.
* No PIN or password travels over the broker protocol. There is no automatic
  network listener, service, agent connection, trust-store import or signing.
* The client independently checks the approved developer publisher public key,
  detached CMS manifest, exact release/worker hashes and saved PDF SHA-256.
  A contradictory result, unauthorized document path or absent module fails closed.
* Qualified status is attributed only to the configured EU DSS policy, not inferred
  from a valid CMS signature, certificate issuer or visible PDF signature.

## Accepted QA results

* `cargo check -p pdfcraft-sign -p pdfcraft-automation -p pdfcraft-ui-egui --locked --offline`: PASS, exit 0.
* `cargo test -p pdfcraft-sign craft_signer_client::tests --lib --locked --offline`:
  **PASS: 10/10**, covering positive and negative verdicts, mismatched UUID,
  network paths, catalog leaf constraints and changed PDF bytes.
* Windows automation integration/root-confinement test: PASS, exit 0;
  rejects traversal; accepts canonical DOS file resolution; fails closed when the
  module-specific approved publisher is not installed.
* pdfcraft-cli v0.21.1 compiled with MCP enabled: PASS, exit 0.
* CLI real-process synthetic PDF smoke: 7/7 PASS. The tool is discoverable,
  the PDF opens, out-of-root files are refused, the missing publisher policy
  gives the correct denial, and exact SHA-256 and live module state are untouched.
* The Windows canonical extended-drive-path bug was repaired: local drive
  aliases normalize to ordinary DOS paths for the C# broker; UNC, device
  volumes, junctions and symlinks remain rejected.
* The signed standalone 0.2.1 installer and disposable uninstall acceptance are
  separately documented in the signer repo's
  `docs/CRAFT_SIGNER_V021_SIGNED_PACKAGE_QA_20261113.md`.

## Gates before end-to-end acceptance and release

1. Obtain explicit publisher approval and register the separately signed module
   on the authorized Windows host; do **not** fabricate a policy or install trust roots.
2. Configure the pinned HTTPS 127.0.0.1 EU DSS validator with current policies.
3. Validate a real authorized B-Trust signed PDF via the installed module, both
   `pdfcraft-cli run` and the native Signatures UI; compare exact file hashes.
4. Exercise app updates, module rotation/rollback, negative GUI behaviour and
   CI acceptance before requesting official upstream host support.

Do not mark an installed or public product PASS based on these source QA tests.
