# Craft Signer v2 — unified authenticated resolver acceptance

Date: 14 November 2026
Project: PdfCraft v0.21.1 isolated QA branch
Branch: qa/craft-signer-certificates-v0211-20261113
Security scope: Windows-only, saved-PDF read-only verification; no signing.

## Root cause and correction

The previous PdfCraft v2 client duplicated Windows publisher-approval,
signed-manifest, version-registration and broker-only SHA-256 checks. That
was neither equivalent to the WordCraft/GridCraft shared host resolver nor
subject to its known-defective v0.2.1 minimum-version rejection.

The PdfCraft production client now calls
craft_signing_core::installed_broker::resolve_installed_broker() from the
EXACT, immutable dependency revision:
8428d93bfae3572aa719754ced0e4e6d727790ae
It reads the OS user LocalAppData known folder rather than trusting a
caller-supplied LOCALAPPDATA environment variable; requires existing
owner approval, matches publisher SPKI pin and detached CMS catalog,
rejects version below 0.2.2, verifies the exact active release, guards
reparse paths, refuses unknown release entries, hashes all three executable
workers and retains the read-only/no-delete handles until after process
creation. No approval policy is created by the resolver.

The independent PdfCraft .NET CMS parser remains test-only for
interoperability/tamper regression tests; it is no longer an alternative
production trust/launch implementation.

## RSA compatibility

PdfCraft 0.21.1 used rsa =0.10.0-rc.18; the shared core uses stable
rsa =0.10.0. This QA branch changes only PdfCraft's Rust dependency and
the two public RSA alias/bit-width API spellings; it does not replace
signature algorithms or add signing capabilities. The locked resolver
necessarily refreshes some transitive packages. The full cryptographic
signing library unit suite was executed after this lockfile change.

The saved-PDF SHA-256 reader now also enforces the configured byte limit
throughout reading, rejecting a file that grows while being hashed.

## Windows acceptance results

- cargo check -p pdfcraft-sign --locked --offline: PASS, exit 0.
- cargo test -p pdfcraft-sign --lib --locked --offline:
  128 passed, 0 failed, 2 ignored (opt-in/source-resource tests).
- Real .NET detached CMS 0.2.2 catalog acceptance in the independent
  PdfCraft test parser: PASS, exit 0, with manifest/CMS/certificate
  tamper and wrong publisher-key rejection.
- cargo check -p pdfcraft-automation -p pdfcraft-cli -p pdfcraft-ui-egui
  --locked --offline: PASS, exit 0.
- cargo test -p pdfcraft-automation
  craft_signer_qes_tool_is_read_only_root_confined_and_fail_closed
  --lib --locked --offline: PASS (1/1), exit 0.
- Shared-core source suite: 35 normal tests and 4 real signed-package
  opt-in tests PASS; Clippy -D warnings PASS. The shared-core dual
  signed 0.2.1/0.2.2 test confirms known-defective 0.2.1 is rejected
  while properly signed 0.2.2 is accepted, and broker mutation/invalid
  registration fail closed.

## Remaining gates

The source/build tests do NOT prove a live installed-module QES PASS.
Before a production release: obtain explicit owner review/approval of
the publisher key, install the separately signed 0.2.2 module without
adding an untrusted developer certificate to Windows Trusted Root,
configure and pin the HTTPS EU DSS validation policy, confirm authorized
B-Trust PDF verification through the installed PdfCraft CLI and GUI,
and separately test updates, rollbacks and rollback-resistant policy.

All tests to date use isolated QA worktrees or disposable test roots.
No live Craft module registration, owner approval, publisher trust store,
token PIN, production app installation or personal signed document was
changed or copied into the repository.

## Final CLI and GUI integration acceptance

Windows build/check commands against the final shared-core revision:
- cargo build -p pdfcraft-cli --locked --offline: PASS, exit 0.
- cargo check -p pdfcraft-ui-egui -p pdfcraft-automation
  --locked --offline: PASS, exit 0.
- The independent pdfcraft-sign 128/128 cryptographic library suite and
  actual .NET CMS interop passed after the stable RSA lockfile migration.
  They used the immediately preceding shared resolver source revision,
  fafbc0b993abbb80df8457d1af2a019077ac3429. The final revision
  only changes missing-install error handling; the final UI/CLI code
  compiled and the final CLI was executed against that exact revision.

Newly built CLI SHA-256:
8D2A1CF6F88C349831188B35C60B7732A4A2C6399148208201A5A3148EFFE5BD

Real CLI process smoke test using an unchanged synthetic unsigned 455-byte
PDF: 8/8 PASS, exit 0:
- Read-only automation tool is discoverable.
- CLI opens the synthetic PDF successfully.
- File outside the explicitly allowed root is rejected.
- Fresh Windows profile without installed module receives a clear
  "Craft Signer is not installed with an approved publisher" denial.
- No false QES PASS is reported.
- Original PDF SHA-256 is identical before and after verification.
- No live Craft Signer current.json registration was created or changed.
- No live owner publisher approval policy was created or changed.

Synthetic PDF SHA-256:
078C73981CA352B7A778B8E4C1E83631DF8C7F323828304CD39EA55C743D643E

Sanitized local-only executable QA receipt:
target/craft-signer-smoke/unified-cli-smoke-20261114.json
The first smoke test correctly refused a missing module but surfaced an
ambiguous missing-root diagnostic. This was fixed centrally in the
new shared-core revision before rebuilding and passing the final 8/8 run.

This is a source and CLI acceptance only: no production installation,
user approval, EU DSS service start or real B-Trust QES validation occurred.