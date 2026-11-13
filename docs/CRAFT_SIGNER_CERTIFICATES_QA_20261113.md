# Craft Signer → PdfCraft 0.21.1: Certificates/Signatures QA adapter

Date: 2026-11-13
Branch: `qa/craft-signer-certificates-v0211-20261113`
Base: upstream `v0.21.1` (`b503b2e62dfeec5598f344e4e287d9c9cbdb34fa`)
Status: **QA SOURCE ONLY; not installed, not accepted for production**.

## Contract

PdfCraft's existing `RightPanel::Signatures` displays a read-only
**Check QES with Craft Signer (QA)** action on Windows only. The native
PdfCraft signature validator remains untouched. PDF signing still uses
the native signing UI. An unsaved or dirty document cannot be checked.

The opt-in action uses the one-shot `craft-signer-broker.exe` stdio
`document.verify` protocol v1. It does not send passwords, PINs or
certificate secrets. The broker is an independently installed module,
not an executable bundled with or copied into PdfCraft.

The bridge only resolves this fixed module ID:
`%LOCALAPPDATA%\Craft\Extensions\org.craftopensource.signer`.
Before executing any binary it requires:

* an explicit module-local publisher policy with public-key SHA-256;
* approved `current.json`, protocol v1, valid release-leaf and a
  signed-catalog-derived release directory name;
* one detached CMS publisher signature, the exact publisher certificate,
  valid certificate dates, the approved SubjectPublicKeyInfo SHA-256,
  SHA-256 content digest, matching module version and expected commands;
* exactly three known workers and a matching broker SHA-256;
* no filesystem reparse points on the resolved path, and a no-write/no-delete
  open handle on the broker through `CreateProcess`.

One UUID-tagged JSON request is sent over inherited stdin. Replies must
match the protocol, UUID and document kind. QES PASS requires
`PDF_QES_PASS`, status `ok`, exact source SHA-256, indication
`TOTAL_PASSED`, qualification `QESig` and
`qualifiedSignatureConfirmed=true`. Unknown or contradictory reports
cannot display QES PASS. The file is hashed before and after broker
verification and the display rechecks it. The broker itself validates
the configured pinned HTTPS local EU DSS service.

## Known non-acceptance

At creation time the Lenovo had no active module registration, publisher
approval policy or module PDF DSS policy. The previous real B-Trust
`PAdES-BASELINE-B` result was confirmed in the **isolated DSS QA path**
on 2026-11-13, not through this PdfCraft GUI adapter.

This source branch does not install the module or alter official
PdfCraft binaries. The original `pdfcraft-signatures` working tree and
its untracked `tools/__pycache__` remain untouched.

Before a real GUI PASS:

1. Build/check the 0.21.1 QA branch in a private Windows environment.
2. Run synthetic fail-closed Rust tests, including tampered catalogs,
   changed binaries, missing installations and hostile PDF replies.
3. Prepare a separately signed 0.2.1 module package, accept the local
   publisher policy deliberately, then perform safe disposable installation QA.
4. Verify the real B-Trust signed PDF through the installed module with
   local pinned HTTPS EU DSS; inspect the actual GUI response.
5. Prove host update/rollback and official maintainer acceptance of a
   persistent host contract before shipping.
6. Add a supported headless automation tool and end-to-end test before
   calling the feature shipped, as the upstream AGENTS.md requires.

No production or official installed application was modified.
