# Code signing policy — Yanakiev432 PdfCraft QES fork

Status: draft / pre-application; no code-signing sponsor has approved this fork.
Last review: 2026-10-19

## Project and provenance

- Upstream signed releases: https://github.com/storytold/pdfcraft (publisher stated upstream: Learning Machines Inc / LLC).
- Actual public GitHub fork: https://github.com/Yanakiev432/pdfcraft
- Development branch: `feature/universal-signature-providers`, currently under draft pull request https://github.com/Yanakiev432/pdfcraft/pull/1.
- Reusable provider and Office-format contracts: https://github.com/Yanakiev432/craft-signing-core/pull/1.
- The trademark, artwork and upstream attribution requirements must be reviewed before public redistribution of modified binaries.

## Signing-team roles

- Maintainer / code author: GitHub owner `Yanakiev432`.
- Reviewer / signing approver: not independently assigned. A one-person project cannot assert that a distinct peer has reviewed a change.
- No external signing service approval, identity vetting or trust-chain certificate is held by the fork.
- A real release requires an explicit manual approval, code review, verified dependency provenance, final source hash and an independent signing service decision.

## Release procedure

1. Freeze a reviewed release branch based on a signed upstream release; freeze Cargo.lock and all external dependencies.
2. Check repository content, attribution, security, copyright, and review the exact diff against the upstream signed release. Do not claim an unreviewed inherited patch is covered by a prior code review.
3. Build in an authorized Windows release environment, with WiX v5 and Windows SDK; no disabling or modifying Smart App Control on Yanakiev-Lenovo.
4. Sign the actual EXE, CLI, DLL (if any) and MSI using a trusted authorized code-signing provider, with a trusted timestamp. A personal B-Trust document QES is not an acceptable substitute without an actual Code Signing EKU/issuer contract.
5. Run `packaging/windows/package.ps1 -Arch x64 -RequireTrustedRelease`. This fails closed when the actual files lack proper Authenticode/Code Signing EKU/timestamp.
6. On an SAC-enforced Windows test machine, verify installation, GUI, open signed PDF, independent EU DSS result, tamper rejection, uninstallation and rollback.
7. Publish signed hashes (SHA-256) and original signed release files on the actual fork release page.

## User security and privacy

- Do not read/export smartcard private keys; PIN entry occurs only in the authorized token provider's own UI.
- Signed private user documents and GUI screenshots containing personal data must not be uploaded to the public repository.
- EU DSS QES verification uses opt-in loopback-local transport and does not send signed PDFs to public services.
- Future remote signing providers require separate published, reviewable privacy notices; upstream update and other network-related functionality must be audited before a full no-network claim.
- Installer/uninstaller changes must be documented; no hidden root trust changes, no WDAC policy modifications, no self-signed root import.

## SignPath Foundation pre-application conditions

The project may seek the open-source signing program at https://signpath.org/. Under the published policy, modified upstream forks can qualify only if the upstream releases signed binaries, the fork is visibly a GitHub fork, the release branch is based on a normally signed upstream branch, all upstream-change review and other conditions are fulfilled, and the application is **approved**. A fork and signed upstream do not prove eligibility or automatically grant a certificate.

If SignPath Foundation formally approves this project, update this policy and release pages with its required attribution and actual signing roles, including the exact prescribed sentence about SignPath.io and SignPath Foundation. Do **not** display "Free code signing provided by SignPath.io" as a current fact before formal approval.

## Current decision

NO-GO for public trusted MSI signing. The artifact will remain a local unsigned preview until legitimate Code Signing and artifact verification succeed. The stage is not PAdES-LT/LTA issuance, which has independent evidence and trusted timestamp requirements.
