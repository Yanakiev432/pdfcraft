# PKCS#11 disposable software-token integration gate

Status: NOT EXECUTED. Unit tests do not establish that C_Sign works.
No production key, certificate, PIN or physical token is allowed.

## Preconditions
1. Obtain a trusted PKCS#11 software-token module; verify origin and checksum.
2. Provision a disposable test token and key pair in an isolated directory.
3. Set PDFCRAFT_TEST_PKCS11_MODULE to the trusted absolute module path.
4. Record module version, mechanisms, slot ID, public certificate and CKA_ID.
   Never record a PIN.
5. A module without CKF_PROTECTED_AUTHENTICATION_PATH cannot test the
   protected-authentication signer. Do not bypass this production restriction.

## Read-only discovery gate
Run from repository root in PowerShell:

    $env:PDFCRAFT_TEST_PKCS11_MODULE = 'C:\absolute\trusted\test-pkcs11.dll'
    & "$env:USERPROFILE\.cargo\bin\cargo.exe" test -p pdfcraft-sign --lib pkcs11::tests::opt_in_software_token_read_only_discovery -- --ignored --exact
    Remove-Item Env:PDFCRAFT_TEST_PKCS11_MODULE

Expected: initialized token slot and exit code 0. An unconfigured test is
ignored, not passed. A module with no token must fail this gate.

## Signing and verification gate (pending)
1. Confirm the test token supports protected authentication.
2. Match a public certificate to exactly one private key by CKA_ID.
3. Perform test-only CKM_RSA_PKCS SHA-256 C_Sign and independently verify.
4. If supported, perform CKM_ECDSA C_Sign, convert raw r||s to DER, verify.
5. Sign a disposable PDF; validate CMS and signed byte ranges, and confirm
   that modifying the PDF invalidates the signature.
6. Test absent slot, wrong CKA_ID, duplicate match, unsupported mechanism,
   cancellation and token removal. All must fail closed.

Do not mark this gate complete until a real disposable module, key,
C_Sign operation and independent verification have actually run.