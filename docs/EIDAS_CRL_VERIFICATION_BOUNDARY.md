# CRL validation boundary

`tools/eidas_crl_verify.py` verifies the CRL signature with the embedded issuer public key, matches the issuer DN, checks CRL freshness against a caller-supplied UTC time, and looks up the leaf serial.

`GoodAtEvaluationTime` means **not listed in this verified CRL at the supplied evaluation time**, not complete qualified-signature revocation evidence.

Still required: authenticate the issuer chain and applicable trust-list service; verify CA/CRL-sign key usage, AKI/SKI and indirect/delta CRL rules; check critical CRL extensions and scope, CRL distribution point binding, historical status, trusted time, and OCSP policy. The input time is caller-supplied. Missing CRL yields no result, never Good.

No personal signer information or test certificate private keys are committed.
