# B-Trust signed-PDF QCStatements inventory — 2026-10-17

Read-only extraction from the end-entity certificate embedded in the locally signed B-Trust test PDF. This document intentionally omits personal identity fields.

Parsed ETSI QCStatements OIDs:

| OID | Meaning |
| --- | --- |
| `1.3.6.1.5.5.7.11.2` | Additional legacy ETSI statement; statementInfo present |
| `0.4.0.1862.1.1` | QcCompliance declared |
| `0.4.0.1862.1.4` | QcSSCD declared |
| `0.4.0.1862.1.5` | QcPDS present with statementInfo |
| `0.4.0.1862.1.6` | QcType present with statementInfo |

The presence of QcSSCD is a declaration in the certificate, **not independently verified QSCD hardware evidence**. `QcType` statementInfo has not yet been fully decoded or validated. Certificate revocation and trusted signing time have not been established. The result is `Indeterminate`.
