# PdfCraft opt-in local DSS adapter — verified

Entry point: `tools/eidas_dss_local_verify.py`. Uses only an explicit loopback IP URL, fixed REST validation path, no proxies, no redirects, bounded PDF/report sizes. Requires the local DSS 6.5.1 demo service on Windows `127.0.0.1:8080`. The Windows Python 3.12 executable was used because WSL's own 127.0.0.1 does not reach the Windows listener in this configuration.

Example (Windows):
```powershell
& 'C:\Users\User\AppData\Local\Programs\Python\Python312\python.exe' 'C:\Users\User\Documents\GitHub\pdfcraft-signatures\tools\eidas_dss_local_verify.py' 'C:\Users\User\AppData\Local\Temp\pdfcraft-btrust-real-sign-20261017.pdf'
```

Verified real output at `2026-10-18T20:25:03Z`: `independent_dss_qes_pass=true`, `dss_indication=TOTAL_PASSED`, `dss_signature_level=QESig`, `dss_signature_format=PAdES-BASELINE-B`. PDF SHA-256 `3016d0e0cbd7f72fa7dbc4c29685f714176d978f2c300f022c3d617d7abc9c9a`. Raw DSS report SHA-256 `7103c928ba4978c990207c97ec73c985d6a9efd76c3c0f590d2047c6ef2134db`. Raw report not published; may contain PII.

Adapter enforces exactly one signature and one valid signature, and only treats `QESig` + `TOTAL_PASSED` as an independent QES PASS. It does NOT turn on the separate native engine `qes_pass` or assert trusted signing time. Results are from the independent DSS policy at the validation time, not from a timestamp at signature creation. Revalidate on subsequent runs. Never accept a caller-supplied report as proof without obtaining it through the live loopback service.

74/74 `test_eidas_*.py` Python tests pass, including negative DSS adapter cases. This does not implement future PAdES-LT/LTA signing or product UI wiring.
