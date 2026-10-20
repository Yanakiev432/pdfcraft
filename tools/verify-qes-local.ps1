# Read-only independent EU DSS QES check for an already signed PDF.
# Does not sign, request a PIN, alter Windows trust settings, or send files off-host.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$PdfPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$python = 'C:\Users\User\AppData\Local\Programs\Python\Python312\python.exe'
$adapter = Join-Path $PSScriptRoot 'eidas_dss_local_verify.py'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw 'Configured Python 3.12 executable not found.'
}
if (-not (Test-Path -LiteralPath $adapter -PathType Leaf)) {
    throw 'PdfCraft independent DSS adapter not found.'
}
$document = (Resolve-Path -LiteralPath $PdfPath -ErrorAction Stop).ProviderPath
if (-not (Test-Path -LiteralPath $document -PathType Leaf)) {
    throw 'The selected PDF is not a local file.'
}
if ([IO.Path]::GetExtension($document) -ine '.pdf') {
    throw 'Only saved .pdf files are accepted.'
}

# Do not let an inherited endpoint override redirect the signed document elsewhere.
Remove-Item 'Env:PDFCRAFT_DSS_LOCAL_ENDPOINT' -ErrorAction SilentlyContinue
$json = & $python -I $adapter $document
if ($LASTEXITCODE -ne 0) {
    throw 'Independent EU DSS verification failed or the loopback service is unavailable.'
}
$report = ($json -join [Environment]::NewLine) | ConvertFrom-Json
if ($report.schema -ne 'pdfcraft.eidas.independent-dss.v1') {
    throw 'Unrecognized independent EU DSS report schema.'
}
$actualSha = (Get-FileHash -LiteralPath $document -Algorithm SHA256).Hash.ToLowerInvariant()
if ($report.pdf_sha256 -ne $actualSha) {
    throw 'PDF changed since independent DSS verification. Recheck required.'
}
$passed = ($report.independent_dss_qes_pass -eq $true) -and
          ($report.dss_signature_level -ceq 'QESig') -and
          ($report.dss_indication -ceq 'TOTAL_PASSED')
[pscustomobject]@{
    IndependentEUDSS = $(if ($passed) { 'QES PASS' } else { 'NO QES PASS' })
    SignatureLevel = $report.dss_signature_level
    Indication = $report.dss_indication
    PdfSha256 = $actualSha
    Note = 'Native PdfCraft validation is separate. No PAdES-LT/LTA issuance is claimed.'
}
if (-not $passed) {
    throw 'Independent EU DSS did not confirm QES PASS.'
}
