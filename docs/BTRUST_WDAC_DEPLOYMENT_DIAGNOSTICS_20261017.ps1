# Read-only diagnostics; run from elevated PowerShell. Does not modify WDAC.
$ErrorActionPreference = 'Continue'
$report = Join-Path $env:TEMP 'pdfcraft-wdac-diagnostics-20261017.txt'
$lines = @('PdfCraft WDAC diagnostics', ('Date: ' + (Get-Date -Format o)), ('Elevated: ' + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)), '--- WDAC policies ---')
$lines += (& "$env:WINDIR\System32\CiTool.exe" --list-policies 2>&1 | Out-String)
$lines += '--- Recent Code Integrity block events (no certificate data) ---'
$lines += (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational';Id=3077;StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue | Select-Object -First 15 TimeCreated,Id,@{N='BlockedPath';E={if($_.Message -match '(?:[A-Z]:\\[^\r\n]+?\.(?:dll|exe))'){$matches[0]}else{'unknown'}}} | Format-Table -AutoSize | Out-String)
$lines += '--- Executable signature ---'
$lines += (Get-AuthenticodeSignature 'C:\Program Files\PdfCraft\pdfcraft.exe' | Select-Object Status,@{N='Signer';E={$_.SignerCertificate.Subject}} | Format-List | Out-String)
$lines | Set-Content -LiteralPath $report -Encoding UTF8
Write-Output "Report: $report"
