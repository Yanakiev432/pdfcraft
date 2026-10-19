#requires -Version 7.0
# Offline policy regression checks: never creates a socket or requests a timestamp.
$ErrorActionPreference='Stop'
$probe=Join-Path $PSScriptRoot 'rfc3161_provider_probe.ps1'
$cases=@(
    @{Name='ACCV requires personal-use confirmation'; Args=@{Provider='accv-personal'}; Match='ConfirmPersonalUse'},
    @{Name='APED not available for synthetic probe'; Args=@{Provider='aped'}; Match='ValidateSet'},
    @{Name='arbitrary TSA URL cannot be supplied'; Args=@{Provider='https://attacker.invalid'}; Match='ValidateSet'},
    @{Name='invalid timeout rejected before transport'; Args=@{Provider='open-tsa'; TimeoutSeconds=1}; Match='minimum allowed range'}
)
$passed=0
foreach($case in $cases){
    try {
        $params=$case.Args
        & $probe @params | Out-Null
        throw "TEST_FAILURE: request unexpectedly accepted: $($case.Name)"
    } catch {
        $message=$_.Exception.Message
        if($message.StartsWith('TEST_FAILURE:')){throw}
        if($message -notmatch [regex]::Escape($case.Match)){
            throw "TEST_FAILURE: wrong rejection for $($case.Name): $message"
        }
        Write-Output "PASS: $($case.Name)"
        $passed++
    }
}
if($passed -ne $cases.Count){throw "TEST_FAILURE: only $passed tests passed"}
$testRoot=Join-Path ([IO.Path]::GetTempPath()) ("pdfcraft-tsa-policy-"+[Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $testRoot)
try {
    $invalidReq=Join-Path $testRoot 'malformed.tsq'
    [IO.File]::WriteAllBytes($invalidReq,[byte[]](0x30,0x00))
    $existingResponse=Join-Path $testRoot 'already-existing.tsr'
    [IO.File]::WriteAllBytes($existingResponse,[byte[]](0x01))
    $cases=@(
        @{Name='malformed external TimeStampReq rejected before network'; Args=@{Provider='open-tsa';RequestPath=$invalidReq}; Match='Asn'},
        @{Name='existing response cannot be overwritten'; Args=@{Provider='open-tsa';ResponsePath=$existingResponse}; Match='already exists'}
    )
    foreach($case in $cases) {
        try {
            $params=$case.Args
            & $probe @params | Out-Null
            throw "TEST_FAILURE: request unexpectedly accepted: $($case.Name)"
        } catch {
            $message=$_.Exception.Message
            if($message.StartsWith('TEST_FAILURE:')){throw}
            if($case.Name -eq 'malformed external TimeStampReq rejected before network'){
                # The framework's DER decoder exception is locale-sensitive.
                if($message -notmatch 'ASN|DER|sequence|EndOfContent|length|data'){
                    throw "TEST_FAILURE: wrong rejection for $($case.Name): $message"
                }
            } elseif($message -notmatch [regex]::Escape($case.Match)){
                throw "TEST_FAILURE: wrong rejection for $($case.Name): $message"
            }
            Write-Output "PASS: $($case.Name)"
            $passed++
        }
    }
    if([IO.File]::ReadAllBytes($existingResponse)[0] -ne 1){
        throw 'TEST_FAILURE: response file was overwritten'
    }
} finally {Remove-Item -LiteralPath $testRoot -Recurse -Force}
Write-Output "OFFLINE_RFC3161_PROVIDER_POLICY_TESTS_PASS=$passed"
