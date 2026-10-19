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
Write-Output "OFFLINE_RFC3161_PROVIDER_POLICY_TESTS_PASS=$passed"
