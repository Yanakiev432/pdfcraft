#requires -Version 7.0
<#
.SYNOPSIS
  One-shot, source-verifiable RFC 3161 transport and cryptographic smoke test.
.DESCRIPTION
  Sends a synthetic SHA-256 imprint with fresh nonce, or accepts a pre-built .tsq.
  Never sends original PDF bytes. Checks HTTP, DER, CMS signature, imprint, nonce.
  Does NOT validate the eIDAS trust list, certificate chain/revocation or PAdES.
  Open TSA is non-qualified, expressly intended for developer experiments.
  ACCV is for personal use ONLY and requires explicit -ConfirmPersonalUse.
  APED is deliberately excluded from synthetic tests due to its published usage policy.
#>
[CmdletBinding()]
param(
    [ValidateSet('open-tsa', 'accv-personal')]
    [string]$Provider = 'open-tsa',
    [switch]$ConfirmPersonalUse,
    [ValidateRange(2,30)]
    [int]$TimeoutSeconds = 15,
    [string]$RequestPath,
    [string]$ResponsePath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Provider -eq 'accv-personal' -and -not $ConfirmPersonalUse) {
    throw 'ACCV requires -ConfirmPersonalUse; professional or bulk use is not authorized.'
}
$providers = @{
    'open-tsa' = @{Url='https://tsr.open-tsa.eu'; Qualified='NO'; Usage='DEVELOPER_TEST'}
    'accv-personal' = @{Url='http://tss.accv.es:8318/tsa'; Qualified='UNDETERMINED'; Usage='PERSONAL_ONLY'}
}
$profile=$providers[$Provider]
$der=[System.Formats.Asn1.AsnEncodingRules]::DER
$requestedPolicy=$null
if($ResponsePath){
    $destFull=[IO.Path]::GetFullPath($ResponsePath)
    if([IO.File]::Exists($destFull)){throw 'ResponsePath already exists; refusing overwrite'}
    if(-not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($destFull))){
        throw 'ResponsePath parent directory must exist'
    }
    if($RequestPath -and [IO.Path]::GetFullPath($RequestPath) -eq $destFull){
        throw 'RequestPath and ResponsePath must differ'
    }
}
if($RequestPath){
    $requestFile=Get-Item -LiteralPath $RequestPath -ErrorAction Stop
    if(-not $requestFile.PSIsContainer -and $requestFile.Length -gt 0 -and $requestFile.Length -le 1MB){
        $requestBytes=[IO.File]::ReadAllBytes($requestFile.FullName)
    } else {throw 'RequestPath is not a nonempty DER file up to 1 MiB'}
    $requestReader=[System.Formats.Asn1.AsnReader]::new([ReadOnlyMemory[byte]]$requestBytes,$der)
    $query=$requestReader.ReadSequence()
    if($query.ReadInteger() -ne 1){throw 'Unsupported TimeStampReq version'}
    $messageImprint=$query.ReadSequence()
    $digestAlgorithm=$messageImprint.ReadSequence()
    $digestOid=$digestAlgorithm.ReadObjectIdentifier()
    if($digestAlgorithm.HasData){$digestAlgorithm.ReadNull()}
    if($digestAlgorithm.HasData -or $digestOid -ne '2.16.840.1.101.3.4.2.1'){
        throw 'TimeStampReq must use SHA-256'
    }
    $imprint=[byte[]]$messageImprint.ReadOctetString()
    if($imprint.Length -ne 32 -or $messageImprint.HasData){throw 'Invalid SHA-256 messageImprint'}
    $nonce=$null
    $certReq=$false
    $seenCertReq=$false
    while($query.HasData){
        $tag=$query.PeekTag()
        if($tag.TagClass -ne [System.Formats.Asn1.TagClass]::Universal){throw 'Unsupported TimeStampReq extensions'}
        switch($tag.TagValue){
            6 {
                if($null -ne $requestedPolicy){throw 'Repeated TimeStampReq policy'}
                $requestedPolicy=$query.ReadObjectIdentifier()
            }
            2 {
                if($null -ne $nonce){throw 'Repeated TimeStampReq nonce'}
                $nonce=$query.ReadInteger()
            }
            1 {
                if($seenCertReq){throw 'Repeated certReq'}
                $seenCertReq=$true
                $certReq=$query.ReadBoolean()
            }
            default {throw 'Unexpected TimeStampReq field'}
        }
    }
    if($requestReader.HasData -or $null -eq $nonce -or $nonce -le 0 -or -not $certReq){
        throw 'TimeStampReq requires a positive nonce and certReq=true'
    }
    $requestMode='EXTERNAL_TSQ'
}
else {
    $probe = "PdfCraft-RFC3161-synthetic-$([Guid]::NewGuid().ToString('N'))"
    $imprint=[System.Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($probe))
    $nonceBytes=[Security.Cryptography.RandomNumberGenerator]::GetBytes(8)
    $nonceBytes[0]=[byte]($nonceBytes[0] -band 0x7f)
    $nonce=[System.Numerics.BigInteger]::new([byte[]]$nonceBytes,$true,$true)
    if($nonce.IsZero){$nonce=[System.Numerics.BigInteger]::One}
    $writer=[System.Formats.Asn1.AsnWriter]::new($der)
    $writer.PushSequence()|Out-Null
    $writer.WriteInteger(1)
    $writer.PushSequence()|Out-Null
    $writer.PushSequence()|Out-Null
    $writer.WriteObjectIdentifier('2.16.840.1.101.3.4.2.1')
    $writer.WriteNull()
    $writer.PopSequence()|Out-Null
    $writer.WriteOctetString($imprint)
    $writer.PopSequence()|Out-Null
    $writer.WriteInteger($nonce)
    $writer.WriteBoolean($true)
    $writer.PopSequence()|Out-Null
    $requestBytes=$writer.Encode()
    $requestMode='SYNTHETIC'
}
$handler=[Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect=$false
$handler.UseCookies=$false
$client=[Net.Http.HttpClient]::new($handler)
$client.Timeout=[TimeSpan]::FromSeconds($TimeoutSeconds)
$client.MaxResponseContentBufferSize=4MB
try {
    $req=[Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Post,$profile.Url)
    $req.Content=[Net.Http.ByteArrayContent]::new([byte[]]$requestBytes)
    $req.Content.Headers.ContentType=[Net.Http.Headers.MediaTypeHeaderValue]::Parse('application/timestamp-query')
    $resp=$client.SendAsync($req).GetAwaiter().GetResult()
    if([int]$resp.StatusCode -ne 200){throw "TSA HTTP failure: $([int]$resp.StatusCode)"}
    $mime=$resp.Content.Headers.ContentType.MediaType
    if($mime -ne 'application/timestamp-reply' -and $mime -ne 'application/timestamp-response'){
        throw "Unexpected TSA response Content-Type: $mime"
    }
    $responseBytes=$resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
    if($responseBytes.Length -lt 10 -or $responseBytes.Length -gt 4MB){
        throw 'TimeStampResp empty, too short or larger than 4 MiB'
    }
}
finally {$client.Dispose()}
$reader=[System.Formats.Asn1.AsnReader]::new([ReadOnlyMemory[byte]]$responseBytes,$der)
$response=$reader.ReadSequence()
$statusInfo=$response.ReadSequence()
$status=$statusInfo.ReadInteger()
if($status -ne 0 -and $status -ne 1){throw "TSA did not grant token: status $status"}
if(-not $response.HasData){throw 'Granted status without a CMS token'}
$tokenBytes=$response.ReadEncodedValue().ToArray()
if($response.HasData -or $reader.HasData){throw 'TimeStampResp trailing fields/data'}
$cms=[System.Security.Cryptography.Pkcs.SignedCms]::new()
$cms.Decode([byte[]]$tokenBytes)
if($cms.ContentInfo.ContentType.Value -ne '1.2.840.113549.1.9.16.1.4'){
    throw 'CMS content is not RFC 3161 TSTInfo'
}
if($cms.SignerInfos.Count -ne 1){throw 'Expected exactly one TSA CMS signer'}
$cms.CheckSignature($true) # Cryptographic signature only, NOT a trusted certificate path.
$info=[System.Formats.Asn1.AsnReader]::new([ReadOnlyMemory[byte]]$cms.ContentInfo.Content,$der)
$tst=$info.ReadSequence()
if($tst.ReadInteger() -ne 1){throw 'Invalid TSTInfo version'}
$policy=$tst.ReadObjectIdentifier()
if($requestedPolicy -and $policy -ne $requestedPolicy){throw 'TimeStampResp policy differs from TimeStampReq'}
$imprintSeq=$tst.ReadSequence()
$algorithm=$imprintSeq.ReadSequence()
$hashOid=$algorithm.ReadObjectIdentifier()
if($algorithm.HasData){$algorithm.ReadNull()}
if($algorithm.HasData){throw 'Unexpected imprint algorithm parameters'}
$actualImprint=[byte[]]$imprintSeq.ReadOctetString()
if($hashOid -ne '2.16.840.1.101.3.4.2.1' -or
   -not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals($imprint,$actualImprint)){
    throw 'RFC 3161 response imprint differs from requested SHA-256 digest'
}
if($imprintSeq.HasData){throw 'Unexpected messageImprint fields'}
$serial=$tst.ReadInteger()
$genTime=$tst.ReadGeneralizedTime()
$returnedNonce=$null
while($tst.HasData){
    $tag=$tst.PeekTag()
    if($tag.TagClass -eq [System.Formats.Asn1.TagClass]::Universal -and $tag.TagValue -eq 2){
        if($null -ne $returnedNonce){throw 'Duplicate TSTInfo nonce'}
        $returnedNonce=$tst.ReadInteger()
    }
    else {$tst.ReadEncodedValue()|Out-Null}
}
if($info.HasData -or $null -eq $returnedNonce -or $returnedNonce -ne $nonce){
    throw 'TSA response nonce missing, invalid or mismatched'
}
$signerCert=$cms.SignerInfos[0].Certificate
if($null -eq $signerCert){throw 'TSA signer certificate missing'}
$hasEKU=$false
foreach($ext in $signerCert.Extensions){
    if($ext -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]){
        foreach($oid in $ext.EnhancedKeyUsages){
            if($oid.Value -eq '1.3.6.1.5.5.7.3.8'){$hasEKU=$true}
        }
    }
}
if(-not $hasEKU){throw 'TSA signing certificate has no timeStamping EKU'}
if($ResponsePath){
    $parent=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($ResponsePath))
    if(-not [IO.Directory]::Exists($parent)){throw 'Parent directory for -ResponsePath must exist'}
    $output=[IO.File]::Open($ResponsePath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$output.Write([byte[]]$responseBytes,0,$responseBytes.Length)}finally{$output.Dispose()}
}
[pscustomobject]@{
    protocol='RFC3161'
    request_mode=$requestMode
    request_sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($requestBytes)).ToLowerInvariant()
    provider=$Provider
    profile_usage=$profile.Usage
    http_status=200
    bytes=$responseBytes.Length
    pki_status=[string]$status
    sha256_response=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($responseBytes)).ToLowerInvariant()
    cms_signature='PASS'
    imprint_sha256='PASS'
    unpredictable_nonce='PASS'
    tsa_eku='PASS'
    tsa_certificate_sha256=$signerCert.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256)
    policy_oid=$policy
    gen_time_utc=$genTime.ToUniversalTime().ToString('o')
    qualified_eidas='NOT_CHECKED'
    trusted_chain='NOT_CHECKED'
    pades_b_t='NOT_CHECKED'
} | ConvertTo-Json -Depth 5
