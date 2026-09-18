# PowerShell 7: ephemeral, in-memory certificates only; never imports a key/store.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../packaging/windows/TlsConnectionSettings.psm1') -Force
$key=[Security.Cryptography.RSA]::Create(2048)
$owned=[Collections.Generic.List[IDisposable]]::new()
function New-Identity([string]$Usage,[bool]$IsCa=$false) {
    $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=LanPilot ephemeral workflow',$key,[Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($IsCa,$false,0,$true))
    if($Usage){
        $oids=[Security.Cryptography.OidCollection]::new()
        $null=$oids.Add([Security.Cryptography.Oid]::new($Usage))
        $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids,$true))
    }
    $certificate=$request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5),[DateTimeOffset]::UtcNow.AddMinutes(10))
    $owned.Add($certificate)
    return $certificate
}
function Reject([scriptblock]$Action,[string]$Expected) {
    $message=''
    try {& $Action} catch {$message=$_.Exception.Message}
    if($message -notlike ('*'+$Expected+'*')){throw ('Expected rejection: '+$Expected+'; got: '+$message)}
}
try {
    $valid=New-Identity '1.3.6.1.5.5.7.3.2'
    Assert-LanPilotClientIdentity $valid
    Reject {Assert-LanPilotClientIdentity $null} 'not found'
    $public=[Security.Cryptography.X509Certificates.X509Certificate2]::new($valid.RawData)
    $owned.Add($public)
    Reject {Assert-LanPilotClientIdentity $public} 'no associated private key'
    Reject {Assert-LanPilotClientIdentity $valid -NowUtc $valid.NotBefore.ToUniversalTime().AddTicks(-1)} 'not yet valid'
    Reject {Assert-LanPilotClientIdentity $valid -NowUtc $valid.NotAfter.ToUniversalTime()} 'expired'
    $server=New-Identity '1.3.6.1.5.5.7.3.1'
    Reject {Assert-LanPilotClientIdentity $server} 'client authentication'
    $noEku=New-Identity ''
    Reject {Assert-LanPilotClientIdentity $noEku} 'client authentication'
    $ca=New-Identity '1.3.6.1.5.5.7.3.2' $true
    Reject {Assert-LanPilotClientIdentity $ca} 'CA certificate'
    Write-Output 'PASS identity readiness: valid, missing, public-only, validity boundaries, wrong/missing EKU, CA rejected; store_writes=0 network=0'
} finally {
    foreach($item in $owned){$item.Dispose()}
    $key.Dispose()
}
