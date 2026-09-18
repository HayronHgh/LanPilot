Set-StrictMode -Version Latest

function Assert-LanPilotLocalPath([string]$Path) {
    if ($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path -match '[\x00-\x1f"]' -or
        $Path.Substring(2).Contains(':')) { throw 'Use an absolute local drive path (no UNC or alternate stream).' }
}

function Get-LanPilotTlsArguments($Settings) {
    $names=@('schema','transport','host','port','clientCertificate','serverFingerprint','rootDer','crlDer','control','visual')
    foreach($name in $Settings.PSObject.Properties.Name){if($name -cnotin $names){throw 'Unknown TLS setting.'}}
    foreach($name in $names){if($name -cnotin $Settings.PSObject.Properties.Name){throw "Missing TLS setting: $name"}}
    if(($Settings.schema -isnot [int] -and $Settings.schema -isnot [long]) -or $Settings.schema -ne 1 -or $Settings.transport -cne 'tls'){throw 'Unsupported TLS profile schema.'}
    foreach($name in @('host','clientCertificate','serverFingerprint','rootDer','crlDer','control','visual')){
        if($Settings.$name -isnot [string]){throw "TLS setting must be text: $name"}
    }
    if($Settings.host -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$'){throw 'Enter a DNS host or IPv4 address, without an SSH account.'}
    if(($Settings.port -isnot [int] -and $Settings.port -isnot [long]) -or $Settings.port -lt 1 -or $Settings.port -gt 65535){throw 'Port must be an integer from 1 to 65535.'}
    if($Settings.clientCertificate -notmatch '^[0-9a-fA-F]{40}$' -or $Settings.serverFingerprint -notmatch '^[0-9a-fA-F]{64}$'){throw 'Enter the client SHA-1 thumbprint and paired server SHA-256 fingerprint.'}
    foreach($name in @('rootDer','crlDer')){
        Assert-LanPilotLocalPath $Settings.$name
        $file=Get-Item -LiteralPath $Settings.$name -ErrorAction Stop
        if($file.PSIsContainer -or $file.Length -lt 1 -or $file.Length -gt 65536){throw 'DER trust files must contain 1..65536 bytes.'}
    }
    if($Settings.control -cnotin @('view-only','interactive') -or $Settings.visual -cnotin @('h264-only','exact-only')){throw 'Invalid control or visual mode.'}
    # This validates configuration only. Viewer still verifies certificates,
    # revocation, hostname, paired fingerprint and server-granted input rights.
    return @('--tls',$Settings.host,[string]$Settings.port,$Settings.clientCertificate,
        $Settings.serverFingerprint,$Settings.rootDer,$Settings.crlDer,$Settings.control,$Settings.visual)
}

function Read-LanPilotTlsSettings([string]$Path) {
    Assert-LanPilotLocalPath $Path
    $file=Get-Item -LiteralPath $Path -ErrorAction Stop
    if($file.PSIsContainer -or $file.Length -gt 65536){throw 'TLS profile exceeds 64 KiB.'}
    $settings=Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    $null=Get-LanPilotTlsArguments $settings
    return $settings
}

function Save-LanPilotTlsSettings([string]$Path,$Settings) {
    Assert-LanPilotLocalPath $Path
    $null=Get-LanPilotTlsArguments $Settings
    $null=New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force
    $temporary=$Path+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
    try {
        [IO.File]::WriteAllText($temporary,($Settings | ConvertTo-Json),[Text.UTF8Encoding]::new($false))
        if(Test-Path -LiteralPath $Path){[IO.File]::Replace($temporary,$Path,[NullString]::Value)}
        else{[IO.File]::Move($temporary,$Path)}
    } finally {if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary}}
}
function Assert-LanPilotClientIdentity {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
          [DateTime]$NowUtc=[DateTime]::UtcNow)
    if($null -eq $Certificate){throw 'Client certificate was not found in CurrentUser/My.'}
    if(-not $Certificate.HasPrivateKey){throw 'Client certificate has no associated private key.'}
    if($NowUtc -lt $Certificate.NotBefore.ToUniversalTime() -or
       $NowUtc -ge $Certificate.NotAfter.ToUniversalTime()){
        throw 'Client certificate is expired or not yet valid. Renew the paired identity.'
    }
    $clientUsage=$false
    foreach($extension in $Certificate.Extensions){
        if($extension.Oid.Value -eq '2.5.29.37'){
            $eku=[Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($extension,$extension.Critical)
            foreach($oid in $eku.EnhancedKeyUsages){if($oid.Value -eq '1.3.6.1.5.5.7.3.2'){$clientUsage=$true}}
        }
        if($extension.Oid.Value -eq '2.5.29.19'){
            $constraints=[Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($extension,$extension.Critical)
            if($constraints.CertificateAuthority){throw 'A CA certificate cannot be used as the desktop client identity.'}
        }
    }
    if(-not $clientUsage){throw 'Client certificate requires explicit TLS client authentication usage.'}
}

function Test-LanPilotTlsReadiness($Settings) {
    $null=Get-LanPilotTlsArguments $Settings
    # Read-only store access. No import, key export, chain download or trust change.
    $store=[Security.Cryptography.X509Certificates.X509Store]::new('My','CurrentUser')
    $certificates=$null
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor
                    [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
        $certificates=$store.Certificates
        $matches=@($certificates | Where-Object {$_.Thumbprint -ieq $Settings.clientCertificate})
        if($matches.Count -ne 1){throw 'Expected exactly one client certificate in CurrentUser/My. Provision the paired identity first.'}
        Assert-LanPilotClientIdentity $matches[0]
        # HasPrivateKey is only association evidence; actual key access and all
        # remote authentication/revocation checks remain the native TLS gate.
        return [pscustomobject]@{LocalIdentityReady=$true;PeerAuthenticated=$false;ExpiresUtc=$matches[0].NotAfter.ToUniversalTime()}
    } finally {
        if($null -ne $certificates){foreach($certificate in $certificates){$certificate.Dispose()}}
        $store.Dispose()
    }
}
Export-ModuleMember -Function Get-LanPilotTlsArguments,Read-LanPilotTlsSettings,Save-LanPilotTlsSettings,Assert-LanPilotLocalPath,Assert-LanPilotClientIdentity,Test-LanPilotTlsReadiness
