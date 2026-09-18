#requires -Version 7.0
# Issue once, then regenerate signed public revocation artifacts without new keys.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OpenSslPath,
    [string]$AuthorityDirectory=(Join-Path $env:LOCALAPPDATA 'LanPilot/identity/authority-v1'),
    [Parameter(Mandatory)][string]$OutputDirectory,
    [switch]$IssueMac,
    [string]$MacCsr,
    [string]$MacAddress
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not $IsWindows){throw 'CurrentUser DPAPI requires Windows.'}
foreach($path in @($OpenSslPath,$AuthorityDirectory,$OutputDirectory)){
    if(-not [IO.Path]::IsPathFullyQualified($path) -or $path -match '[\x00-\x1f]'){throw 'Absolute local paths required.'}
}
if(Test-Path -LiteralPath $OutputDirectory){throw 'Output directory must be new.'}
$directory=[IO.Path]::GetFullPath($AuthorityDirectory)
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$acl=Get-Acl -LiteralPath $directory
if(-not $acl.AreAccessRulesProtected){throw 'Authority DACL must be protected.'}
foreach($rule in $acl.Access){
    if($rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @($sid,'S-1-5-18')){throw 'Unexpected authority ACL principal.'}
}
$serverDirectory=Join-Path $directory 'mac-server'
$serverCertificate=Join-Path $serverDirectory 'server.pem'
if($IssueMac){
    if(Test-Path -LiteralPath $serverDirectory){throw 'Mac issuance already exists; refusing duplicate issuance.'}
    if(-not [IO.Path]::IsPathFullyQualified($MacCsr) -or (Get-Item -LiteralPath $MacCsr).Length -gt 65536){throw 'Bounded absolute CSR required.'}
    $ip=$null
    if(-not [Net.IPAddress]::TryParse($MacAddress,[ref]$ip) -or
       $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $ip.ToString() -cne $MacAddress){throw 'Canonical LAN IPv4 required for certificate SAN.'}
    $octets=$ip.GetAddressBytes()
    if(-not ($octets[0] -eq 10 -or $octets[0] -eq 127 -or ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or ($octets[0] -eq 192 -and $octets[1] -eq 168))){throw 'Private LAN address required.'}
} elseif(-not (Test-Path -LiteralPath $serverCertificate -PathType Leaf)){throw 'Issue a Mac identity first.'}
# Serialize issuance/refresh against this same tool. This is not an OS-wide CA.
$lock=[IO.File]::Open((Join-Path $directory 'maintenance.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
$secret=$null
try {
    Add-Type -AssemblyName System.Security.Cryptography.ProtectedData
    $secret=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes((Join-Path $directory 'authority-passphrase.dpapi')),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    function Invoke-Crypto([string[]]$Arguments) {
        $start=[Diagnostics.ProcessStartInfo]::new($OpenSslPath)
        $start.UseShellExecute=$false; $start.CreateNoWindow=$true
        $start.RedirectStandardInput=$true; $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
        foreach($argument in $Arguments){$start.ArgumentList.Add($argument)}
        $process=[Diagnostics.Process]::Start($start)
        try {
            $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
            if($Arguments -contains 'stdin'){$process.StandardInput.WriteLine([Text.Encoding]::UTF8.GetString($secret))}
            $process.StandardInput.Close()
            if(-not $process.WaitForExit(30000)){$process.Kill();throw 'Certificate maintenance timed out.'}
            $output=$stdout.GetAwaiter().GetResult(); $null=$stderr.GetAwaiter().GetResult()
            if($process.ExitCode){throw ('Certificate maintenance failed: '+$process.ExitCode)}
            return $output
        } finally {$process.Dispose()}
    }
    $authority=Join-Path $directory 'authority.pem'
    $config=Join-Path $directory 'authority.cnf'
    $client=Join-Path $directory 'windows-client/client.pem'
    if($IssueMac){
        $null=Invoke-Crypto @('req','-in',$MacCsr,'-verify','-noout')
        $null=New-Item -ItemType Directory -Path $serverDirectory
        $extensionPath=Join-Path $serverDirectory 'server-ext.cnf'
        [IO.File]::WriteAllText($extensionPath,@"
[ server ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = IP:$MacAddress
"@,[Text.UTF8Encoding]::new($false))
        $null=Invoke-Crypto @('ca','-batch','-config',$config,'-extfile',$extensionPath,'-extensions','server','-passin','stdin','-in',$MacCsr,'-out',$serverCertificate,'-notext')
    }
    $null=Invoke-Crypto @('verify','-purpose','sslserver','-CAfile',$authority,$serverCertificate)
    $null=New-Item -ItemType Directory -Path $OutputDirectory
    Copy-Item -LiteralPath (Join-Path $directory 'root.der') -Destination (Join-Path $OutputDirectory 'root.der')
    Copy-Item -LiteralPath $serverCertificate -Destination (Join-Path $OutputDirectory 'server.pem')
    Copy-Item -LiteralPath (Join-Path $directory 'windows-client/client.der') -Destination (Join-Path $OutputDirectory 'client.der')
    $null=Invoke-Crypto @('x509','-in',$serverCertificate,'-outform','DER','-out',(Join-Path $OutputDirectory 'server.der'))
    $ocsp=Join-Path $OutputDirectory 'client-ocsp.der'
    $null=Invoke-Crypto @('ocsp','-index',(Join-Path $directory 'index.txt'),'-CA',$authority,'-rsigner',$authority,'-rkey',(Join-Path $directory 'authority-key.encrypted.pem'),'-passin','stdin','-issuer',$authority,'-cert',$client,'-respout',$ocsp,'-ndays','7','-no_nonce')
    $status=Invoke-Crypto @('ocsp','-respin',$ocsp,'-issuer',$authority,'-cert',$client,'-CAfile',$authority,'-no_nonce')
    if($status -notmatch ': good[\r\n]'){throw 'Signed client OCSP status is not good; no deployable bundle produced.'}
    $crl=Join-Path $OutputDirectory 'revocation.pem'
    $null=Invoke-Crypto @('ca','-config',$config,'-gencrl','-passin','stdin','-out',$crl)
    $null=Invoke-Crypto @('crl','-in',$crl,'-noout','-verify','-CAfile',$authority)
    $null=Invoke-Crypto @('crl','-in',$crl,'-outform','DER','-out',(Join-Path $OutputDirectory 'revocation.der'))
    $files=@('root.der','server.pem','server.der','client.der','client-ocsp.der','revocation.pem','revocation.der')
    $hashes=[ordered]@{}
    foreach($file in $files){$hashes[$file]=(Get-FileHash -LiteralPath (Join-Path $OutputDirectory $file) -Algorithm SHA256).Hash.ToLowerInvariant()}
    # Manifest written LAST: failed or partial bundles are never marked ready.
    [IO.File]::WriteAllText((Join-Path $OutputDirectory 'bundle.json'),([ordered]@{schema=1;createdUtc=[DateTime]::UtcNow.ToString('o');refreshBeforeUtc=[DateTime]::UtcNow.AddDays(6).ToString('o');files=$hashes} | ConvertTo-Json -Depth 4))
    Write-Output 'trust_bundle=verified public_only=1 validity_days=7 automatic_refresh=0'
} finally {
    if($secret){[Array]::Clear($secret,0,$secret.Length)}
    $lock.Dispose()
}
