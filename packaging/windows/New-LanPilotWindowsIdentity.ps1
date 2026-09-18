#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OpenSslPath,
    [string]$AuthorityDirectory=(Join-Path $env:LOCALAPPDATA 'LanPilot/identity/authority-v1'),
    [switch]$ResumePending
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not $IsWindows){throw 'Windows CNG and CurrentUser DPAPI required.'}
if(-not [IO.Path]::IsPathFullyQualified($OpenSslPath) -or -not (Test-Path -LiteralPath $OpenSslPath -PathType Leaf)){throw 'Specify an absolute existing OpenSSL executable.'}
$directory=[IO.Path]::GetFullPath($AuthorityDirectory)
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$acl=Get-Acl -LiteralPath $directory
if(-not $acl.AreAccessRulesProtected){throw 'Authority requires a protected DACL.'}
foreach($rule in $acl.Access){
    if($rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @($sid,'S-1-5-18')){throw 'Unexpected authority ACL principal.'}
}
$clientDirectory=Join-Path $directory 'windows-client'
$manifestPath=Join-Path $clientDirectory 'identity.json'
if(Test-Path -LiteralPath $clientDirectory){
    if(-not $ResumePending){throw 'Client provisioning already exists; refusing identity replacement.'}
    $manifest=[IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json -AsHashtable
    if($manifest.stage -ne 'pending' -or $manifest.keyName -notmatch '\ALanPilot-TLS-client-[0-9a-f]{32}\z' -or
        $manifest.provider -ne 'Microsoft Software Key Storage Provider' -or $manifest.store -ne 'CurrentUser/My'){
        throw 'Only the recorded pending identity can be resumed.'
    }
    $keyName=$manifest.keyName
} else {
    if($ResumePending){throw 'No pending identity exists.'}
    $null=New-Item -ItemType Directory -Path $clientDirectory
    $keyName='LanPilot-TLS-client-'+[Guid]::NewGuid().ToString('N')
    $manifest=[ordered]@{schema=1;stage='pending';keyName=$keyName;provider='Microsoft Software Key Storage Provider';store='CurrentUser/My'}
    [IO.File]::WriteAllText($manifestPath,($manifest | ConvertTo-Json))
}
$parameters=[Security.Cryptography.CngKeyCreationParameters]::new()
$parameters.Provider=[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
$parameters.ExportPolicy=[Security.Cryptography.CngExportPolicies]::None
$parameters.KeyUsage=[Security.Cryptography.CngKeyUsages]::Signing -bor [Security.Cryptography.CngKeyUsages]::Decryption
$parameters.Parameters.Add([Security.Cryptography.CngProperty]::new('Length',[BitConverter]::GetBytes(3072),[Security.Cryptography.CngPropertyOptions]::None))
$key=if($ResumePending){[Security.Cryptography.CngKey]::Open($keyName,$parameters.Provider)}
    else{[Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::Rsa,$keyName,$parameters)}
$rsa=[Security.Cryptography.RSACng]::new($key)
$secret=$null; $certificate=$null; $identity=$null; $store=$null
try {
    if($key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None){throw 'Client key unexpectedly exportable.'}
    $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=LanPilot Windows Client',$rsa,
        [Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $csr=Join-Path $clientDirectory 'client.csr'
    if(-not (Test-Path -LiteralPath $csr)){[IO.File]::WriteAllText($csr,$request.CreateSigningRequestPem(),[Text.UTF8Encoding]::new($false))}
    Add-Type -AssemblyName System.Security.Cryptography.ProtectedData
    $secret=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes((Join-Path $directory 'authority-passphrase.dpapi')),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    $certificatePath=Join-Path $clientDirectory 'client.pem'
    $start=[Diagnostics.ProcessStartInfo]::new($OpenSslPath)
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true; $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
    foreach($argument in @('ca','-batch','-config',(Join-Path $directory 'authority.cnf'),'-extensions','client','-passin','stdin','-in',$csr,'-out',$certificatePath,'-notext')){$start.ArgumentList.Add($argument)}
    if(-not (Test-Path -LiteralPath $certificatePath)){
    $process=[Diagnostics.Process]::Start($start)
    try {
        $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
        $process.StandardInput.WriteLine([Text.Encoding]::UTF8.GetString($secret)); $process.StandardInput.Close()
        if(-not $process.WaitForExit(30000)){$process.Kill(); throw 'Client signing timed out.'}
        $null=$stdout.GetAwaiter().GetResult(); $null=$stderr.GetAwaiter().GetResult()
        if($process.ExitCode){throw ('Client signing failed: '+$process.ExitCode)}
    } finally {$process.Dispose()}
    }
    $certificate=[Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem([IO.File]::ReadAllText($certificatePath))
    $identity=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($certificate,$rsa)
    Import-Module (Join-Path $PSScriptRoot 'TlsConnectionSettings.psm1') -Force
    Assert-LanPilotClientIdentity $identity
    $store=[Security.Cryptography.X509Certificates.X509Store]::new('My','CurrentUser')
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $store.Add($identity)
    $manifest.stage='installed'
    $manifest.clientCertificate=$identity.Thumbprint
    $manifest.certificateSha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($identity.RawData)).ToLowerInvariant()
    $manifest.expiresUtc=$identity.NotAfter.ToUniversalTime().ToString('o')
    [IO.File]::WriteAllBytes((Join-Path $clientDirectory 'client.der'),$identity.RawData)
    [IO.File]::WriteAllText($manifestPath,($manifest | ConvertTo-Json))
    Write-Output ('client_identity_installed=1 nonexportable=1 system_trust_modified=0 thumbprint='+$identity.Thumbprint)
} finally {
    if($secret){[Array]::Clear($secret,0,$secret.Length)}
    if($store){$store.Dispose()}; if($identity){$identity.Dispose()}; if($certificate){$certificate.Dispose()}
    $rsa.Dispose(); $key.Dispose()
}
# On partial failure keep the manifest/key for explicit recovery; never blindly
# delete a key that may already be associated with an installed certificate.
