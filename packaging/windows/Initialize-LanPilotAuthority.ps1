#requires -Version 7.0
# Explicit provisioning operation: private application authority, NOT OS root trust.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OpenSslPath,
    [string]$AuthorityDirectory=(Join-Path $env:LOCALAPPDATA 'LanPilot/identity/authority-v1')
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not $IsWindows){throw 'Windows CurrentUser DPAPI is required.'}
if(-not [IO.Path]::IsPathFullyQualified($OpenSslPath) -or -not (Test-Path -LiteralPath $OpenSslPath -PathType Leaf)){throw 'Specify an existing absolute OpenSSL executable.'}
if($AuthorityDirectory -notmatch '\A[A-Za-z]:[\\/]' -or $AuthorityDirectory -match '["$\x00-\x1f]' -or $AuthorityDirectory.Substring(2).Contains(':')){throw 'Unsupported authority directory.'}
$directory=[IO.Path]::GetFullPath($AuthorityDirectory)
if(Test-Path -LiteralPath $directory){throw 'Authority already exists; refusing key replacement.'}
$ancestor=[IO.Path]::GetDirectoryName($directory)
while($ancestor){
    if(Test-Path -LiteralPath $ancestor){
        if((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Authority ancestors cannot be reparse points.'}
    }
    $ancestor=[IO.Path]::GetDirectoryName($ancestor)
}
$null=New-Item -ItemType Directory -Path $directory
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true,$false)
foreach($principal in @($sid,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))){
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','ContainerInherit, ObjectInherit','None','Allow'))
}
Set-Acl -LiteralPath $directory -AclObject $acl
# Verify the effective explicit DACL before writing any secret material.
$actual=Get-Acl -LiteralPath $directory
if(-not $actual.AreAccessRulesProtected){throw 'Authority ACL inheritance remained enabled.'}
foreach($rule in $actual.Access){
    if($rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @($sid.Value,'S-1-5-18')){throw 'Unexpected authority ACL principal.'}
}
Add-Type -AssemblyName System.Security.Cryptography.ProtectedData
$random=[byte[]]::new(32)
[Security.Cryptography.RandomNumberGenerator]::Fill($random)
$passphrase=[Convert]::ToBase64String($random)
$secret=[Text.Encoding]::UTF8.GetBytes($passphrase)
$sealed=[Security.Cryptography.ProtectedData]::Protect($secret,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
[IO.File]::WriteAllBytes((Join-Path $directory 'authority-passphrase.dpapi'),$sealed)
function Invoke-AuthorityOpenSsl([string[]]$Arguments) {
    $start=[Diagnostics.ProcessStartInfo]::new($OpenSslPath)
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true; $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
    foreach($argument in $Arguments){$start.ArgumentList.Add($argument)}
    $process=[Diagnostics.Process]::Start($start)
    try {
        $stdout=$process.StandardOutput.ReadToEndAsync()
        $stderr=$process.StandardError.ReadToEndAsync()
        if($Arguments -contains 'stdin'){$process.StandardInput.WriteLine($passphrase)}
        $process.StandardInput.Close()
        if(-not $process.WaitForExit(30000)){$process.Kill(); throw 'OpenSSL authority operation timed out.'}
        $null=$stdout.GetAwaiter().GetResult(); $null=$stderr.GetAwaiter().GetResult()
        if($process.ExitCode -ne 0){throw ('OpenSSL authority operation failed: '+$process.ExitCode)}
    } finally {$process.Dispose()}
}
try {
    $key=Join-Path $directory 'authority-key.encrypted.pem'
    $certificate=Join-Path $directory 'authority.pem'
    Invoke-AuthorityOpenSsl @('genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:3072','-aes-256-cbc','-pass','stdin','-out',$key)
    Invoke-AuthorityOpenSsl @('req','-new','-x509','-key',$key,'-passin','stdin','-sha256','-days','1825',
        '-subj','/CN=LanPilot Local Pairing Authority','-addext','basicConstraints=critical,CA:TRUE,pathlen:0',
        '-addext','keyUsage=critical,keyCertSign,cRLSign','-addext','subjectKeyIdentifier=hash','-out',$certificate)
    Invoke-AuthorityOpenSsl @('x509','-in',$certificate,'-outform','DER','-out',(Join-Path $directory 'root.der'))
    $null=New-Item -ItemType Directory -Path (Join-Path $directory 'issued')
    [IO.File]::WriteAllText((Join-Path $directory 'index.txt'),'')
    [IO.File]::WriteAllText((Join-Path $directory 'serial'),"01`n")
    [IO.File]::WriteAllText((Join-Path $directory 'crlnumber'),"01`n")
    $opensslDirectory=$directory.Replace('\','/')
    $config=@"
[ ca ]
default_ca = lanpilot
[ lanpilot ]
dir = "$opensslDirectory"
database = `$dir/index.txt
new_certs_dir = `$dir/issued
certificate = `$dir/authority.pem
private_key = `$dir/authority-key.encrypted.pem
serial = `$dir/serial
crlnumber = `$dir/crlnumber
default_md = sha256
default_days = 90
default_crl_days = 7
policy = identity_name
unique_subject = no
copy_extensions = none
[ identity_name ]
commonName = supplied
[ client ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
"@
    [IO.File]::WriteAllText((Join-Path $directory 'authority.cnf'),$config,[Text.UTF8Encoding]::new($false))
    Invoke-AuthorityOpenSsl @('ca','-config',(Join-Path $directory 'authority.cnf'),'-gencrl','-passin','stdin','-out',(Join-Path $directory 'revocation.pem'))
    Invoke-AuthorityOpenSsl @('crl','-in',(Join-Path $directory 'revocation.pem'),'-outform','DER','-out',(Join-Path $directory 'revocation.der'))
    $root=[Security.Cryptography.X509Certificates.X509Certificate2]::new((Join-Path $directory 'root.der'))
    try {
        Write-Output ('authority_created=1 system_trust_modified=0 root_sha256='+[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($root.RawData)).ToLowerInvariant())
    } finally {$root.Dispose()}
} finally {
    [Array]::Clear($secret,0,$secret.Length); [Array]::Clear($random,0,$random.Length)
    $passphrase=$null
}
