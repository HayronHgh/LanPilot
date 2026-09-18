# Generates configuration only. Never loads a job or provisions trust/keys.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputPath,
    [Parameter(Mandatory)][string]$MacHome,
    [Parameter(Mandatory)][string]$AgentPath,
    [Parameter(Mandatory)][string]$BindAddress,
    [ValidateRange(1024,65535)][int]$Port=45443,
    [Parameter(Mandatory)][string]$IdentityReference,
    [Parameter(Mandatory)][string]$ClientFingerprint,
    [Parameter(Mandatory)][string]$RootDerPath,
    [Parameter(Mandatory)][string]$ClientOcspPath,
    [ValidateSet('view-only','interactive')][string]$Control='view-only',
    [ValidateSet('h264-only','exact-only')][string]$Visual='h264-only'
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Assert-MacPath([string]$Value) {
    if($Value.Length -gt 1024 -or $Value -notmatch '^/Users/[^/]+/.+' -or
       $Value -match '[\x00-\x1f\x7f\\]' -or $Value -match '//|/(\.|\.\.)(/|$)' -or
       $Value.EndsWith('/')) {throw 'Expected canonical absolute Mac user path'}
}
if($MacHome -notmatch '^/Users/[A-Za-z0-9._-]+$' -or $MacHome -match '/\.\.?$'){
    throw 'Expected explicit /Users/account home'
}
foreach($value in @($AgentPath,$RootDerPath,$ClientOcspPath)) {
    Assert-MacPath $value
    if(-not $value.StartsWith($MacHome+'/',[StringComparison]::Ordinal)) {
        throw 'Service resources must belong to the specified user home'
    }
}
if($AgentPath -eq $RootDerPath){throw 'Agent and trust root paths must differ'}
if($ClientOcspPath -eq $AgentPath -or $ClientOcspPath -eq $RootDerPath){throw 'OCSP response requires a separate path'}
if($IdentityReference -notmatch '\A(?:[0-9a-fA-F]{2}){1,4096}\z'){
    throw 'Invalid Keychain persistent identity reference'
}
if($ClientFingerprint -notmatch '\A[0-9a-fA-F]{64}\z'){
    throw 'Expected client certificate SHA-256'
}
# Limit this initial service tool to explicit RFC1918 or loopback IPv4.
# No wildcard, DNS lookup, public exposure, shorthand, or implicit interface.
$address=$null
if(-not [Net.IPAddress]::TryParse($BindAddress,[ref]$address) -or
   $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
   $address.ToString() -cne $BindAddress){throw 'Expected canonical numeric LAN IPv4'}
$octets=$address.GetAddressBytes()
if(-not ($octets[0] -eq 10 -or $octets[0] -eq 127 -or
    ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or
    ($octets[0] -eq 192 -and $octets[1] -eq 168))){throw 'Bind must be private LAN or loopback'}
if(-not [IO.Path]::IsPathRooted($OutputPath) -or $OutputPath -match '[\x00-\x1f\x7f]'){
    throw 'Output must be absolute'
}
if($env:OS -eq 'Windows_NT' -and $OutputPath -notmatch '\A[A-Za-z]:[\\/][^:]*\z'){
    throw 'Output must be a local absolute drive path without ADS'
}
$outputFull=[IO.Path]::GetFullPath($OutputPath)
if(-not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($outputFull))){throw 'Output parent must exist'}
$settings=[Xml.XmlWriterSettings]::new()
$settings.Indent=$true
$settings.Encoding=[Text.UTF8Encoding]::new($false)
$buffer=[IO.MemoryStream]::new()
$xml=[Xml.XmlWriter]::Create($buffer,$settings)
try {
    $xml.WriteStartDocument()
    $xml.WriteStartElement('plist'); $xml.WriteAttributeString('version','1.0')
    $xml.WriteStartElement('dict')
    function Entry([string]$Name,[string]$Type,[string]$Value) {
        $xml.WriteElementString('key',$Name); $xml.WriteElementString($Type,$Value)
    }
    Entry 'Label' 'string' 'com.lanpilot.desktop-tls'
    $xml.WriteElementString('key','ProgramArguments'); $xml.WriteStartElement('array')
    foreach($argument in @($AgentPath,'--stream-visual-tls',$BindAddress,
        $Port.ToString([Globalization.CultureInfo]::InvariantCulture),$IdentityReference,
        $ClientFingerprint.ToLowerInvariant(),$RootDerPath,$Control,$Visual,$ClientOcspPath)){
        $xml.WriteElementString('string',$argument)
    }
    $xml.WriteEndElement()
    Entry 'LimitLoadToSessionType' 'string' 'Aqua'
    Entry 'RunAtLoad' 'true' ''
    Entry 'KeepAlive' 'true' ''
    Entry 'ThrottleInterval' 'integer' '10'
    Entry 'Umask' 'integer' '63'
    Entry 'WorkingDirectory' 'string' $MacHome
    # No unbounded diagnostic files until a bounded log sink exists.
    Entry 'StandardOutPath' 'string' '/dev/null'
    Entry 'StandardErrorPath' 'string' '/dev/null'
    $xml.WriteEndElement(); $xml.WriteEndElement(); $xml.WriteEndDocument(); $xml.Flush()
    $bytes=$buffer.ToArray()
} finally {$xml.Dispose(); $buffer.Dispose()}
$file=[IO.File]::Open($outputFull,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try {$file.Write($bytes,0,$bytes.Length); $file.Flush()} finally {$file.Dispose()}
Write-Output 'launch_agent_configuration=created installed=0 started=0 trust_modified=0'
