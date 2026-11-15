# This body is embedded with a build-time inventory. It is not a general updater.
# The native setup holds the embedded archive/driver read-only until we exit.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
function Assert-LanPilotPersonalPair([string]$ProfilePath){
    if(-not (Test-Path -LiteralPath $ProfilePath -PathType Leaf)){throw 'This personal package requires this computer''s existing paired connection. No identities or settings were created.'}
    $settings=Read-LanPilotTlsSettings $ProfilePath
    $ready=Test-LanPilotTlsReadiness $settings
    if(-not $ready.LocalIdentityReady){throw 'The existing paired identity is not ready. Its normal renewal/validation must complete first.'}
}
$locks=[Collections.Generic.List[IDisposable]]::new()
try {
    if($args.Count -ne 1 -or $args[0] -cnotin @('install','verify','pair-check')){throw 'Invalid setup operation.'}
    $verify=$args[0] -ceq 'verify'
    $pairCheck=$args[0] -ceq 'pair-check'
    Add-Type -AssemblyName System.IO.Compression
    $root=Join-Path $PSScriptRoot 'payload'
    $null=New-Item -ItemType Directory -Path $root -ErrorAction Stop
    $inputFile=[IO.File]::OpenRead((Join-Path $PSScriptRoot 'payload.zip'))
    $zip=[IO.Compression.ZipArchive]::new($inputFile,[IO.Compression.ZipArchiveMode]::Read)
    try {
        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        [long]$total=0
        foreach($entry in $zip.Entries){
            $name=$entry.FullName
            if(-not $expected.ContainsKey($name) -or -not $seen.Add($name) -or
               $name -cnotmatch '^[A-Za-z0-9._-]+$' -or $entry.Length -lt 1 -or
               $entry.Length -gt 268435456){throw 'Unexpected setup package member.'}
            $total+=$entry.Length
            if($total -gt 536870912){throw 'Setup package exceeds size limit.'}
            $file=[IO.File]::Open((Join-Path $root $name),[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
            $stream=$entry.Open()
            try{$stream.CopyTo($file)}finally{$stream.Dispose();$file.Dispose()}
            $file=[IO.File]::Open((Join-Path $root $name),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            $locks.Add($file)
            if($file.Length -ne $entry.Length){throw 'Incomplete setup member.'}
            $file.Position=0
            $sha=[Security.Cryptography.SHA256]::Create()
            try{$hash=([BitConverter]::ToString($sha.ComputeHash($file))).Replace('-','').ToLowerInvariant()}
            finally{$sha.Dispose()}
            if($hash -cne $expected[$name]){throw 'Setup package integrity check failed.'}
        }
        if($seen.Count -ne $expected.Count){throw 'Incomplete setup package.'}
    }finally{$zip.Dispose();$inputFile.Dispose()}
    if($verify){Write-Output 'setup_package=PASS';exit 0}
    $personal=$false
    if(Test-Path variable:personalExistingPair){$personal=[bool]$personalExistingPair}
    if($personal){
        Import-Module (Join-Path $root 'TlsConnectionSettings.psm1') -Force
        $profile=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'LanPilot\connections\default.json'
        Assert-LanPilotPersonalPair $profile
        Write-Output 'personal_pair=ready keys_copied=0 settings_changed=0 peer_validation=required'
    }elseif($pairCheck){throw 'Pair-check is available only in the existing-pair personal package.'}
    if($pairCheck){exit 0}
    Write-Output 'Installing verified program files. Existing connection settings and device keys are retained.'
    & (Join-Path $root 'Install-DesktopPreview.ps1') -ProductVersion $productVersion
    if(-not $?){throw 'Installation did not complete.'}
    Write-Output 'setup_install=PASS'
    exit 0
}catch {
    Write-Output ('Setup could not finish: '+$_.Exception.Message)
    Write-Output 'Close an active LanPilot connection before retrying. Existing trust checks remain enabled.'
    exit 1
}finally{foreach($lock in $locks){$lock.Dispose()}}
