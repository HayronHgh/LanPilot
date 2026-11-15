#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ConfigPath='',
    [string]$DataRoot='',
    [switch]$EvaluateOnly,
    [switch]$ForceRefresh,
    [datetime]$NowUtc=[DateTime]::UtcNow
)

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'TrustMaintenance.psm1') -Force

function Assert-AbsoluteLocalPath([string]$Path,[string]$Label) {
    if(-not $Path -or $Path -notmatch '^[A-Za-z]:[\\/]' -or $Path.Substring(2).Contains(':')){
        throw "$Label must be an absolute local path."
    }
    $full=[IO.Path]::GetFullPath($Path)
    $cursor=$full
    while($cursor){
        if(Test-Path -LiteralPath $cursor){
            if((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){
                throw "$Label may not traverse a linked path."
            }
        }
        $cursor=[IO.Path]::GetDirectoryName($cursor)
    }
    return $full
}

function Assert-ChildPath([string]$Path,[string]$Parent,[string]$Label) {
    $full=Assert-AbsoluteLocalPath $Path $Label
    $root=[IO.Path]::GetFullPath($Parent).TrimEnd([char[]]@('\','/'))+[IO.Path]::DirectorySeparatorChar
    if(-not $full.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)){
        throw "$Label must remain under $Parent."
    }
    return $full
}

function Assert-Leaf([string]$Path,[string]$Label) {
    $full=Assert-AbsoluteLocalPath $Path $Label
    if(-not (Test-Path -LiteralPath $full -PathType Leaf)){throw "$Label is missing."}
    return $full
}

function Parse-Utc([string]$Value,[string]$Label) {
    $parsed=[datetime]::MinValue
    if(-not [datetime]::TryParse($Value,[Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,[ref]$parsed)){
        throw "$Label is not a canonical timestamp."
    }
    return $parsed.ToUniversalTime()
}

function Write-RenewalLog([string]$Status) {
    $logDirectory=Join-Path $DataRoot 'logs'
    $null=New-Item -ItemType Directory -Path $logDirectory -Force
    $logPath=Join-Path $logDirectory 'trust-renewal.log'
    if((Test-Path -LiteralPath $logPath) -and (Get-Item -LiteralPath $logPath).Length -gt 1048576){
        Move-Item -LiteralPath $logPath -Destination ($logPath+'.previous') -Force
    }
    Add-Content -LiteralPath $logPath -Value (([DateTime]::UtcNow.ToString('o'))+' status='+$Status) -Encoding UTF8
}

if(-not $DataRoot){$DataRoot=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'LanPilot'}
$DataRoot=Assert-AbsoluteLocalPath $DataRoot 'DataRoot'
if(-not $ConfigPath){$ConfigPath=Join-Path $DataRoot 'maintenance\trust-renewal.json'}
$ConfigPath=Assert-ChildPath $ConfigPath (Join-Path $DataRoot 'maintenance') 'ConfigPath'
if(-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)){
    Write-Output 'trust_renewal=not_configured'
    return
}
if((Get-Item -LiteralPath $ConfigPath).Length -gt 32768){throw 'Trust renewal profile exceeds 32 KiB.'}
$config=Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
if($config.schema -ne 1){throw 'Unsupported trust renewal profile schema.'}
if($config.enabled -isnot [bool]){throw 'Trust renewal enabled flag must be boolean.'}
$nextRefreshUtc=Parse-Utc ([string]$config.nextRefreshUtc) 'nextRefreshUtc'
$expiresUtc=Parse-Utc ([string]$config.expiresUtc) 'expiresUtc'
if($expiresUtc -le $nextRefreshUtc){throw 'Trust renewal validity window is invalid.'}
$NowUtc=$NowUtc.ToUniversalTime()
$earlyRefreshUtc=$expiresUtc.AddHours(-72)
if($earlyRefreshUtc -lt $nextRefreshUtc){$nextRefreshUtc=$earlyRefreshUtc}
$status=if(-not $config.enabled){'disabled'}elseif(-not $ForceRefresh -and $NowUtc -lt $nextRefreshUtc){'current'}else{'due'}
if($EvaluateOnly){
    Write-Output "trust_renewal=$status expires_utc=$($expiresUtc.ToString('o')) network=0 crypto=0"
    return
}
if($status -ne 'due'){
    Write-RenewalLog $status
    Write-Output "trust_renewal=$status"
    return
}

$authority=Assert-ChildPath ([string]$config.authorityDirectory) (Join-Path $DataRoot 'identity') 'authorityDirectory'
$localRoot=Assert-ChildPath ([string]$config.localRootDer) (Join-Path $DataRoot 'connections') 'localRootDer'
$localCrl=Assert-ChildPath ([string]$config.localCrlDer) (Join-Path $DataRoot 'connections') 'localCrlDer'
$openSsl=Assert-Leaf ([string]$config.openSslPath) 'openSslPath'
$ssh=Assert-Leaf ([string]$config.sshPath) 'sshPath'
$scp=Assert-Leaf ([string]$config.scpPath) 'scpPath'
$sshKey=Assert-Leaf ([string]$config.sshKey) 'sshKey'
$updateScript=Assert-Leaf (Join-Path $PSScriptRoot 'Update-LanPilotTrustBundle.ps1') 'trust bundle issuer'
foreach($required in @{authorityDirectory=$authority;localRootDer=$localRoot;localCrlDer=$localCrl}.GetEnumerator()){
    if(-not (Test-Path -LiteralPath $required.Value)){throw ('Missing maintenance input: '+$required.Key)}
}
if([string]$config.sshTarget -notmatch '^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+$'){throw 'sshTarget is invalid.'}
foreach($remote in @([string]$config.remoteOcspPath,[string]$config.remoteMaintenanceDirectory)){
    if($remote -notmatch '^/[A-Za-z0-9._/-]+$' -or $remote.Contains('..') -or $remote.Contains('//')){
        throw 'Remote maintenance path is invalid.'
    }
}
if(-not ([string]$config.remoteOcspPath).EndsWith('/client-ocsp.der',[StringComparison]::Ordinal)){
    throw 'remoteOcspPath must target client-ocsp.der.'
}
if([string]$config.launchAgentDomain -notmatch '^gui/[0-9]+$' -or
   [string]$config.launchAgentLabel -notmatch '^[A-Za-z0-9._-]+$'){
    throw 'LaunchAgent identity is invalid.'
}
$tlsPort=[int]$config.tlsPort
if($tlsPort -lt 1 -or $tlsPort -gt 65535){throw 'tlsPort is invalid.'}

$maintenance=Join-Path $DataRoot 'maintenance'
$null=New-Item -ItemType Directory -Path $maintenance -Force
$lock=[IO.File]::Open((Join-Path $maintenance 'trust-renewal.lock'),[IO.FileMode]::OpenOrCreate,
    [IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
try {
    $stamp=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    $bundle=Join-Path $maintenance ('trust-refresh-'+$stamp+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8))
    $stage='issuer'
    try {
        $sshOptions=@('-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes',
            '-o','ConnectTimeout=5','-o','ConnectionAttempts=1','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=1','-i',$sshKey)
        $stage='active-session'
        if(@(Get-Process -Name 'rwn-viewer' -ErrorAction SilentlyContinue).Count){throw 'A local Viewer is active or connecting.'}
        $sessionCheck='set +e; active=$(/usr/sbin/lsof -nP -a -iTCP:'+$tlsPort+' -sTCP:ESTABLISHED -t 2>/dev/null); result=$?; set -e; if test "$result" -gt 1; then exit 74; fi; if test -n "$active"; then exit 75; fi'
        # The Mac service must be restartable before its OCSP is replaced; otherwise
        # every retry swaps the remote evidence and still leaves both ends expired.
        $job=[string]$config.launchAgentDomain+'/'+[string]$config.launchAgentLabel
        $servicePlist='$HOME/Library/LaunchAgents/'+[string]$config.launchAgentLabel+'.plist'
        $serviceCheck='plist='+$servicePlist+'; test -f "$plist" || exit 76; agent=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$plist" 2>/dev/null) || exit 76; test -x "$agent" || exit 76'
        $check=Invoke-LanPilotBoundedProcess $ssh ($sshOptions+@([string]$config.sshTarget,($sessionCheck+'; '+$serviceCheck))) 15
        if($check.ExitCode -eq 75){throw 'An active session is using the listener.'}
        if($check.ExitCode -eq 76){$stage='remote-service-missing';throw 'The Mac LanPilot service or its runtime is missing.'}
        if($check.ExitCode){$stage='ssh-connect';throw 'SSH peer is unavailable.'}
        $stage='issuer'
        & $updateScript -OpenSslPath $openSsl -AuthorityDirectory $authority -OutputDirectory $bundle
        $stage='manifest'
        $manifestPath=Join-Path $bundle 'bundle.json'
        if(-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)){throw 'Verified bundle manifest is missing.'}
        $manifest=Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
        if($manifest.schema -ne 1){throw 'Verified bundle manifest schema mismatch.'}
        foreach($name in @('root.der','revocation.der','client-ocsp.der')){
            $file=Join-Path $bundle $name
            $expected=[string]$manifest.files.PSObject.Properties[$name].Value
            if($expected -notmatch '^[0-9a-f]{64}$' -or
               (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant() -cne $expected){
                throw "Verified bundle hash mismatch: $name"
            }
        }
        if((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $bundle 'root.der')).Hash -cne
           (Get-FileHash -Algorithm SHA256 -LiteralPath $localRoot).Hash){
            throw 'Trust refresh attempted to replace the pairing authority.'
        }

        $ocsp=Join-Path $bundle 'client-ocsp.der'
        $ocspHash=(Get-FileHash -Algorithm SHA256 -LiteralPath $ocsp).Hash.ToLowerInvariant()
        $remoteTemp=[string]$config.remoteOcspPath+'.new-'+[Guid]::NewGuid().ToString('N')
        $stage='ocsp-transfer'
        $transfer=Invoke-LanPilotBoundedProcess $scp ($sshOptions+@($ocsp,(([string]$config.sshTarget)+':'+$remoteTemp))) 20
        if($transfer.ExitCode){throw "OCSP transfer failed with $($transfer.ExitCode)."}
        # A booted-out job keeps its plist on disk; load it again instead of failing kickstart.
        $remoteBackup=([string]$config.remoteMaintenanceDirectory).TrimEnd('/')+'/client-ocsp-pre-refresh-'+$stamp+'.der'
        $remoteCommand='set -eu; '+$sessionCheck+'; '+$serviceCheck+'; actual=$(shasum -a 256 '+$remoteTemp+'); actual=${actual%% *}; test "$actual" = '+$ocspHash+
            '; mkdir -p '+[string]$config.remoteMaintenanceDirectory+
            '; chmod 700 '+[string]$config.remoteMaintenanceDirectory+
            '; if test -f '+[string]$config.remoteOcspPath+'; then cp -p '+[string]$config.remoteOcspPath+' '+$remoteBackup+'; fi'+
            '; chmod 600 '+$remoteTemp+'; mv '+$remoteTemp+' '+[string]$config.remoteOcspPath+
            '; launchctl print '+$job+' >/dev/null 2>&1 || launchctl bootstrap '+[string]$config.launchAgentDomain+' "$plist"'+
            '; launchctl kickstart -k '+$job+
            '; sleep 1; lsof -nP -iTCP:'+$tlsPort+' -sTCP:LISTEN >/dev/null'
        $stage='active-session'
        if(@(Get-Process -Name 'rwn-viewer' -ErrorAction SilentlyContinue).Count){throw 'A local Viewer started during staging.'}
        $stage='ocsp-activate'
        $activation=Invoke-LanPilotBoundedProcess $ssh ($sshOptions+@([string]$config.sshTarget,$remoteCommand)) 20
        if($activation.ExitCode -eq 75){$stage='active-session';throw 'An active session appeared during staging.'}
        if($activation.ExitCode -eq 76){$stage='remote-service-missing';throw 'The Mac LanPilot service or its runtime is missing.'}
        if($activation.ExitCode){throw "Remote OCSP activation failed with $($activation.ExitCode)."}

        $stage='local-crl'
        $crl=Join-Path $bundle 'revocation.der'
        $localTemporary=$localCrl+'.new-'+[Guid]::NewGuid().ToString('N')
        Copy-Item -LiteralPath $crl -Destination $localTemporary
        if((Get-FileHash -Algorithm SHA256 -LiteralPath $crl).Hash -cne
           (Get-FileHash -Algorithm SHA256 -LiteralPath $localTemporary).Hash){throw 'Local CRL staging hash mismatch.'}
        $localBackup=Join-Path $maintenance ('revocation-pre-refresh-'+$stamp+'.der')
        [IO.File]::Replace($localTemporary,$localCrl,$localBackup,$true)

        $config.nextRefreshUtc=[string]$manifest.refreshBeforeUtc
        $config.expiresUtc=[string]$manifest.expiresUtc
        $stage='profile-commit'
        $configTemporary=$ConfigPath+'.new-'+[Guid]::NewGuid().ToString('N')
        [IO.File]::WriteAllText($configTemporary,($config | ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
        [IO.File]::Replace($configTemporary,$ConfigPath,(Join-Path $maintenance ('trust-renewal-pre-refresh-'+$stamp+'.json')),$true)
        Write-RenewalLog 'refreshed'
        Write-Output "trust_renewal=refreshed expires_utc=$($config.expiresUtc) private_key_transferred=0"
    } catch {
        Write-RenewalLog ('failed stage='+$stage)
        Write-Output ('trust_renewal=failed stage='+$stage)
        Write-Verbose ('Trust renewal failed at stage '+$stage+': '+$_.Exception.Message)
        if($NowUtc -lt $expiresUtc){
            Write-Warning 'Trust renewal was deferred; current signed evidence remains valid.'
            Write-Output "trust_renewal=deferred expires_utc=$($expiresUtc.ToString('o'))"
            return
        }
        throw 'Trust renewal failed and the current signed evidence is expired. Visual TLS remains fail-closed.'
    }
} finally {
    $lock.Dispose()
}
