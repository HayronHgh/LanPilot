[CmdletBinding()]
param([ValidateSet('tls','ssh','configure')][string]$Connection='configure',
      [switch]$CheckLayout,
      [string]$DataRoot='',
      [switch]$MigrateOnly)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Assert-LocalDataRoot([string]$Path) {
    if($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path.Substring(2).Contains(':')){
        throw 'LanPilot data root must be an absolute local path.'
    }
    $cursor=[IO.Path]::GetFullPath($Path)
    while($cursor){
        if(Test-Path -LiteralPath $cursor){
            if((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){
                throw 'Linked LanPilot data root rejected.'
            }
        }
        $cursor=[IO.Path]::GetDirectoryName($cursor)
    }
}

function Initialize-LanPilotProductLayout([string]$Root) {
    Assert-LocalDataRoot $Root
    $connections=Join-Path $Root 'connections'
    $maintenance=Join-Path $Root 'maintenance'
    $profile=Join-Path $connections 'default.json'
    $legacy=Join-Path $Root 'tls-desktop.json'
    if(Test-Path -LiteralPath $profile -PathType Leaf){return [pscustomobject]@{Profile=$profile;Status='existing'}}
    if(-not (Test-Path -LiteralPath $legacy -PathType Leaf)){return [pscustomobject]@{Profile=$profile;Status='absent'}}

    $null=New-Item -ItemType Directory -Path $connections -Force
    $null=New-Item -ItemType Directory -Path $maintenance -Force
    $archive=Join-Path $maintenance ('legacy-profile-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8))
    $null=New-Item -ItemType Directory -Path $archive
    $profileTemporary=$profile+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
    $recoveryTemporary=$profile+'.recovery.'+[Guid]::NewGuid().ToString('N')+'.tmp'
    try {
        Copy-Item -LiteralPath $legacy -Destination (Join-Path $archive 'tls-desktop.json')
        Copy-Item -LiteralPath $legacy -Destination $profileTemporary
        $hasRecovery=Test-Path -LiteralPath ($legacy+'.recovery') -PathType Leaf
        if($hasRecovery){
            Copy-Item -LiteralPath ($legacy+'.recovery') -Destination (Join-Path $archive 'tls-desktop.json.recovery')
            Copy-Item -LiteralPath ($legacy+'.recovery') -Destination $recoveryTemporary
        }
        [IO.File]::Move($profileTemporary,$profile)
        if($hasRecovery){[IO.File]::Move($recoveryTemporary,$profile+'.recovery')}
    } finally {
        foreach($temporary in @($profileTemporary,$recoveryTemporary)){
            if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary -Force}
        }
    }
    return [pscustomobject]@{Profile=$profile;Status='migrated'}
}

if(-not $DataRoot){$DataRoot=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'LanPilot'}
$DataRoot=[IO.Path]::GetFullPath($DataRoot)
try {
    $layout=Initialize-LanPilotProductLayout $DataRoot
    if($MigrateOnly){
        Write-Output "lanpilot_product_layout=PASS status=$($layout.Status) profile=$($layout.Profile) desktop_artifacts=0"
        return
    }
    Add-Type -AssemblyName System.Windows.Forms
    [Windows.Forms.Application]::EnableVisualStyles()
    if($CheckLayout){$Connection='configure'}
    if($Connection -eq 'ssh') {
        & (Join-Path $PSScriptRoot 'Start-DesktopPreview.ps1') -ConfigPath (Join-Path $DataRoot 'desktop.json')
    } else {
        $immediate=$Connection -eq 'tls'
        $tlsProfilePath=$layout.Profile
        if(-not (Test-Path -LiteralPath $tlsProfilePath -PathType Leaf)){$immediate=$false}
        $renewalProfile=Join-Path $DataRoot 'maintenance\trust-renewal.json'
        if(Test-Path -LiteralPath $renewalProfile -PathType Leaf){
            $maintenanceScript=Join-Path $PSScriptRoot 'Invoke-LanPilotTrustMaintenance.ps1'
            if(-not (Test-Path -LiteralPath $maintenanceScript -PathType Leaf)){
                throw 'Trust maintenance component is missing. Reinstall the verified LanPilot package.'
            }
            $null=& $maintenanceScript -DataRoot $DataRoot -RequireReady
        }
        & (Join-Path $PSScriptRoot 'Start-LanPilotTls.ps1') -ConfigPath $tlsProfilePath -ViewerPath (Join-Path $PSScriptRoot 'rwn-viewer.exe') -ConnectImmediately:$immediate -CheckLayout:$CheckLayout
    }
} catch {
    if($MigrateOnly){throw}
    [Windows.Forms.MessageBox]::Show($_.Exception.Message,'LanPilot - Connection failed',
        [Windows.Forms.MessageBoxButtons]::OK,[Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    exit 1
}
