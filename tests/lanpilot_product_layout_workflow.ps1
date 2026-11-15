param([string]$PackagingDirectory=(Join-Path $PSScriptRoot '..\packaging\windows'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

$launcher=Join-Path ([IO.Path]::GetFullPath($PackagingDirectory)) 'Start-LanPilot.ps1'
$hostPath=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('lanpilot-product-layout-'+[Guid]::NewGuid().ToString('N'))
$legacy=Join-Path $testRoot 'tls-desktop.json'
$legacyRecovery=$legacy+'.recovery'
$profile=Join-Path $testRoot 'connections\default.json'
function Get-Sha256([string]$Path) {
    $stream=[IO.File]::OpenRead($Path)
    try {
        $sha=[Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','') }
        finally { $sha.Dispose() }
    } finally { $stream.Dispose() }
}
try {
    $null=New-Item -ItemType Directory -Path $testRoot
    [IO.File]::WriteAllText($legacy,'{"schema":1,"opaque":"profile"}',[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllBytes($legacyRecovery,[byte[]]@(7,6,5,4,3,2,1))
    $legacyHash=Get-Sha256 $legacy
    $recoveryHash=Get-Sha256 $legacyRecovery

    & $hostPath -NoProfile -ExecutionPolicy Bypass -File $launcher -DataRoot $testRoot -MigrateOnly
    if($LASTEXITCODE){throw 'Product layout migration process failed'}
    if(-not (Test-Path -LiteralPath $profile -PathType Leaf) -or
       (Get-Sha256 $profile) -cne $legacyHash){throw 'Canonical profile migration mismatch'}
    if(-not (Test-Path -LiteralPath ($profile+'.recovery') -PathType Leaf) -or
       (Get-Sha256 ($profile+'.recovery')) -cne $recoveryHash){throw 'Recovery migration mismatch'}
    $archives=@(Get-ChildItem -LiteralPath (Join-Path $testRoot 'maintenance') -Directory -Filter 'legacy-profile-*')
    if($archives.Count -ne 1){throw 'Expected exactly one legacy archive'}
    if((Get-Sha256 (Join-Path $archives[0].FullName 'tls-desktop.json')) -cne $legacyHash){throw 'Archived profile mismatch'}

    & $hostPath -NoProfile -ExecutionPolicy Bypass -File $launcher -DataRoot $testRoot -MigrateOnly
    if($LASTEXITCODE){throw 'Idempotent product layout check failed'}
    if(@(Get-ChildItem -LiteralPath (Join-Path $testRoot 'maintenance') -Directory -Filter 'legacy-profile-*').Count -ne 1){throw 'Idempotent launch created another archive'}
    if(@(Get-ChildItem -LiteralPath $testRoot -Recurse -File -Filter '*.tmp').Count){throw 'Migration leaked temporary files'}
    # Exercise the actual unified entry with inert neighboring transports.
    # No real Viewer/SSH process, UI, key store or network is opened.
    $dispatch=Join-Path $testRoot 'dispatch';$null=New-Item -ItemType Directory -Path $dispatch
    $entry=Join-Path $dispatch 'Start-LanPilot.ps1'
    Copy-Item -LiteralPath $launcher -Destination $entry
    $receipt=Join-Path $dispatch 'route.json'
    [IO.File]::WriteAllText((Join-Path $dispatch 'Start-DesktopPreview.ps1'),@'
param([string]$ConfigPath='legacy-default')
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'route.json'),
    (@{transport='ssh';profile=$ConfigPath}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
'@)
    [IO.File]::WriteAllText((Join-Path $dispatch 'Start-LanPilotTls.ps1'),@'
param([string]$ConfigPath,[string]$ViewerPath,[switch]$ConnectImmediately,[switch]$CheckLayout)
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'route.json'),
    (@{transport='tls';profile=$ConfigPath;immediate=[bool]$ConnectImmediately}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
'@)
    $sshProfile=Join-Path $testRoot 'desktop.json'
    [IO.File]::WriteAllText($sshProfile,'{"opaque":"retained-ssh-settings"}')
    $sshHash=Get-Sha256 $sshProfile
    & $hostPath -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $entry -DataRoot $testRoot -Connection ssh
    if($LASTEXITCODE){throw 'SSH dispatch failed'}
    $route=Get-Content -Raw -LiteralPath $receipt|ConvertFrom-Json
    if($route.transport -cne 'ssh' -or $route.profile -cne $sshProfile){throw 'SSH ignored the selected LanPilot data root'}
    foreach($mode in @('configure','tls')){
        & $hostPath -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $entry -DataRoot $testRoot -Connection $mode
        if($LASTEXITCODE){throw 'TLS dispatch failed'}
        $route=Get-Content -Raw -LiteralPath $receipt|ConvertFrom-Json
        if($route.transport -cne 'tls' -or $route.profile -cne $profile -or $route.immediate -ne ($mode -ceq 'tls')){
            throw 'TLS setup/connect dispatch changed'
        }
    }
    if((Get-Sha256 $sshProfile) -cne $sshHash -or (Get-Sha256 $profile) -cne $legacyHash){throw 'Dispatch changed saved settings'}
    Write-Output 'lanpilot_product_layout_workflow=PASS canonical_profile=1 recovery=1 archive=1 idempotent=1 dispatch=1 settings_preserved=1 desktop_artifacts=0'
} finally {
    if(Test-Path -LiteralPath $testRoot){Remove-Item -LiteralPath $testRoot -Recurse -Force}
}
