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
    Write-Output 'lanpilot_product_layout_workflow=PASS canonical_profile=1 recovery=1 archive=1 idempotent=1 desktop_artifacts=0'
} finally {
    if(Test-Path -LiteralPath $testRoot){Remove-Item -LiteralPath $testRoot -Recurse -Force}
}
