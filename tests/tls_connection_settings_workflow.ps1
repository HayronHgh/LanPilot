param([string]$PackagingDirectory=(Join-Path $PSScriptRoot '..\packaging\windows'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$packaging=[IO.Path]::GetFullPath($PackagingDirectory)
Import-Module (Join-Path $packaging 'TlsConnectionSettings.psm1') -Force
foreach($name in @('Start-LanPilot.ps1','Start-LanPilotTls.ps1','TlsConnectionSettings.psm1')){
    $tokens=$null; $errors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile((Join-Path $packaging $name),[ref]$tokens,[ref]$errors)
    if($errors.Count){throw "Parse failed: $name"}
}
$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('lanpilot-tls-settings-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $testRoot
$rootDer=Join-Path $testRoot 'root with spaces.der'
$crlDer=Join-Path $testRoot 'crl.der'
$profile=Join-Path $testRoot 'profile.json'
function Reject([scriptblock]$Action){$rejected=$false;try{& $Action | Out-Null}catch{$rejected=$true};if(-not $rejected){throw 'Invalid settings accepted'}}
try{
    # Opaque bytes, NOT certificates. Config validation must never imply trust.
    [IO.File]::WriteAllBytes($rootDer,[byte[]]@(1,2,3))
    [IO.File]::WriteAllBytes($crlDer,[byte[]]@(4,5,6))
    $settings=[pscustomobject]@{schema=1;transport='tls';host='mac.example.test';port=45443;clientCertificate=('1'*40);serverFingerprint=('2'*64);rootDer=$rootDer;crlDer=$crlDer;control='view-only';visual='h264-only'}
    $arguments=@(Get-LanPilotTlsArguments $settings)
    if($arguments.Count -ne 9 -or $arguments[5] -ne $rootDer -or $arguments[7] -ne 'view-only'){throw 'Argument boundary/default changed'}
    foreach($control in @('view-only','interactive','view-only')){
        $settings.control=$control
        Save-LanPilotTlsSettings $profile $settings
        $actual=Read-LanPilotTlsSettings $profile
        if($actual.control -ne $control -or $actual.rootDer -ne $rootDer){throw 'Roundtrip failed'}
    }
    & (Join-Path $packaging 'Start-LanPilotTls.ps1') -ConfigPath $profile -ValidateOnly
    # Match desktop shortcut execution: a fresh Windows PowerShell -File host,
    # not an in-process script invocation. Resolve default ViewerPath there too.
    $windowsHost=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    & $windowsHost -NoProfile -ExecutionPolicy Bypass -File (Join-Path $packaging 'Start-LanPilotTls.ps1') -ConfigPath $profile -ValidateOnly
    if($LASTEXITCODE -ne 0){throw 'Fresh Windows PowerShell launcher failed'}
    # Read-only store lookup must fail before launching a Viewer for this absent identity.
    Reject {& (Join-Path $packaging 'Start-LanPilotTls.ps1') -ConfigPath $profile -CheckReadiness}
    Reject {& (Join-Path $packaging 'Start-LanPilotTls.ps1') -ConfigPath $profile -CheckReadiness -ValidateOnly}
    # Read-only store lookup must fail before launching a Viewer for this absent identity.
    Reject {& (Join-Path $packaging 'Start-LanPilotTls.ps1') -ConfigPath $profile -CheckReadiness}
    Reject {& (Join-Path $packaging 'Start-LanPilotTls.ps1') -ConfigPath $profile -CheckReadiness -ValidateOnly}
    foreach($case in @(
        @('port',0),@('port',65536),@('port','45443'),@('schema','1'),
        @('host','user@mac'),@('host','host;command'),@('control','admin'),
        @('visual','unknown'),@('serverFingerprint','short'),@('rootDer','relative.der'),
        @('rootDer','\\server\share\root.der'),@('rootDer',($rootDer+':stream')))){
        $copy=$settings | ConvertTo-Json | ConvertFrom-Json
        $copy.($case[0])=$case[1]
        Reject {Get-LanPilotTlsArguments $copy}
    }
    $copy=$settings | ConvertTo-Json | ConvertFrom-Json
    $copy | Add-Member NoteProperty privateKey 'not-allowed'
    Reject {Get-LanPilotTlsArguments $copy}
    [IO.File]::WriteAllBytes($crlDer,[byte[]]::new(65537))
    Reject {Get-LanPilotTlsArguments $settings}
    if(@(Get-ChildItem -LiteralPath $testRoot -Filter '*.tmp').Count){throw 'Temporary profile leaked'}
    Write-Output 'PASS TLS settings: argument boundaries, atomic persistence, view-only default, invalid types/modes/paths/size/unknown-field rejection; network=0 UI=0'
}finally{
    foreach($file in @($rootDer,$crlDer,$profile)){if(Test-Path -LiteralPath $file){Remove-Item -LiteralPath $file}}
    if(@(Get-ChildItem -LiteralPath $testRoot -Force).Count -eq 0){Remove-Item -LiteralPath $testRoot}
}
