param([Parameter(Mandatory)][string]$PackagingDirectory,
      [Parameter(Mandatory)][string]$Destination,
      [Parameter(Mandatory)][string]$Viewer,
      [Parameter(Mandatory)][string]$Launcher,
      [Parameter(Mandatory)][string]$Maintenance,
      [Parameter(Mandatory)][string]$License,
      [Parameter(Mandatory)][ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+$')][string]$ProductVersion,
      [switch]$ExistingPair,
      [string]$ExpectedViewerSha256='')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PackagingDirectory 'ProductInstall.psm1') -Force
$null=New-Item -ItemType Directory -Path $Destination -Force
$files=[ordered]@{}
foreach($name in @((Get-LanPilotProgramFiles)+@('LanPilot.exe','Start-LanPilotBootstrap.ps1','Install-DesktopPreview.ps1'))){
    $files[$name]=Join-Path $PackagingDirectory $name
}
$files['rwn-viewer.exe']=$Viewer
$files['LanPilot.exe']=$Launcher
$files['rwn-maintenance-launcher.exe']=$Maintenance
$files['LICENSE.txt']=$License
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive=[IO.File]::Open((Join-Path $Destination 'payload.zip'),[IO.FileMode]::Create)
$hashes=[Collections.Generic.List[string]]::new()
$viewerLock=$null
try {
    if($ExistingPair){
        if($ExpectedViewerSha256 -cnotmatch '^[0-9a-f]{64}$'){throw 'Personal setup requires the expected Viewer SHA-256.'}
        $viewerLock=[IO.File]::Open($Viewer,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        if((Get-LanPilotInstallFileHash $Viewer) -cne $ExpectedViewerSha256){throw 'Personal Viewer changed after configuration. Package was not accepted.'}
    }
    $zip=[IO.Compression.ZipArchive]::new($archive,[IO.Compression.ZipArchiveMode]::Create,$true)
    try {
        foreach($entry in $files.GetEnumerator()){
            $null=[IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,$entry.Value,$entry.Key)
            $hash=Get-LanPilotInstallFileHash $entry.Value
            $hashes.Add("    '$($entry.Key)'='$hash'")
        }
    }finally{$zip.Dispose()}
}finally{if($viewerLock){$viewerLock.Dispose()};$archive.Dispose()}
$driver="`$expected=@{`r`n"+($hashes -join "`r`n")+"`r`n}`r`n`$productVersion='$ProductVersion'`r`n"+
    "`$personalExistingPair=`$"+([string][bool]$ExistingPair).ToLowerInvariant()+"`r`n"+
    [IO.File]::ReadAllText((Join-Path $PackagingDirectory 'Setup-Driver.ps1'))
[IO.File]::WriteAllText((Join-Path $Destination 'driver.ps1'),$driver,[Text.UTF8Encoding]::new($true))
$zipPath=(Join-Path $Destination 'payload.zip').Replace('\','/')
$driverPath=(Join-Path $Destination 'driver.ps1').Replace('\','/')
$manifestPath=(Join-Path $PackagingDirectory 'Setup.manifest').Replace('\','/')
[IO.File]::WriteAllText((Join-Path $Destination 'payload.rc'),
    "101 RCDATA `"$zipPath`"`r`n102 RCDATA `"$driverPath`"`r`n1 24 `"$manifestPath`"`r`n",[Text.UTF8Encoding]::new($false))
