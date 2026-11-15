param([Parameter(Mandatory)][string]$Setup,[Parameter(Mandatory)][string]$PackagingDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PackagingDirectory 'TrustMaintenance.psm1') -Force
function Check([bool]$Value,[string]$Reason){if(-not $Value){throw $Reason}}
$hostExe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
foreach($flag in @('--check-ui','--check-package')){
    $result=Invoke-LanPilotBoundedProcess $Setup @($flag) 100
    Check ($result.ExitCode -eq 0) ('Setup probe failed: '+$flag+' '+$result.Error)
}
$result=Invoke-LanPilotBoundedProcess $Setup @('--script','untrusted.ps1') 10
Check ($result.ExitCode -ne 0) 'Setup accepts arbitrary script paths'
$bytes=[IO.File]::ReadAllBytes($Setup);$pe=[BitConverter]::ToInt32($bytes,0x3c)
Check ([BitConverter]::ToUInt16($bytes,$pe+24+68) -eq 2) 'Setup must use GUI subsystem'
Add-Type -AssemblyName System.IO.Compression
$root=Join-Path ([IO.Path]::GetTempPath()) ('lanpilot-setup-test-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $root
$body=[IO.File]::ReadAllText((Join-Path $PackagingDirectory 'Setup-Driver.ps1'))
$content=[Text.Encoding]::UTF8.GetBytes('exact fixture bytes')
$sha=[Security.Cryptography.SHA256]::Create()
try{$hash=([BitConverter]::ToString($sha.ComputeHash($content))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
try {
    $layoutPath=Join-Path $root 'layout.bmp'
    $result=Invoke-LanPilotBoundedProcess $Setup @('--check-layout',$layoutPath) 15
    Check ($result.ExitCode -eq 0) 'Hidden setup layout could not render'
    $layoutBytes=[IO.File]::ReadAllBytes($layoutPath)
    Check ($layoutBytes.Length -gt 54 -and $layoutBytes[0] -eq 66 -and $layoutBytes[1] -eq 77) 'Invalid layout bitmap'
    Check ([BitConverter]::ToInt32($layoutBytes,18) -ge 600 -and [BitConverter]::ToInt32($layoutBytes,22) -le -530) 'Setup layout is clipped'
    $layoutBefore=[Convert]::ToBase64String($layoutBytes)
    $result=Invoke-LanPilotBoundedProcess $Setup @('--check-layout',$layoutPath) 15
    Check ($result.ExitCode -ne 0 -and [Convert]::ToBase64String([IO.File]::ReadAllBytes($layoutPath)) -ceq $layoutBefore) 'Layout overwrote an existing file'
    $result=Invoke-LanPilotBoundedProcess $Setup @('--check-layout','relative-layout.bmp') 15
    Check ($result.ExitCode -ne 0) 'Layout accepted a relative output path'
    # Extract only the local preflight function; never run the production driver
    # or access the user's profile/key store in this isolated fixture.
    $tokens=$null;$parseErrors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$parseErrors)
    $fn=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-LanPilotPersonalPair'},$true)
    Check ($null -ne $fn -and $parseErrors.Count -eq 0) 'Missing personal preflight'
    . ([scriptblock]::Create($fn.Extent.Text))
    function Read-LanPilotTlsSettings([string]$Path){return @{fixture=$true}}
    function Test-LanPilotTlsReadiness($Settings){return @{LocalIdentityReady=$script:fixtureIdentityReady}}
    $fixtureProfile=Join-Path $root 'profile.json'
    $script:fixtureIdentityReady=$true
    $rejected=$false;try{Assert-LanPilotPersonalPair $fixtureProfile}catch{$rejected=$true}
    Check $rejected 'Missing pairing was accepted'
    [IO.File]::WriteAllText($fixtureProfile,'fixture')
    $script:fixtureIdentityReady=$false
    $rejected=$false;try{Assert-LanPilotPersonalPair $fixtureProfile}catch{$rejected=$true}
    Check $rejected 'Unready existing identity was accepted'
    $script:fixtureIdentityReady=$true;Assert-LanPilotPersonalPair $fixtureProfile
    foreach($scenario in @('valid','tamper','missing','duplicate','traversal','unexpected','truncated')){
        $dir=Join-Path $root $scenario;$null=New-Item -ItemType Directory -Path $dir
        [IO.File]::WriteAllText((Join-Path $dir 'driver.ps1'),("`$expected=@{'fixture.txt'='$hash'}`r`n`$productVersion='0.1.0'`r`n"+$body),[Text.UTF8Encoding]::new($true))
        $file=[IO.File]::Create((Join-Path $dir 'payload.zip'))
        $zip=[IO.Compression.ZipArchive]::new($file,[IO.Compression.ZipArchiveMode]::Create,$true)
        try {
            if($scenario -ne 'missing'){
                $names=@('fixture.txt')
                if($scenario -eq 'duplicate'){$names+=@('fixture.txt')}
                if($scenario -eq 'traversal'){$names=@('../escape.txt')}
                if($scenario -eq 'unexpected'){$names+=@('unknown.txt')}
                foreach($name in $names){
                    $entry=$zip.CreateEntry($name);$stream=$entry.Open()
                    try{
                        $data=if($scenario -eq 'tamper'){[byte[]]@(0,1,2)}else{$content}
                        $stream.Write($data,0,$data.Length)
                    }finally{$stream.Dispose()}
                }
            }
        }finally{$zip.Dispose();$file.Dispose()}
        if($scenario -eq 'truncated'){[IO.File]::WriteAllBytes((Join-Path $dir 'payload.zip'),[byte[]]@(0,1,2))}
        $result=Invoke-LanPilotBoundedProcess $hostExe @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $dir 'driver.ps1'),'verify') 20
        Check (($result.ExitCode -eq 0) -eq ($scenario -eq 'valid')) ('Wrong package validation: '+$scenario)
        Check (-not (Test-Path -LiteralPath (Join-Path $dir 'escape.txt'))) 'Archive path escaped payload'
    }
    # Exercise the real fixed driver's invocation with an inert installer fixture.
    # This does not run the production installer or touch Apps/tasks/desktop/state.
    $dir=Join-Path $root 'install-dispatch';$null=New-Item -ItemType Directory -Path $dir
    $fixture=[Text.Encoding]::UTF8.GetBytes('param([string]$ProductVersion) [IO.File]::WriteAllText((Join-Path $PSScriptRoot "called.txt"),$ProductVersion)')
    $sha=[Security.Cryptography.SHA256]::Create()
    try{$hash=([BitConverter]::ToString($sha.ComputeHash($fixture))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
    [IO.File]::WriteAllText((Join-Path $dir 'driver.ps1'),("`$expected=@{'Install-DesktopPreview.ps1'='$hash'}`r`n`$productVersion='0.1.0'`r`n"+$body),[Text.UTF8Encoding]::new($true))
    $file=[IO.File]::Create((Join-Path $dir 'payload.zip'))
    $zip=[IO.Compression.ZipArchive]::new($file,[IO.Compression.ZipArchiveMode]::Create,$true)
    try{$stream=$zip.CreateEntry('Install-DesktopPreview.ps1').Open();try{$stream.Write($fixture,0,$fixture.Length)}finally{$stream.Dispose()}}
    finally{$zip.Dispose();$file.Dispose()}
    $result=Invoke-LanPilotBoundedProcess $hostExe @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $dir 'driver.ps1'),'install') 20
    Check ($result.ExitCode -eq 0) ('Fixed installer dispatch failed: '+$result.Error)
    Check ([IO.File]::ReadAllText((Join-Path $dir 'payload\called.txt')) -ceq '0.1.0') 'Package version not passed to installer'
    # Run the actual installer script across its transaction callback boundary.
    # The inert module performs no activation, file install, key access or UI.
    # Under StrictMode the receipt must not depend on callback-local variables.
    $receiptDir=Join-Path $root 'install-receipt';$null=New-Item -ItemType Directory -Path $receiptDir
    Copy-Item -LiteralPath (Join-Path $PackagingDirectory 'Install-DesktopPreview.ps1') -Destination $receiptDir
    [IO.File]::WriteAllText((Join-Path $receiptDir 'ProductInstall.psm1'),@'
function Invoke-LanPilotProgramUpdate {
    param($SourceDirectory,$InstallRoot,$DataRoot,[scriptblock]$Activate)
    return @{Status='fixture'}
}
Export-ModuleMember Invoke-LanPilotProgramUpdate
'@)
    $result=Invoke-LanPilotBoundedProcess $hostExe @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',
        (Join-Path $receiptDir 'Install-DesktopPreview.ps1'),'-ConfigRoot',(Join-Path $receiptDir 'state')) 20
    Check ($result.ExitCode -eq 0) ('Installer receipt scope failed: '+$result.Error)
    Check ($result.Output.Contains('Shortcut: ') -and $result.Output.Contains('LanPilot.lnk')) 'Missing shortcut receipt'
    Check (-not (Test-Path -LiteralPath (Join-Path $receiptDir 'state'))) 'Receipt fixture performed activation'
    # Real WinForms failure callback, inert child exit, no UI/network/key store.
    $rootDer=Join-Path $root 'root.der';$crlDer=Join-Path $root 'crl.der'
    [IO.File]::WriteAllBytes($rootDer,[byte[]]@(1,2,3));[IO.File]::WriteAllBytes($crlDer,[byte[]]@(4,5,6))
    $profile=Join-Path $root 'connection.json'
    $settings=@{schema=1;transport='tls';host='127.0.0.1';port=45443;clientCertificate=('1'*40);serverFingerprint=('2'*64);rootDer=$rootDer;crlDer=$crlDer;control='view-only';visual='exact-only'}
    [IO.File]::WriteAllText($profile,($settings|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    $result=Invoke-LanPilotBoundedProcess $hostExe @('-NoProfile','-STA','-NonInteractive','-ExecutionPolicy','Bypass','-File',
        (Join-Path $PackagingDirectory 'Start-LanPilotTls.ps1'),'-ConfigPath',$profile,'-CheckLayout','-CheckViewerFailure') 15
    Check ($result.ExitCode -eq 0 -and $result.Output.Contains('retry_enabled=1 endpoint_shown=1')) ('Viewer failure recovery failed: '+$result.Error)
    Write-Output 'setup_workflow=PASS hidden_ui=1 embedded_package=1 negative_archives=6 fixed_dispatch=1 receipt_scope=1 real_install_not_invoked=1'
}finally{
    $resolved=[IO.Path]::GetFullPath($root)
    $parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    if([IO.Path]::GetDirectoryName($resolved) -ceq $parent -and [IO.Path]::GetFileName($resolved) -match '^lanpilot-setup-test-[0-9a-f]{32}$'){
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
