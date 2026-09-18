Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$generator=Join-Path $PSScriptRoot '../packaging/macos/New-LanPilotLaunchAgent.ps1'
$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('lanpilot-launch-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $testRoot
$output=Join-Path $testRoot 'agent.plist'
$config=@{OutputPath=$output;MacHome='/Users/tester';AgentPath='/Users/tester/Lan Pilot & test/agent';BindAddress='192.168.1.12';IdentityReference='0102ab';ClientFingerprint=('a'*64);RootDerPath='/Users/tester/Trust & Cert/root.der';ClientOcspPath='/Users/tester/Trust & Cert/client-ocsp.der'}
function Reject([hashtable]$Values){
    $rejected=$false
    try {& $generator @Values | Out-Null} catch {$rejected=$true}
    if(-not $rejected){throw 'Invalid service configuration accepted'}
}
try {
    & $generator @config
    [xml]$document=[IO.File]::ReadAllText($output)
    $args=@($document.SelectNodes('/plist/dict/array/string') | ForEach-Object {$_.InnerText})
    if($args.Count -ne 10 -or $args[0] -cne $config.AgentPath -or $args[6] -cne $config.RootDerPath -or $args[7] -ne 'view-only' -or $args[9] -cne $config.ClientOcspPath){
        throw 'Argument isolation or default grant failed'
    }
    if(-not $document.SelectSingleNode('/plist/dict/key[text()="KeepAlive"]/following-sibling::*[1][self::true]') -or
       $document.SelectSingleNode('/plist/dict/key[text()="LimitLoadToSessionType"]/following-sibling::*[1]').InnerText -ne 'Aqua'){
        throw 'User-session lifecycle contract changed'
    }
    $original=Get-FileHash -LiteralPath $output -Algorithm SHA256
    Reject $config
    if((Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash -ne $original.Hash){throw 'Existing output overwritten'}
    Remove-Item -LiteralPath $output
    foreach($case in @(@('BindAddress','0.0.0.0'),@('BindAddress','8.8.8.8'),@('BindAddress','127.1'),
        @('BindAddress','mac.local'),@('Port',80),@('IdentityReference','abc'),@('ClientFingerprint','abc'),
        @('MacHome','/Users/..'),@('AgentPath','/bin/sh'),@('AgentPath','/Users/tester/../other/agent'),
        @('RootDerPath','/Users/other/root.der'),@('ClientOcspPath','/Users/other/response.der'),
        @('ClientOcspPath',$config.RootDerPath),@('OutputPath','relative.plist'),@('Control','admin'))){
        $bad=$config.Clone(); $bad[$case[0]]=$case[1]; Reject $bad
        if(Test-Path -LiteralPath $output){throw 'Rejected configuration created a file'}
    }
    $config.Control='interactive'; $config.Visual='exact-only'
    & $generator @config
    [xml]$document=[IO.File]::ReadAllText($output)
    $args=@($document.SelectNodes('/plist/dict/array/string') | ForEach-Object {$_.InnerText})
    if($args[7] -ne 'interactive' -or $args[8] -ne 'exact-only'){throw 'Explicit modes not preserved'}
    Write-Output 'PASS Mac launch configuration: literal argv, safe defaults, create-new, path/address/deadline-independent grant validation; install=0 network=0'
} finally {
    if(Test-Path -LiteralPath $output){Remove-Item -LiteralPath $output}
    if(@(Get-ChildItem -LiteralPath $testRoot -Force).Count -eq 0){Remove-Item -LiteralPath $testRoot}
}
