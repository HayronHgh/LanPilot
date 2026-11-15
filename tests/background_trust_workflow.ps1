param([string]$PackagingDirectory=(Join-Path $PSScriptRoot '..\packaging\windows'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$packaging=[IO.Path]::GetFullPath($PackagingDirectory)
Import-Module (Join-Path $packaging 'TrustMaintenance.psm1') -Force
$root=Join-Path ([IO.Path]::GetTempPath()) ('lanpilot-background-'+[Guid]::NewGuid().ToString('N'))
$hostPath=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
function Check([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
function Invoke-Worker([switch]$RequireReady){
    $arguments=@('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $packaging 'Invoke-LanPilotTrustMaintenance.ps1'),'-DataRoot',$root)
    if($RequireReady){$arguments+='-RequireReady'}
    return Invoke-LanPilotBoundedProcess $hostPath $arguments 15
}
try {
    $now=[datetime]'2030-01-01T00:00:00Z'
    Check ((Get-LanPilotRenewalDecision $now $now.AddDays(7)) -eq 'current') 'Unexpected early renewal'
    Check ((Get-LanPilotRenewalDecision $now $now.AddHours(72)) -eq 'due') '72-hour boundary was skipped'
    Check ((Get-LanPilotRenewalDecision $now $now.AddHours(-1) $now.AddHours(1)) -eq 'backoff') 'Background retry budget ignored'
    Check ((Get-LanPilotRenewalDecision $now $now.AddHours(-1) $now.AddHours(1) -RequireReady) -eq 'due') 'Explicit recovery was blocked by background backoff'
    foreach($count in 1..5){
        $delay=Get-LanPilotRetrySeconds $count
        $minimum=@(60,300,1800,7200)[[Math]::Min($count-1,3)]
        Check ($delay -ge $minimum -and $delay -le [Math]::Min(7200,$minimum*1.1)) 'Retry delay outside bounded policy'
    }
    $maintenance=Join-Path $root 'maintenance'
    $null=New-Item -ItemType Directory -Path $maintenance
    $config=[ordered]@{schema=1;enabled=$true;openSslPath=$hostPath;localRootDer=(Join-Path $root 'missing-root.der');localCrlDer=(Join-Path $root 'missing-crl.der')}
    [IO.File]::WriteAllText((Join-Path $maintenance 'trust-renewal.json'),($config|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    $first=Invoke-Worker
    Check ($first.ExitCode -eq 0 -and $first.Output -match 'trust_maintenance=retry') 'Missing input did not become a background retry'
    $statusPath=Join-Path $maintenance 'trust-status.json'
    $status=Get-Content -Raw -LiteralPath $statusPath|ConvertFrom-Json
    Check ($status.failureCount -eq 1 -and $status.reason -eq 'Missing maintenance input: localRootDer') 'Missing input diagnostic is not specific'
    $second=Invoke-Worker
    Check ($second.Output -match 'trust_maintenance=backoff') 'Next process did not honor persisted backoff'
    $reloaded=Get-Content -Raw -LiteralPath $statusPath|ConvertFrom-Json
    Check ($reloaded.nextAttemptUtc -eq $status.nextAttemptUtc -and $reloaded.failureCount -eq 1) 'Backoff changed after restart'
    $foreground=Invoke-Worker -RequireReady
    Check ($foreground.ExitCode -ne 0 -and $foreground.Error -match 'Secure connection maintenance needs attention') 'Unverified evidence did not fail closed'
    $lock=[IO.File]::Open((Join-Path $maintenance 'trust-background.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        $busy=Invoke-Worker
        Check ($busy.ExitCode -eq 0 -and $busy.Output -match 'trust_maintenance=busy') 'Concurrent worker was not excluded'
    } finally {$lock.Dispose()}
    $timeout=Invoke-LanPilotBoundedProcess $hostPath @('-NoProfile','-Command','Start-Sleep -Seconds 5') 1
    Check ($timeout.ExitCode -eq 124) 'Child timeout did not stop the operation'
    Check (@(Get-ChildItem -LiteralPath $root -Recurse -Filter '*.tmp').Count -eq 0) 'Temporary state files leaked'
    Write-Output 'background_trust_workflow=PASS early_window=1 persisted_backoff=1 input_diagnostic=1 fail_closed=1 concurrent_writer_excluded=1 deadline=1 network=0 private_keys=0'
} finally {
    if(Test-Path -LiteralPath $root){Remove-Item -LiteralPath $root -Recurse -Force}
}
