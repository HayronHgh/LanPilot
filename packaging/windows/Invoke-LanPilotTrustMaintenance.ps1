#requires -Version 5.1
[CmdletBinding()]
param([string]$DataRoot='',[switch]$RequireReady,[switch]$CheckOnly)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'TrustMaintenance.psm1') -Force
if(-not $DataRoot){$DataRoot=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'LanPilot'}
$DataRoot=Assert-LanPilotMaintenancePath $DataRoot
$maintenance=Join-Path $DataRoot 'maintenance'
$configPath=Join-Path $maintenance 'trust-renewal.json'
if(-not (Test-Path -LiteralPath $configPath -PathType Leaf)){Write-Output 'trust_maintenance=not_configured';return}
$null=New-Item -ItemType Directory -Path $maintenance -Force
$null=Assert-LanPilotMaintenancePath $configPath
$statePath=Join-Path $maintenance 'trust-status.json'
$null=Assert-LanPilotMaintenancePath $statePath
$lockPath=Join-Path $maintenance 'trust-background.lock'
$null=Assert-LanPilotMaintenancePath $lockPath
try {$lock=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
catch [IO.IOException] {
    if($RequireReady){
        $current=Get-Content -Raw -LiteralPath $configPath|ConvertFrom-Json
        $verified=Get-LanPilotVerifiedExpiry $current
        if([datetime]::UtcNow -ge $verified.ExpiresUtc){throw 'Secure connection maintenance is running. Retry in a moment.'}
    }
    Write-Output 'trust_maintenance=busy';return
}
$now=[datetime]::UtcNow
$state=[ordered]@{schema=1;status='checking';checkedUtc=$now.ToString('o');verifiedExpiresUtc='';failureCount=0;nextAttemptUtc='';reason=''}
$expires=$null
try {
    try {
        if((Get-Item -LiteralPath $configPath).Length -gt 32768){throw 'Maintenance profile exceeds 32 KiB.'}
        $config=Get-Content -Raw -LiteralPath $configPath|ConvertFrom-Json
        if($config.schema -ne 1 -or $config.enabled -isnot [bool]){throw 'Invalid maintenance profile.'}
        if(-not $config.enabled){Write-Output 'trust_maintenance=disabled';return}
        if(Test-Path -LiteralPath $statePath){
            if((Get-Item -LiteralPath $statePath).Length -gt 32768){throw 'Maintenance status exceeds 32 KiB.'}
            $old=Get-Content -Raw -LiteralPath $statePath|ConvertFrom-Json
            if($old.schema -ne 1 -or [int]$old.failureCount -lt 0 -or [int]$old.failureCount -gt 10000){throw 'Invalid maintenance status.'}
            $state.failureCount=[int]$old.failureCount
            $state.nextAttemptUtc=[string]$old.nextAttemptUtc
        }
        if(-not $RequireReady -and -not $CheckOnly -and $state.nextAttemptUtc){
            $retryAt=[datetime]::Parse($state.nextAttemptUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
            if($now -lt $retryAt){Write-Output 'trust_maintenance=backoff';return}
        }
        # Verify the signed CRL; the profile expiry is scheduling metadata only.
        $evidence=Get-LanPilotVerifiedExpiry $config
        $expires=$evidence.ExpiresUtc
        $state.verifiedExpiresUtc=$expires.ToString('o')
        if($now -lt $evidence.IssuedUtc.AddMinutes(-5)){throw 'System clock precedes signed revocation evidence.'}
        $nextAttempt=[datetime]::MinValue
        if($state.nextAttemptUtc){$nextAttempt=[datetime]::Parse($state.nextAttemptUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()}
        $decision=Get-LanPilotRenewalDecision $now $expires $nextAttempt -RequireReady:$RequireReady
        if($CheckOnly){Write-Output "trust_maintenance=$decision verified_expiry=$($expires.ToString('o'))";return}
        if($decision -ne 'due'){
            $state.status=$decision
            if($decision -eq 'current'){$state.failureCount=0;$state.nextAttemptUtc=''}
            Save-LanPilotMaintenanceState $statePath $state
            Write-Output "trust_maintenance=$decision"
            return
        }
        $state.status='refreshing';Save-LanPilotMaintenanceState $statePath $state
        $hostPath=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $result=Invoke-LanPilotBoundedProcess $hostPath @('-NoProfile','-ExecutionPolicy','Bypass','-File',
            (Join-Path $PSScriptRoot 'Maintain-LanPilotTrust.ps1'),'-DataRoot',$DataRoot,'-ConfigPath',$configPath,'-ForceRefresh') 90
        if($result.ExitCode -eq 124){throw 'Renewal deadline exceeded.'}
        if($result.ExitCode -ne 0 -or $result.Output -notmatch 'trust_renewal=refreshed'){
            if($result.Output -match 'stage=active-session'){throw 'Active session: renewal deferred until the stream closes.'}
            if($result.Output -match 'stage=remote-service-missing'){throw 'Mac service missing: reinstall LanPilot on the Mac, then connect again.'}
            $specific=[regex]::Match($result.Error,'Missing maintenance input: [A-Za-z]+')
            if($specific.Success){throw $specific.Value}
            throw 'Renewal failed; check local inputs and SSH connectivity.'
        }
        $verified=Get-LanPilotVerifiedExpiry $config
        if($verified.ExpiresUtc -le $expires){throw 'Renewal did not advance signed CRL validity.'}
        $state.status='refreshed';$state.verifiedExpiresUtc=$verified.ExpiresUtc.ToString('o')
        $state.failureCount=0;$state.nextAttemptUtc='';$state.reason=''
        Save-LanPilotMaintenanceState $statePath $state
        Write-Output "trust_maintenance=refreshed verified_expiry=$($state.verifiedExpiresUtc)"
    } catch {
        $state.status='retry';$state.failureCount=[Math]::Min(10000,$state.failureCount+1)
        $state.nextAttemptUtc=[datetime]::UtcNow.AddSeconds((Get-LanPilotRetrySeconds $state.failureCount)).ToString('o')
        $message=$_.Exception.Message
        $state.reason=if($message -match '^(Missing maintenance input: [A-Za-z]+|CRL signature verification failed\.|Signed CRL validity.*|System clock precedes.*|Renewal .*|Active session:.*|Mac service missing:.*|Maintenance storage .*)$'){
            $message
        }else{'Maintenance configuration or verification failed.'}
        # Errors generated here contain no command line, key content or input text.
        Save-LanPilotMaintenanceState $statePath $state
        if($RequireReady -and ($null -eq $expires -or [datetime]::UtcNow -ge $expires)){
            throw ('Secure connection maintenance needs attention: '+$state.reason)
        }
        Write-Output "trust_maintenance=retry next_attempt=$($state.nextAttemptUtc)"
    }
} finally {$lock.Dispose()}
