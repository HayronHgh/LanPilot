#requires -Version 5.1
[CmdletBinding()]
param([string]$DataRoot='',[switch]$Remove,[switch]$CheckOnly)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'TrustMaintenance.psm1') -Force
if(-not $DataRoot){$DataRoot=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'LanPilot'}
$DataRoot=Assert-LanPilotMaintenancePath $DataRoot
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$taskName='LanPilot-TrustMaintenance-'+$sid
if($Remove){
    $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if($task){Unregister-ScheduledTask -TaskName $taskName -Confirm:$false}
    Write-Output 'trust_task=removed';return
}
$worker=Assert-LanPilotMaintenancePath (Join-Path $PSScriptRoot 'Invoke-LanPilotTrustMaintenance.ps1')
if(-not (Test-Path -LiteralPath $worker -PathType Leaf)){throw 'Maintenance worker is missing.'}
$hostPath=Assert-LanPilotMaintenancePath (Join-Path $PSScriptRoot 'rwn-maintenance-launcher.exe')
if(-not (Test-Path -LiteralPath $hostPath -PathType Leaf)){throw 'Windowless maintenance launcher is missing.'}
$arguments='--data-root "'+$DataRoot.TrimEnd([char[]]@('\','/'))+'"'
$productRoot=Split-Path -Parent $PSScriptRoot
$workingDirectory=$PSScriptRoot
if([IO.Path]::GetFileName($PSScriptRoot) -eq 'runtime' -and [IO.Path]::GetFileName($productRoot) -eq 'LanPilot'){
    $hostPath=Assert-LanPilotMaintenancePath (Join-Path $productRoot 'LanPilot.exe')
    if(-not (Test-Path -LiteralPath $hostPath -PathType Leaf)){throw 'Stable product launcher is missing.'}
    $arguments='--maintenance '+$arguments
    $workingDirectory=$productRoot
}
$action=New-ScheduledTaskAction -Execute $hostPath -Argument $arguments -WorkingDirectory $workingDirectory
$triggers=@((New-ScheduledTaskTrigger -AtLogOn -User $sid),
    (New-ScheduledTaskTrigger -Once -At ([datetime]::Now.AddMinutes(1)) -RepetitionInterval (New-TimeSpan -Minutes 1)))
$principal=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$definition=New-ScheduledTask -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Description 'Maintain signed LanPilot revocation evidence with persisted retries under this user account.'
if($CheckOnly){
    $definition|Export-ScheduledTask
    return
}
$null=Register-ScheduledTask -TaskName $taskName -InputObject $definition -Force
Write-Output "trust_task=registered name=$taskName user_scope=1 interval_seconds=60 admin=0"
