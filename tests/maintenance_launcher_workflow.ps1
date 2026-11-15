param(
    [Parameter(Mandatory=$true)][string]$Launcher,
    [string]$PackagingDirectory=(Join-Path $PSScriptRoot '..\packaging\windows')
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$packaging=[IO.Path]::GetFullPath($PackagingDirectory)
Import-Module (Join-Path $packaging 'TrustMaintenance.psm1') -Force
$root=Join-Path ([IO.Path]::GetTempPath()) ('lanpilot windowless '+[Guid]::NewGuid().ToString('N'))
function Check([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
try {
    $null=New-Item -ItemType Directory -Path $root
    $binary=Join-Path $root 'rwn-maintenance-launcher.exe'
    Copy-Item -LiteralPath $Launcher -Destination $binary
    Copy-Item -LiteralPath (Join-Path $packaging 'TrustMaintenance.psm1') -Destination $root
    # A GUI PE entry point cannot create a console before parsing arguments.
    $bytes=[IO.File]::ReadAllBytes($binary)
    $pe=[BitConverter]::ToInt32($bytes,0x3c)
    Check ([BitConverter]::ToUInt16($bytes,$pe+24+68) -eq 2) 'Launcher must be a GUI-subsystem executable'
    $worker=Join-Path $root 'Invoke-LanPilotTrustMaintenance.ps1'
    $fixture=@'
param([string]$DataRoot)
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class ConsoleProbe { [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow(); }'
if([ConsoleProbe]::GetConsoleWindow() -ne [IntPtr]::Zero){exit 91}
Import-Module (Join-Path $PSScriptRoot 'TrustMaintenance.psm1') -Force
$probe='Add-Type -TypeDefinition ''using System; using System.Runtime.InteropServices; public static class NestedConsoleProbe { [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow(); }''; if([NestedConsoleProbe]::GetConsoleWindow() -ne [IntPtr]::Zero){exit 92}; exit 0'
$child=Invoke-LanPilotBoundedProcess (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') @('-NoProfile','-NonInteractive','-Command',$probe) 15
if($child.ExitCode){exit $child.ExitCode}
if(Test-Path -LiteralPath (Join-Path $DataRoot 'hold')){
 $start=[Diagnostics.ProcessStartInfo]::new((Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'))
 $start.UseShellExecute=$false; $start.CreateNoWindow=$true
 $start.Arguments='-NoProfile -NonInteractive -Command Start-Sleep -Seconds 30'
 $nested=[Diagnostics.Process]::Start($start)
 [IO.File]::WriteAllText((Join-Path $DataRoot 'child-pids.txt'),([string]$PID+','+[string]$nested.Id))
 Start-Sleep -Seconds 30
}
[IO.File]::WriteAllText((Join-Path $DataRoot 'receipt.txt'),'console=0')
exit 23
'@
    [IO.File]::WriteAllText($worker,$fixture,[Text.UTF8Encoding]::new($false))
    $result=Invoke-LanPilotBoundedProcess $binary @('--data-root',($root+'\')) 20
    Check ($result.ExitCode -eq 23) ('Child exit status was lost: '+$result.ExitCode)
    Check ((Get-Content -Raw -LiteralPath (Join-Path $root 'receipt.txt')) -eq 'console=0') 'Worker console probe did not complete'
    $invalid=Invoke-LanPilotBoundedProcess $binary @('--data-root','relative-path') 5
    Check ($invalid.ExitCode -eq 87) 'Relative data root accepted'
    $injection=Invoke-LanPilotBoundedProcess $binary @('--data-root',($root+'" -Command exit')) 5
    Check ($injection.ExitCode -eq 87) 'Quoted data root accepted'
    [IO.File]::WriteAllText((Join-Path $root 'hold'),'1')
    $start=[Diagnostics.ProcessStartInfo]::new($binary)
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    $start.Arguments='--data-root "'+$root+'"'
    $launcherProcess=[Diagnostics.Process]::Start($start)
    try {
        $deadline=[datetime]::UtcNow.AddSeconds(10)
        $pidsPath=Join-Path $root 'child-pids.txt'
        while(-not (Test-Path -LiteralPath $pidsPath) -and [datetime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 20}
        Check (Test-Path -LiteralPath $pidsPath) 'Cleanup fixture did not start'
        $children=@((Get-Content -Raw -LiteralPath $pidsPath).Split(',')|ForEach-Object{[Diagnostics.Process]::GetProcessById([int]$_)})
        try {
            $launcherProcess.Kill(); $launcherProcess.WaitForExit()
            foreach($process in $children){Check ($process.WaitForExit(3000)) 'Launcher termination left an orphaned process'}
        } finally {foreach($process in $children){$process.Dispose()}}
    } finally {
        if(-not $launcherProcess.HasExited){$launcherProcess.Kill()}
        $launcherProcess.Dispose()
    }
    Remove-Item -LiteralPath $worker
    $missing=Invoke-LanPilotBoundedProcess $binary @('--data-root',$root) 5
    Check ($missing.ExitCode -eq 2) 'Missing worker did not fail closed'
    # Unit tests must not require the Task Scheduler service/CIM permissions.
    # The installed action is additionally exercised by the runtime probe.
    $registration=Get-Content -Raw -LiteralPath (Join-Path $packaging 'Register-LanPilotMaintenance.ps1')
    Check ($registration.Contains("'rwn-maintenance-launcher.exe'")) 'Task still invokes a console host'
    Check ($registration.Contains('New-ScheduledTaskAction -Execute $hostPath')) 'Task bypasses the validated launcher'
    Check ($registration -notmatch 'powershell.exe') 'Console host used as task entry point'
    $maintenance=Get-Content -Raw -LiteralPath (Join-Path $packaging 'Maintain-LanPilotTrust.ps1')
    Check ($maintenance -notmatch '&\s+\$(ssh|scp)\b') 'Maintenance directly invokes a console transport'
    Write-Output 'maintenance_launcher_workflow=PASS gui_subsystem=1 child_console=0 nested_child_console=0 exit_propagation=1 bad_path_rejected=1 missing_worker_rejected=1 orphaned_children=0 task_action=windowless network=0 trust_changes=0'
} finally {
    # Explicitly scoped to the unique fixture directory resolved above.
    if(Test-Path -LiteralPath $root){Remove-Item -LiteralPath $root -Recurse -Force}
}
