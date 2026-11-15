[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'Programs\LanPilot'),
    [string]$ConfigRoot = (Join-Path $env:LOCALAPPDATA 'LanPilot'),
    [switch]$RemoveConfiguration,[switch]$CheckOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$InstallRoot=[IO.Path]::GetFullPath($InstallRoot)
$expectedRoot=[IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Programs\LanPilot'))
if(-not $InstallRoot.Equals($expectedRoot,[StringComparison]::OrdinalIgnoreCase)){
    throw 'Refusing unexpected program removal root.'
}
Import-Module (Join-Path $PSScriptRoot 'ProductInstall.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'TrustMaintenance.psm1')
$ConfigRoot=Assert-LanPilotMaintenancePath $ConfigRoot
if($RemoveConfiguration -and -not $ConfigRoot.Equals(
    [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'LanPilot')),[StringComparison]::OrdinalIgnoreCase)){
    throw 'Refusing unexpected configuration removal.'
}
$shortcutPath=Join-Path ([Environment]::GetFolderPath('DesktopDirectory')) 'LanPilot.lnk'
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$taskName='LanPilot-TrustMaintenance-'+$sid
$registration='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\LanPilot'
$bindings=@{ShortcutBytes=$null;Task=$null;TaskXml=$null;TaskDisabled=$false;HadRegistration=$false;Registry=@()}

$result=Invoke-LanPilotProgramRemoval -InstallRoot $InstallRoot -DataRoot $ConfigRoot -RemoveConfiguration:$RemoveConfiguration -CheckOnly:$CheckOnly -PrepareBindings {
    # Snapshot ONLY this product's bindings, after installation ownership and
    # runtime leases have been acquired. No native key or trust operations.
    if(Test-Path -LiteralPath $shortcutPath){
        $null=Assert-LanPilotMaintenancePath $shortcutPath
        if((Get-Item -LiteralPath $shortcutPath).Length -gt 65536){throw 'Shortcut exceeds removal bound.'}
        $link=(New-Object -ComObject WScript.Shell).CreateShortcut($shortcutPath)
        $owned=$link.TargetPath -ieq (Join-Path $InstallRoot 'LanPilot.exe')
        $systemHost=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if($link.TargetPath -ieq $systemHost){
            foreach($name in @('Start-LanPilot.ps1','Start-LanPilotTls.ps1','Start-DesktopPreview.ps1')){
                if($link.Arguments.Contains(('"'+(Join-Path $InstallRoot $name)+'"'))){$owned=$true}
            }
        }
        if(-not $owned){throw 'LanPilot shortcut points to another installation; no bindings were removed.'}
        $bindings.ShortcutBytes=[IO.File]::ReadAllBytes($shortcutPath)
    }
    $bindings.Task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if($bindings.Task){
        $task=$bindings.Task
        $expectedArguments='--data-root "'+$ConfigRoot.TrimEnd([char[]]@('\','/'))+'"'
        $native=$task.Actions.Count -eq 1 -and $task.Actions[0].Execute -ieq (Join-Path $InstallRoot 'LanPilot.exe') -and
            $task.Actions[0].Arguments -ceq ('--maintenance '+$expectedArguments)
        $legacy=$task.Actions.Count -eq 1 -and $task.Actions[0].Execute -ieq (Join-Path $InstallRoot 'rwn-maintenance-launcher.exe') -and
            $task.Actions[0].Arguments -ceq $expectedArguments
        if(-not ($native -or $legacy)){throw 'Maintenance task points to another installation; no bindings were removed.'}
        $bindings.TaskXml=Export-ScheduledTask -TaskName $taskName
        if($bindings.TaskXml.Length -gt 65536){throw 'Task definition exceeds removal bound.'}
        $bindings.TaskDisabled=$task.State -eq 'Disabled'
    }
    $bindings.HadRegistration=Test-Path $registration
    if($bindings.HadRegistration){
        $record=Get-ItemProperty -Path $registration
        if(-not ([string]$record.InstallLocation).Equals($InstallRoot,[StringComparison]::OrdinalIgnoreCase)){
            throw 'Apps registration refers to another installation.'
        }
        $key=Get-Item -LiteralPath $registration
        foreach($name in $key.GetValueNames()){
            $bindings.Registry+=@{Name=$name;Value=$key.GetValue($name,$null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);Kind=$key.GetValueKind($name)}
        }
    }
} -Deactivate {
    if($bindings.Task){Stop-ScheduledTask -TaskName $taskName;Unregister-ScheduledTask -TaskName $taskName -Confirm:$false}
    if($null -ne $bindings.ShortcutBytes){Remove-Item -LiteralPath $shortcutPath -Force -ErrorAction Stop}
    if($bindings.HadRegistration){Remove-Item -LiteralPath $registration -Recurse -Force -ErrorAction Stop}
} -RestoreBindings {
    # The engine restores the program directory before this callback.
    if($bindings.TaskXml){
        $null=Register-ScheduledTask -TaskName $taskName -Xml $bindings.TaskXml -Force
        if($bindings.TaskDisabled){$null=Disable-ScheduledTask -TaskName $taskName}
    }
    if($null -ne $bindings.ShortcutBytes){[IO.File]::WriteAllBytes($shortcutPath,$bindings.ShortcutBytes)}
    if($bindings.HadRegistration){
        $null=New-Item -Path $registration -Force
        $key=Get-Item -LiteralPath $registration
        foreach($value in $bindings.Registry){$key.SetValue($value.Name,$value.Value,$value.Kind)}
    }
}
if($CheckOnly){Write-Output 'uninstall_preflight=passed removed=0 configuration_changed=0';return}
Write-Host ('LanPilot programs removed; configuration_removed='+$result.ConfigurationRemoved.ToString().ToLowerInvariant()+
    '; cleanup_pending='+$result.CleanupPending.ToString().ToLowerInvariant()+'.')
Write-Host 'Native identity-store keys and SSH keys were not deleted. Pairing/settings remain unless configuration removal was explicitly requested.'
