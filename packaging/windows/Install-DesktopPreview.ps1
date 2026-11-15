[CmdletBinding()]
param(
    [string]$HostName = '',

    [string]$SshKey = '',

    [string]$RemoteAgent = '',

    [ValidateSet('h264', 'snapshot-only', 'raw-rect-experimental')]
    [string]$Hybrid = 'h264',

    [ValidateSet('ssh','tls')]
    [string]$Transport = 'tls',

    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'Programs\LanPilot'),
    [string]$ConfigRoot = (Join-Path $env:LOCALAPPDATA 'LanPilot'),
    [switch]$ForceConfig,
    [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+$')]
    [string]$ProductVersion = '0.1.0'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-AbsoluteWindowsPath([string]$Path) {
    return $Path -match '^(?:[A-Za-z]:[\\/]|\\\\[^\\]+\\[^\\]+[\\/])'
}

$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$ConfigRoot = [IO.Path]::GetFullPath($ConfigRoot)
$allowedInstallParent = [IO.Path]::GetFullPath(
    (Join-Path $env:LOCALAPPDATA 'Programs'))
if (-not $InstallRoot.Equals((Join-Path $allowedInstallParent 'LanPilot'),
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'LanPilot has one canonical installation under LocalAppData\Programs\LanPilot.'
}
if ($HostName -or $SshKey -or $RemoteAgent) {
    if ($HostName -notmatch '^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+$') {
        throw 'HostName must use user@host form.'
    }
    if (-not (Test-AbsoluteWindowsPath $SshKey) -or
        -not (Test-Path -LiteralPath $SshKey -PathType Leaf)) {
        throw 'SshKey must be an existing absolute file.'
    }
    if (-not $RemoteAgent) {
        $RemoteAgent = '/Users/' + $HostName.Split('@')[0] + '/.local/libexec/remoteworkspacenode/rwn-desktop-agent'
    }
    if ($RemoteAgent -notmatch '^/[A-Za-z0-9/_.-]+$' -or $RemoteAgent.Contains('..')) {
        throw 'RemoteAgent must be an absolute canonical POSIX path.'
    }
}

Import-Module (Join-Path $PSScriptRoot 'ProductInstall.psm1') -Force
$configPath = Join-Path $ConfigRoot 'desktop.json'
# Activation runs in a child scope inside the transaction module. Keep the
# shortcut path in the caller's scope too: the final receipt uses it afterward.
$shortcutPath = Join-Path ([Environment]::GetFolderPath('DesktopDirectory')) 'LanPilot.lnk'
$update=Invoke-LanPilotProgramUpdate -SourceDirectory $PSScriptRoot -InstallRoot $InstallRoot -DataRoot $ConfigRoot -Activate {
    param($activeRoot)
    New-Item -ItemType Directory -Path $ConfigRoot -Force | Out-Null
    foreach ($name in @('connections','identity','logs','maintenance')) {
        New-Item -ItemType Directory -Path (Join-Path $ConfigRoot $name) -Force | Out-Null
    }
    if ($ForceConfig -or -not (Test-Path -LiteralPath $configPath)) {
        $configJson = [ordered]@{
            schema = 1
            host = $HostName
            sshKey = if ($SshKey) { [IO.Path]::GetFullPath($SshKey) } else { '' }
            remoteAgent = $RemoteAgent
            hybrid = $Hybrid
            control = if ($HostName) { 'interactive' } else { 'view' }
        } | ConvertTo-Json
        [IO.File]::WriteAllText(
            $configPath, $configJson, (New-Object Text.UTF8Encoding($false)))
    }

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = Join-Path $InstallRoot 'LanPilot.exe'
    $shortcut.Arguments = if($Transport -eq 'ssh'){'--connection ssh'}else{''}
    $defaultData=[IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'LanPilot'))
    if(-not $ConfigRoot.Equals($defaultData,[StringComparison]::OrdinalIgnoreCase)){
        $shortcut.Arguments=('--data-root "'+$ConfigRoot.TrimEnd([char[]]@('\','/'))+'" '+$shortcut.Arguments).TrimEnd()
    }
    $shortcut.WorkingDirectory = $InstallRoot
    $shortcut.Description = 'Connect to a paired computer with LanPilot'
    $shortcut.IconLocation = Join-Path $InstallRoot 'LanPilot.exe'
    $shortcut.Save()

    # One per-user Apps entry. Updating replaces these values, not the user's state.
    $registration='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\LanPilot'
    $null=New-Item -Path $registration -Force
    $uninstaller=Join-Path $InstallRoot 'bootstrap\Uninstall-DesktopPreview.ps1'
    $hostPath=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $values=@{DisplayName='LanPilot';DisplayVersion=$ProductVersion;Publisher='LanPilot Project';InstallLocation=$InstallRoot;
        DisplayIcon=(Join-Path $InstallRoot 'LanPilot.exe');
        UninstallString=('"'+$hostPath+'" -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+$uninstaller+'" -InstallRoot "'+$InstallRoot+'" -ConfigRoot "'+$ConfigRoot+'"')}
    foreach($value in $values.GetEnumerator()){$null=New-ItemProperty -Path $registration -Name $value.Key -Value $value.Value -PropertyType String -Force}
    foreach($name in @('NoModify','NoRepair')){$null=New-ItemProperty -Path $registration -Name $name -Value 1 -PropertyType DWord -Force}
    $null=& (Join-Path $activeRoot 'Register-LanPilotMaintenance.ps1') -DataRoot $ConfigRoot
}

Write-Host "Installed: $InstallRoot"
Write-Host "Program transaction: $($update.Status); identity/settings replacement: false"
Write-Host "Configuration: $configPath"
Write-Host "Shortcut: $shortcutPath"
Write-Host 'Only LanPilot.lnk is placed on the desktop. Settings, identity metadata, logs and maintenance state remain under LocalAppData\LanPilot.'
Write-Host 'The default mode is h264 until Hybrid promotion evidence passes.'
if ($Transport -eq 'tls') {
    Write-Host 'TLS mode selected. Existing paired identities and profiles are retained and loaded by the unified launcher.'
    Write-Host 'A fresh installation still requires the secure first-time pairing flow; installation never fabricates trust.'
}
