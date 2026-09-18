[CmdletBinding()]
param(
    [string]$HostName = '',

    [string]$SshKey = '',

    [string]$RemoteAgent = '',

    [ValidateSet('h264', 'snapshot-only', 'raw-rect-experimental')]
    [string]$Hybrid = 'h264',

    [ValidateSet('ssh','tls')]
    [string]$Transport = 'ssh',

    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'Programs\RemoteWorkspaceNode'),
    [string]$ConfigRoot = (Join-Path $env:LOCALAPPDATA 'RemoteWorkspaceNode'),
    [switch]$ForceConfig
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
if (-not $InstallRoot.StartsWith(
        $allowedInstallParent + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw "InstallRoot must remain under $allowedInstallParent"
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

$sourceViewer = Join-Path $PSScriptRoot 'rwn-viewer.exe'
$sourceLauncher = Join-Path $PSScriptRoot 'Start-DesktopPreview.ps1'
$sourceUninstaller = Join-Path $PSScriptRoot 'Uninstall-DesktopPreview.ps1'
$sourceTlsLauncher = Join-Path $PSScriptRoot 'Start-LanPilotTls.ps1'
$sourceTlsSettings = Join-Path $PSScriptRoot 'TlsConnectionSettings.psm1'
$sources=@($sourceViewer, $sourceLauncher, $sourceUninstaller, $sourceTlsLauncher, $sourceTlsSettings)
foreach ($source in $sources) {
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Release package is incomplete: $source"
    }
}

New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
foreach ($source in $sources) {
    $destination = Join-Path $InstallRoot ([IO.Path]::GetFileName($source))
    $temporary = "$destination.new"
    Copy-Item -LiteralPath $source -Destination $temporary -Force
    Move-Item -LiteralPath $temporary -Destination $destination -Force
}

New-Item -ItemType Directory -Path $ConfigRoot -Force | Out-Null
$configPath = Join-Path $ConfigRoot 'desktop.json'
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

$desktop = [Environment]::GetFolderPath('DesktopDirectory')
$shortcutPath = Join-Path $desktop 'Remote Workspace.lnk'
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$launcher = Join-Path $InstallRoot 'Start-DesktopPreview.ps1'
if ($Transport -eq 'tls') { $launcher = Join-Path $InstallRoot 'Start-LanPilotTls.ps1' }
$shortcut.Arguments = "-NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$launcher`""
$shortcut.WorkingDirectory = $InstallRoot
$shortcut.Description = 'Configure and connect to a Remote Workspace Mac'
$shortcut.IconLocation = Join-Path $InstallRoot 'rwn-viewer.exe'
$shortcut.Save()

Write-Host "Installed: $InstallRoot"
Write-Host "Configuration: $configPath"
Write-Host "Shortcut: $shortcutPath"
Write-Host 'The default mode is h264 until Hybrid promotion evidence passes.'
if ($Transport -eq 'tls') {
    Write-Host 'Experimental TLS launcher selected. Paired identities, CA and CRL are prerequisites; none were provisioned.'
    Write-Host 'TLS profile is separate under LOCALAPPDATA\LanPilot and is retained by uninstall.'
}
