[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'Programs\RemoteWorkspaceNode'),
    [string]$ConfigRoot = (Join-Path $env:LOCALAPPDATA 'RemoteWorkspaceNode'),
    [switch]$RemoveConfiguration
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$expectedRoot = [IO.Path]::GetFullPath(
    (Join-Path $env:LOCALAPPDATA 'Programs\RemoteWorkspaceNode'))
if (-not $InstallRoot.Equals($expectedRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to remove unexpected install root: $InstallRoot"
}

$shortcutPath = Join-Path ([Environment]::GetFolderPath('DesktopDirectory')) 'Remote Workspace.lnk'
if (Test-Path -LiteralPath $shortcutPath) {
    Remove-Item -LiteralPath $shortcutPath -Force
}
if (Test-Path -LiteralPath $InstallRoot) {
    Remove-Item -LiteralPath $InstallRoot -Recurse -Force
}
if ($RemoveConfiguration) {
    $ConfigRoot = [IO.Path]::GetFullPath($ConfigRoot)
    $expectedConfig = [IO.Path]::GetFullPath(
        (Join-Path $env:LOCALAPPDATA 'RemoteWorkspaceNode'))
    if (-not $ConfigRoot.Equals(
            $expectedConfig, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove unexpected configuration root: $ConfigRoot"
    }
    if (Test-Path -LiteralPath $ConfigRoot) {
        Remove-Item -LiteralPath $ConfigRoot -Recurse -Force
    }
}

Write-Host 'Remote Workspace desktop preview removed.'
