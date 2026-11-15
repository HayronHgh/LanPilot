[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Destination,
    [string[]]$ForbiddenTokens=@()
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'SourceExport.psm1') -Force
$root=[IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$result=Export-LanPilotPublicSource -SourceRoot $root -Destination $Destination -ForbiddenTokens $ForbiddenTokens
Write-Output "public_source_export=$($result.Status) files=$($result.Files) hashes=matched history_copied=0"
Write-Output 'Source-manifest.json is an integrity inventory, not a publisher signature or release acceptance.'