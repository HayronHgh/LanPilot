[CmdletBinding()]
param([Parameter(Mandatory)][string]$ProfilePath)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'packaging/windows/TlsConnectionSettings.psm1') -Force
# Actual existing product settings parser; no certificate import/store access,
# trust mutation, listener, desktop, clipboard, input or interactive UI.
$settings=Read-LanPilotTlsSettings $ProfilePath
if($settings.control -cne 'view-only' -or $settings.visual -cne 'h264-only'){
    throw 'New enrollment implicitly changed permission or visual defaults.'
}
$arguments=Get-LanPilotTlsArguments $settings
if($arguments.Count -ne 11 -or $arguments[0] -cne '--tls' -or $arguments[9] -cne '--native-status' -or $arguments[10] -cne 'required'){
    throw 'Native enrollment profile is incompatible with the existing launcher.'
}
$wrong=$settings | ConvertTo-Json | ConvertFrom-Json
$wrong.status=@('native');$rejected=$false
try {$null=Get-LanPilotTlsArguments $wrong} catch {$rejected=$true}
if(-not $rejected){throw 'Non-scalar native status mode was accepted.'}
$legacy=$settings | ConvertTo-Json | ConvertFrom-Json
$legacy.schema=1;$legacy.PSObject.Properties.Remove('status')
if(@(Get-LanPilotTlsArguments $legacy).Count -ne 9){throw 'Legacy profile compatibility changed.'}
Write-Output 'enrollment_configuration_reader=PASS peer_authenticated=0 key_store_access=0'
