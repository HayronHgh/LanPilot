#requires -Version 5.1
[CmdletBinding()]
param([string]$DataRoot='',
      [ValidateSet('configure','ssh')][string]$Connection='configure',
      [switch]$CheckOnly,[switch]$Maintenance)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$runtime=$null
try {
    if(-not $DataRoot){$DataRoot=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'LanPilot'}
    $root=Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $PSScriptRoot 'ProductInstall.psm1') -Force
    $runtime=Open-LanPilotInstalledRuntime $root $DataRoot
    if($CheckOnly){
        [IO.File]::WriteAllText((Join-Path $DataRoot 'maintenance\startup-status.json'),
            ('{"ready":true,"recovered":'+$runtime.Recovered.ToString().ToLowerInvariant()+'}'),[Text.UTF8Encoding]::new($false))
    } elseif($Maintenance){
        & (Join-Path $runtime.Directory 'Invoke-LanPilotTrustMaintenance.ps1') -DataRoot $DataRoot
    } else {
        & (Join-Path $runtime.Directory 'Start-LanPilot.ps1') -DataRoot $DataRoot -Connection $Connection
    }
} catch {
    if(-not $CheckOnly -and -not $Maintenance){
        Add-Type -AssemblyName System.Windows.Forms
        [Windows.Forms.MessageBox]::Show(('LanPilot could not start: '+$_.Exception.Message),'LanPilot',[Windows.Forms.MessageBoxButtons]::OK,[Windows.Forms.MessageBoxIcon]::Error)|Out-Null
    }
    exit 1
} finally {if($runtime){$runtime.Lease.Dispose()}}
