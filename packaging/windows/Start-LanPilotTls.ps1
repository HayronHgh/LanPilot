[CmdletBinding()]
param(
    [string]$ConfigPath=(Join-Path $env:LOCALAPPDATA 'LanPilot\tls-desktop.json'),
    [string]$ViewerPath='',
    [switch]$ConnectImmediately,
    [switch]$ValidateOnly,
    [switch]$CheckReadiness
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not $ViewerPath){$ViewerPath=Join-Path $PSScriptRoot 'rwn-viewer.exe'}
if($ValidateOnly -and $CheckReadiness){throw 'Choose either configuration validation or local identity readiness.'}
Import-Module (Join-Path $PSScriptRoot 'TlsConnectionSettings.psm1') -Force
Assert-LanPilotLocalPath $ConfigPath
Assert-LanPilotLocalPath $ViewerPath
$settings=[pscustomobject]@{schema=1;transport='tls';host='';port=45443;clientCertificate='';serverFingerprint='';rootDer='';crlDer='';control='view-only';visual='h264-only'}
if(Test-Path -LiteralPath $ConfigPath){$settings=Read-LanPilotTlsSettings $ConfigPath}
elseif($ConnectImmediately -or $ValidateOnly -or $CheckReadiness){throw 'Create a TLS connection profile first.'}
if(-not $ConnectImmediately -and -not $ValidateOnly -and -not $CheckReadiness){
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [Windows.Forms.Application]::EnableVisualStyles()
    $form=[Windows.Forms.Form]::new()
    $form.Text='LanPilot — Direct TLS (experimental)'
    $form.ClientSize=[Drawing.Size]::new(700,680)
    $form.StartPosition='CenterScreen'; $form.FormBorderStyle='FixedDialog'; $form.MaximizeBox=$false
    $form.AutoScaleMode='Dpi'; $form.Font=[Drawing.Font]::new('Segoe UI',10)
    $fields=@{}; $y=18
    foreach($item in @(@('host','Mac host / IPv4'),@('port','Dedicated TLS port'),@('clientCertificate','Windows client certificate SHA-1 (CurrentUser/My)'),@('serverFingerprint','Paired Mac certificate SHA-256'),@('rootDer','Application CA certificate (.der)'),@('crlDer','Application certificate revocation list (.der)'))){
        $label=[Windows.Forms.Label]::new(); $label.Text=$item[1]; $label.SetBounds(24,$y,650,22); $form.Controls.Add($label)
        $field=[Windows.Forms.TextBox]::new(); $field.Text=[string]$settings.($item[0]); $field.MaxLength=2048
        $field.AccessibleName=$item[1]; $field.SetBounds(24,($y+24),650,26); $form.Controls.Add($field); $fields[$item[0]]=$field; $y+=66
    }
    foreach($item in @(@('control','view-only','interactive'),@('visual','h264-only','exact-only'))){
        $box=[Windows.Forms.ComboBox]::new(); $box.DropDownStyle='DropDownList'; $box.AccessibleName=$item[0]
        $null=$box.Items.AddRange([object[]]@($item[1],$item[2])); $box.SelectedItem=$settings.($item[0]); $box.SetBounds(24,$y,300,28)
        $form.Controls.Add($box); $fields[$item[0]]=$box; $y+=38
    }
    $info=[Windows.Forms.Label]::new(); $info.SetBounds(24,500,650,62)
    $info.Text='Visual + control use independent TLS sockets. Agent remains SSH. Certificates must already be provisioned. No private keys are copied and no trust/firewall settings are changed.'
    $form.Controls.Add($info)
    $errorLabel=[Windows.Forms.Label]::new(); $errorLabel.ForeColor=[Drawing.Color]::Firebrick; $errorLabel.SetBounds(24,564,650,52); $form.Controls.Add($errorLabel)
    $connect=[Windows.Forms.Button]::new(); $connect.Text='Save and connect'; $connect.SetBounds(484,625,190,32); $form.Controls.Add($connect); $form.AcceptButton=$connect
    $connect.Add_Click({
        try {
            if($fields.port.Text -notmatch '^[1-9][0-9]{0,4}$'){throw 'Enter a canonical port number.'}
            foreach($name in @('host','clientCertificate','serverFingerprint','rootDer','crlDer')){$settings.$name=$fields[$name].Text.Trim()}
            $settings.port=[int]$fields.port.Text
            $settings.control=[string]$fields.control.SelectedItem; $settings.visual=[string]$fields.visual.SelectedItem
            $null=Get-LanPilotTlsArguments $settings
            if(-not (Test-Path -LiteralPath $ViewerPath -PathType Leaf)){throw 'Viewer executable is missing.'}
            $null=Test-LanPilotTlsReadiness $settings
            Save-LanPilotTlsSettings $ConfigPath $settings
            $form.DialogResult=[Windows.Forms.DialogResult]::OK; $form.Close()
        } catch {$errorLabel.Text=$_.Exception.Message}
    })
    try{if($form.ShowDialog() -ne [Windows.Forms.DialogResult]::OK){return}}finally{$form.Dispose()}
}
$arguments=Get-LanPilotTlsArguments $settings
if($ValidateOnly){Write-Output 'TLS profile valid; no connection started, certificates not authenticated.'; return}
$readiness=Test-LanPilotTlsReadiness $settings
if($CheckReadiness){
    Write-Output ('Local client identity ready; expires UTC '+$readiness.ExpiresUtc.ToString('o')+'. Peer not authenticated; no connection started.')
    return
}
if(-not (Test-Path -LiteralPath $ViewerPath -PathType Leaf)){throw 'Viewer executable is missing.'}
# Launch the GUI explicitly; do not inherit a hidden PowerShell window's show
# command. Read current trust paths from the profile, not stale shortcut argv.
$start=[Diagnostics.ProcessStartInfo]::new([IO.Path]::GetFullPath($ViewerPath))
$start.UseShellExecute=$true
$start.WindowStyle=[Diagnostics.ProcessWindowStyle]::Normal
$start.WorkingDirectory=Split-Path -Parent ([IO.Path]::GetFullPath($ViewerPath))
# Validated arguments cannot contain quotes; trust paths refer to regular files
# and cannot end in a directory separator. Quote every argument for spaces.
$start.Arguments=(@($arguments | ForEach-Object {'"'+$_+'"'}) -join ' ')
$null=[Diagnostics.Process]::Start($start)
