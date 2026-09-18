[CmdletBinding()]
param(
    [string]$ConfigPath='',
    [string]$ViewerPath='',
    [switch]$ConnectImmediately,
    [switch]$ValidateOnly,
    [switch]$CheckReadiness,
    [switch]$CheckLayout
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not $ViewerPath){$ViewerPath=Join-Path $PSScriptRoot 'rwn-viewer.exe'}
if(-not $ConfigPath){$ConfigPath=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'LanPilot\tls-desktop.json'}
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
    $form.Text='LanPilot - Connect to Mac'
    $form.ClientSize=[Drawing.Size]::new(700,280)
    $form.StartPosition='CenterScreen'; $form.FormBorderStyle='FixedDialog'; $form.MaximizeBox=$false
    $form.AutoScaleMode='Dpi'; $form.Font=[Drawing.Font]::new('Segoe UI',10)
    $fields=@{}
    $advanced=[Windows.Forms.Panel]::new(); $advanced.SetBounds(0,210,700,390)
    $advanced.Visible=$false; $form.Controls.Add($advanced)
    $y=0
    foreach($name in @('host','port','clientCertificate','serverFingerprint','rootDer','crlDer')){
        $labels=@{host='Mac IP / hostname';port='TLS port';clientCertificate='Paired Windows identity (SHA-1)';serverFingerprint='Paired Mac identity (SHA-256)';rootDer='CA certificate (.der)';crlDer='Revocation list (.der)'}
        $parent=$advanced; $top=$y
        if($name -eq 'host'){$parent=$form; $top=16}else{$y+=62}
        $label=[Windows.Forms.Label]::new(); $label.Text=$labels[$name]; $label.SetBounds(24,$top,650,20); $parent.Controls.Add($label)
        $field=[Windows.Forms.TextBox]::new(); $field.MaxLength=2048
        $field.Text=[string]($settings.PSObject.Properties[$name].Value)
        $field.AccessibleName=$labels[$name]; $field.SetBounds(24,($top+22),650,26)
        $parent.Controls.Add($field); $fields[$name]=$field
        if($name -in @('rootDer','crlDer')){
            $field.Width=540
            $browse=[Windows.Forms.Button]::new(); $browse.Text='Browse...'; $browse.Tag=$field
            $browse.SetBounds(576,($top+20),98,30); $parent.Controls.Add($browse)
            $browse.Add_Click({
                $dialog=[Windows.Forms.OpenFileDialog]::new()
                $dialog.Filter='DER files (*.der)|*.der|All files (*.*)|*.*'
                $dialog.CheckFileExists=$true; $dialog.Multiselect=$false
                try {if($dialog.ShowDialog() -eq [Windows.Forms.DialogResult]::OK){$this.Tag.Text=$dialog.FileName}} finally {$dialog.Dispose()}
            })
        }
    }
    foreach($name in @('control','visual')){
        $box=[Windows.Forms.ComboBox]::new(); $box.DropDownStyle='DropDownList'; $box.AccessibleName=$name
        if($name -eq 'control'){
            $null=$box.Items.AddRange([object[]]@('View only','Control keyboard and mouse'))
            $box.SelectedIndex=if($settings.control -eq 'interactive'){1}else{0}
            $box.SetBounds(24,82,370,28); $form.Controls.Add($box)
        } else {
            $null=$box.Items.AddRange([object[]]@('h264-only','exact-only')); $box.SelectedItem=$settings.visual
            $box.SetBounds(24,320,300,28); $advanced.Controls.Add($box)
        }
        $fields[$name]=$box
    }
    $info=[Windows.Forms.Label]::new(); $info.SetBounds(24,120,650,46)
    $paired=Test-Path -LiteralPath $ConfigPath -PathType Leaf
    $info.Text=if($paired){'Saved pairing loaded. Usually only the Mac IP needs changing. The paired identity is still verified when connecting.'}else{'No saved pairing. This build requires provisioned identities in Advanced settings; automatic first-time pairing is not available yet.'}
    $form.Controls.Add($info)
    $toggle=[Windows.Forms.CheckBox]::new(); $toggle.Text='Advanced settings'; $toggle.SetBounds(24,176,230,26); $form.Controls.Add($toggle)
    $errorLabel=[Windows.Forms.Label]::new(); $errorLabel.ForeColor=[Drawing.Color]::Firebrick; $errorLabel.SetBounds(24,212,445,56); $form.Controls.Add($errorLabel)
    $connect=[Windows.Forms.Button]::new(); $connect.Text='Connect'; $connect.SetBounds(484,230,190,32); $form.Controls.Add($connect); $form.AcceptButton=$connect
    $toggle.Add_CheckedChanged({
        $advanced.Visible=$toggle.Checked
        $form.ClientSize=[Drawing.Size]::new(700,$(if($toggle.Checked){680}else{280}))
        $errorLabel.Top=if($toggle.Checked){606}else{212}
        $connect.Top=if($toggle.Checked){634}else{230}
    })
    $connect.Add_Click({
        try {
            if($fields.port.Text -notmatch '^[1-9][0-9]{0,4}$'){throw 'Enter a canonical port number.'}
            foreach($name in @('host','clientCertificate','serverFingerprint','rootDer','crlDer')){$settings.$name=$fields[$name].Text.Trim()}
            $settings.port=[int]$fields.port.Text
            $settings.control=if($fields.control.SelectedIndex -eq 1){'interactive'}else{'view-only'}; $settings.visual=[string]$fields.visual.SelectedItem
            $null=Get-LanPilotTlsArguments $settings
            if(-not (Test-Path -LiteralPath $ViewerPath -PathType Leaf)){throw 'Viewer executable is missing.'}
            $null=Test-LanPilotTlsReadiness $settings
            Save-LanPilotTlsSettings $ConfigPath $settings
            $form.DialogResult=[Windows.Forms.DialogResult]::OK; $form.Close()
        } catch {$errorLabel.Text=$_.Exception.Message}
    })
    try{
        if($CheckLayout){
            foreach($name in @('host','port','clientCertificate','serverFingerprint','rootDer','crlDer')){
                if($fields[$name].Text -cne [string]($settings.PSObject.Properties[$name].Value)){throw "Saved field not bound: $name"}
            }
            if($advanced.Visible -or $form.ClientSize.Height -ne 280){throw 'Advanced settings must start collapsed'}
            if(@($advanced.Controls | Where-Object {$_ -is [Windows.Forms.Button]}).Count -ne 2){throw 'Trust file browsers missing'}
            Write-Output 'TLS layout PASS: saved fields bound, advanced collapsed, file browsers=2; UI=0 network=0'
            return
        }
        if($form.ShowDialog() -ne [Windows.Forms.DialogResult]::OK){return}
    }finally{$form.Dispose()}
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
