[CmdletBinding()]
param([string]$ConfigPath='',[string]$ViewerPath='',
      [switch]$ConnectImmediately,[switch]$ValidateOnly,
      [switch]$CheckReadiness,[switch]$CheckLayout,[switch]$ExpectUnavailable)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not $ViewerPath){$ViewerPath=Join-Path $PSScriptRoot 'rwn-viewer.exe'}
if(-not $ConfigPath){$ConfigPath=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'LanPilot\tls-desktop.json'}
Import-Module (Join-Path $PSScriptRoot 'TlsConnectionSettings.psm1') -Force
Assert-LanPilotLocalPath $ConfigPath
Assert-LanPilotLocalPath $ViewerPath
if($ValidateOnly -and $CheckReadiness){throw 'Choose one diagnostic check.'}
if($ValidateOnly -or $CheckReadiness){
    $saved=Read-LanPilotTlsSettings $ConfigPath
    if($CheckReadiness){$null=Test-LanPilotTlsReadiness $saved}
    Write-Output 'TLS profile valid; no connection started, peer not authenticated.'
    return
}
$state=@{Settings=$null;Error='';Ready=$false}
function Read-SavedPairing {
    $state.Settings=$null; $state.Ready=$false; $state.Error=''
    try {
        $state.Settings=Read-LanPilotTlsSettings $ConfigPath
        if(-not $CheckLayout){$null=Test-LanPilotTlsReadiness $state.Settings}
        $state.Ready=$true
    } catch {$state.Error=$_.Exception.Message}
}
Read-SavedPairing
if((-not $ConnectImmediately) -or (-not $state.Ready) -or $CheckLayout){
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [Windows.Forms.Application]::EnableVisualStyles()
    $form=[Windows.Forms.Form]::new()
    $form.Text='LanPilot - Connect to Mac'
    $form.ClientSize=[Drawing.Size]::new(560,330)
    $form.StartPosition='CenterScreen'; $form.FormBorderStyle='FixedDialog'; $form.MaximizeBox=$false
    $form.AutoScaleMode='Dpi'; $form.Font=[Drawing.Font]::new('Segoe UI',10)
    $label=[Windows.Forms.Label]::new(); $label.Text='Mac IP / hostname'; $label.SetBounds(24,28,500,22); $form.Controls.Add($label)
    $address=[Windows.Forms.TextBox]::new(); $address.AccessibleName='Mac IP / hostname'; $address.MaxLength=253; $address.SetBounds(24,58,512,28); $form.Controls.Add($address)
    $control=[Windows.Forms.ComboBox]::new(); $control.AccessibleName='Connection permissions'; $control.DropDownStyle='DropDownList'
    $null=$control.Items.AddRange([object[]]@('View only','Control keyboard and mouse')); $control.SelectedIndex=0
    $control.SetBounds(24,108,512,30); $form.Controls.Add($control)
    $status=[Windows.Forms.Label]::new(); $status.SetBounds(24,164,512,94); $form.Controls.Add($status)
    $retry=[Windows.Forms.Button]::new(); $retry.Text='Check again'; $retry.SetBounds(24,276,130,32); $form.Controls.Add($retry)
    $details=[Windows.Forms.Button]::new(); $details.Text='Diagnostics'; $details.SetBounds(166,276,130,32); $form.Controls.Add($details)
    $connect=[Windows.Forms.Button]::new(); $connect.Text='Connect'; $connect.SetBounds(366,276,170,32); $form.Controls.Add($connect); $form.AcceptButton=$connect
    $refresh={
        if($state.Ready){
            $address.Text=$state.Settings.host
            $control.SelectedIndex=if($state.Settings.control -eq 'interactive'){1}else{0}
            $status.Text='Paired device loaded. Confirm the Mac address and connect. Identity is verified again on every connection.'
            $status.ForeColor=[Drawing.Color]::DarkGreen
        } else {
            $status.Text=if(Test-Path -LiteralPath ($ConfigPath+'.recovery')){'Saved connection is unavailable. Choose Repair connection to restore this Windows account''s protected settings. Remote identity will still be verified.'}else{'No usable saved connection. First-time secure pairing is not available in this build yet. No private keys or certificate details need to be typed here.'}
            $status.ForeColor=[Drawing.Color]::Firebrick
        }
        $connect.Enabled=$state.Ready
        $retry.Text=if(-not $state.Ready -and (Test-Path -LiteralPath ($ConfigPath+'.recovery'))){'Repair connection'}else{'Check again'}
    }
    & $refresh
    $retry.Add_Click({
        try {
            if(-not $state.Ready -and (Test-Path -LiteralPath ($ConfigPath+'.recovery'))){
                $null=Restore-LanPilotRecovery $ConfigPath
            }
            Read-SavedPairing; & $refresh
        } catch {$state.Error=$_.Exception.Message; $status.Text='Repair could not complete. No remote identity was trusted. See Diagnostics.'}
    })
    $details.Add_Click({
        [Windows.Forms.MessageBox]::Show(('Pairing profile: '+$ConfigPath+[Environment]::NewLine+$state.Error),'LanPilot diagnostics') | Out-Null
    })
    $connect.Add_Click({
        try {
            $candidate=$state.Settings | ConvertTo-Json | ConvertFrom-Json
            $candidate.host=$address.Text.Trim()
            $candidate.control=if($control.SelectedIndex -eq 1){'interactive'}else{'view-only'}
            $null=Get-LanPilotTlsArguments $candidate
            $null=Test-LanPilotTlsReadiness $candidate
            if(-not (Test-Path -LiteralPath $ViewerPath -PathType Leaf)){throw 'Viewer is missing. Reinstall the verified LanPilot package.'}
            Save-LanPilotTlsSettings $ConfigPath $candidate
            Save-LanPilotRecovery $ConfigPath
            $state.Settings=$candidate
            $form.DialogResult=[Windows.Forms.DialogResult]::OK; $form.Close()
        } catch {$status.Text='Cannot connect: '+$_.Exception.Message; $status.ForeColor=[Drawing.Color]::Firebrick}
    })
    try {
        if($CheckLayout){
            if($ExpectUnavailable){
                if($state.Ready -or $connect.Enabled){throw 'Unavailable pairing allowed connection'}
                if(@($form.Controls | Where-Object {$_ -is [Windows.Forms.TextBox]}).Count -ne 1){throw 'Unavailable pairing exposes trust entry'}
                Write-Output 'TLS unavailable layout PASS: connect_disabled=1 trust_fields=0; UI=0 network=0'
                return
            }
            if(-not $state.Ready){throw 'Expected existing valid pairing for layout check.'}
            if($address.Text -cne $state.Settings.host -or -not $connect.Enabled){throw 'Saved device not bound'}
            if(@($form.Controls | Where-Object {$_ -is [Windows.Forms.TextBox]}).Count -ne 1){throw 'User must not edit trust fields'}
            Write-Output 'TLS layout PASS: pairing_loaded=1 editable_text_fields=1 trust_fields=0; UI=0 network=0'
            return
        }
        if($form.ShowDialog() -ne [Windows.Forms.DialogResult]::OK){return}
    } finally {$form.Dispose()}
}
$arguments=Get-LanPilotTlsArguments $state.Settings
$null=Test-LanPilotTlsReadiness $state.Settings
if(-not (Test-Path -LiteralPath $ViewerPath -PathType Leaf)){throw 'Viewer is missing. Reinstall the verified LanPilot package.'}
$start=[Diagnostics.ProcessStartInfo]::new([IO.Path]::GetFullPath($ViewerPath))
$start.UseShellExecute=$true; $start.WindowStyle=[Diagnostics.ProcessWindowStyle]::Normal
$start.WorkingDirectory=Split-Path -Parent ([IO.Path]::GetFullPath($ViewerPath))
$start.Arguments=(@($arguments | ForEach-Object {'"'+$_+'"'}) -join ' ')
$null=[Diagnostics.Process]::Start($start)
