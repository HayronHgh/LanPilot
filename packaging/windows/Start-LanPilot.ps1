[CmdletBinding()]
param([ValidateSet('choose','tls','ssh','configure')][string]$Connection='choose',
      [switch]$CheckLayout)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [Windows.Forms.Application]::EnableVisualStyles()
    if($CheckLayout){$Connection='configure'}
    if($Connection -eq 'choose') {
        $form=[Windows.Forms.Form]::new()
        $form.Text='LanPilot - Connect'
        $form.ClientSize=[Drawing.Size]::new(480,260)
        $form.StartPosition='CenterScreen'
        $form.FormBorderStyle='FixedDialog'; $form.MaximizeBox=$false
        $form.AutoScaleMode='Dpi'
        $form.Font=[Drawing.Font]::new('Segoe UI',10)
        $label=[Windows.Forms.Label]::new()
        $label.Text="Choose a connection. Existing profiles and permissions are preserved."
        $label.SetBounds(24,20,432,48); $form.Controls.Add($label)
        $latest=[Windows.Forms.Button]::new()
        $latest.Text='Connect: RECT + TLS (latest)'
        $latest.SetBounds(24,78,432,38); $form.Controls.Add($latest)
        $configure=[Windows.Forms.Button]::new()
        $configure.Text='Configure TLS connection'
        $configure.SetBounds(24,126,432,38); $form.Controls.Add($configure)
        $legacy=[Windows.Forms.Button]::new()
        $legacy.Text='Original SSH connection (H.264 / RECT)'
        $legacy.SetBounds(24,174,432,38); $form.Controls.Add($legacy)
        $latest.Add_Click({$form.Tag='tls'; $form.Close()})
        $configure.Add_Click({$form.Tag='configure'; $form.Close()})
        $legacy.Add_Click({$form.Tag='ssh'; $form.Close()})
        $form.AcceptButton=$latest
        try { $null=$form.ShowDialog(); $selected=$form.Tag } finally {$form.Dispose()}
        if(-not $selected){return}
    } else {$selected=$Connection}
    if($selected -eq 'ssh') {
        & (Join-Path $PSScriptRoot 'Start-DesktopPreview.ps1')
    } else {
        $immediate=$selected -eq 'tls'
        $tlsProfilePath=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'LanPilot\tls-desktop.json'
        if(-not (Test-Path -LiteralPath $tlsProfilePath -PathType Leaf)){$immediate=$false}
        & (Join-Path $PSScriptRoot 'Start-LanPilotTls.ps1') -ConfigPath $tlsProfilePath -ViewerPath (Join-Path $PSScriptRoot 'rwn-viewer.exe') -ConnectImmediately:$immediate -CheckLayout:$CheckLayout
    }
} catch {
    [Windows.Forms.MessageBox]::Show($_.Exception.Message,'LanPilot - Connection failed',
        [Windows.Forms.MessageBoxButtons]::OK,[Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    exit 1
}
