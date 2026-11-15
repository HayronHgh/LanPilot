[CmdletBinding()]
param([string]$ConfigPath='',[string]$ViewerPath='',
      [switch]$ConnectImmediately,[switch]$ValidateOnly,
      [switch]$CheckReadiness,[switch]$CheckLayout,[switch]$ExpectUnavailable,
      [switch]$CheckEventLoop,[switch]$CheckViewerFailure)
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
$state=@{Settings=$null;Error='';Ready=$false;Clipboard=$false;PairingProcess=$null;ViewerProcess=$null}
$pairingPath=$ViewerPath
function Read-SavedPairing {
    $state.Settings=$null; $state.Ready=$false; $state.Error=''
    try {
        # Recover only this account's protected record, never infer a peer pin
        # from IP/discovery or select an arbitrary certificate from the store.
        if(-not (Test-Path -LiteralPath $ConfigPath) -and
           (Test-Path -LiteralPath ($ConfigPath+'.recovery') -PathType Leaf)){
            $null=Restore-LanPilotRecovery $ConfigPath
        }
        $state.Settings=Read-LanPilotTlsSettings $ConfigPath
        if(-not $CheckLayout){$null=Test-LanPilotTlsReadiness $state.Settings}
        $state.Ready=$true
    } catch {$state.Error=$_.Exception.Message}
}
Read-SavedPairing
if((-not $ConnectImmediately) -or (-not $state.Ready) -or $CheckLayout -or $CheckEventLoop){
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [Windows.Forms.Application]::EnableVisualStyles()
    $form=[Windows.Forms.Form]::new()
    $form.Text='LanPilot - Connect to Mac [2026.09.19.2]'
    $form.ClientSize=[Drawing.Size]::new(560,370)
    $form.StartPosition='CenterScreen'; $form.FormBorderStyle='FixedDialog'; $form.MaximizeBox=$false
    $form.AutoScaleMode='Dpi'; $form.Font=[Drawing.Font]::new('Segoe UI',10)
    $label=[Windows.Forms.Label]::new(); $label.Text='Mac IP / hostname'; $label.SetBounds(24,28,500,22); $form.Controls.Add($label)
    $address=[Windows.Forms.TextBox]::new(); $address.AccessibleName='Mac IP / hostname'; $address.MaxLength=253; $address.SetBounds(24,58,512,28); $form.Controls.Add($address)
    $control=[Windows.Forms.ComboBox]::new(); $control.AccessibleName='Connection permissions'; $control.DropDownStyle='DropDownList'
    $null=$control.Items.AddRange([object[]]@('View only','Control keyboard and mouse')); $control.SelectedIndex=0
    $control.SetBounds(24,108,512,30); $form.Controls.Add($control)
    $clipboard=[Windows.Forms.CheckBox]::new(); $clipboard.Text='Sync new text copies while connected (32 KiB max)'; $clipboard.AccessibleName='Share text clipboard for this connection'; $clipboard.SetBounds(24,152,512,30); $clipboard.Checked=$false; $form.Controls.Add($clipboard)
    $status=[Windows.Forms.Label]::new(); $status.SetBounds(24,200,512,94); $form.Controls.Add($status)
    $retry=[Windows.Forms.Button]::new(); $retry.Text='Check again'; $retry.SetBounds(24,316,130,32); $form.Controls.Add($retry)
    $details=[Windows.Forms.Button]::new(); $details.Text='Diagnostics'; $details.SetBounds(166,316,130,32); $form.Controls.Add($details)
    $connect=[Windows.Forms.Button]::new(); $connect.Text='Connect'; $connect.SetBounds(366,316,170,32); $form.Controls.Add($connect); $form.AcceptButton=$connect
    $refresh={
        if($state.Ready){
            if(-not $address.Modified){$address.Text=$state.Settings.host}
            if(-not $control.Tag){$control.SelectedIndex=if($state.Settings.control -eq 'interactive'){1}else{0}}
            $status.Text=if($state.Settings.schema -eq 2){'Ready. Your saved pairing is loaded; secure credentials are verified and renewed when connecting.'}else{'Ready. Your paired identity and connection settings are loaded automatically. IP and control mode are remembered when you connect.'}
            $status.ForeColor=[Drawing.Color]::DarkGreen
        } else {
            $status.Text=if(Test-Path -LiteralPath ($ConfigPath+'.recovery')){'Saved connection is unavailable. Choose Repair connection to restore this Windows account''s protected settings. Remote identity will still be verified.'}else{'First use: open LanPilot on the Mac and choose Pair a Windows computer. Enter its IP here, then compare the pairing information on both computers. No certificate details are needed.'}
            $status.ForeColor=[Drawing.Color]::Firebrick
        }
        $pairingBusy=$null -ne $state.PairingProcess -and -not $state.PairingProcess.HasExited
        $connect.Text=if($state.Ready){'Connect'}else{'Pair with Mac'}
        $connect.Enabled=(-not $pairingBusy) -and ($state.Ready -or (Test-Path -LiteralPath $pairingPath -PathType Leaf))
        $address.Enabled=-not $pairingBusy
        $clipboard.Enabled=$state.Ready -and $control.SelectedIndex -eq 1
        if(-not $clipboard.Enabled){$clipboard.Checked=$false}
        $retry.Text=if(-not $state.Ready -and (Test-Path -LiteralPath ($ConfigPath+'.recovery'))){'Repair connection'}else{'Check again'}
    }
    & $refresh
    $control.Add_SelectionChangeCommitted({$control.Tag='user-selected'; & $refresh})
    # Revalidate a failed startup without requiring an engineering repair step.
    # Stop polling once ready; preserve any IP/mode the user is editing.
    $reload=[Windows.Forms.Timer]::new(); $reload.Interval=2000
    $reload.Add_Tick({
        if($null -ne $state.PairingProcess -and $state.PairingProcess.HasExited){
            $pairingExit=$state.PairingProcess.ExitCode;$state.PairingProcess.Dispose();$state.PairingProcess=$null
            Read-SavedPairing; & $refresh
            if($pairingExit -ne 0 -and -not $state.Ready){$status.Text='Pairing did not finish. Open LanPilot on the Mac and retry; existing settings were preserved.'}
        }
        if(-not $state.Ready){Read-SavedPairing; & $refresh}
    })
    if(-not $CheckLayout){$reload.Start()}
    $retry.Add_Click({
        try {
            if(-not $state.Ready -and (Test-Path -LiteralPath ($ConfigPath+'.recovery'))){
                $null=Restore-LanPilotRecovery $ConfigPath
            }
            Read-SavedPairing; & $refresh
        } catch {$state.Error=$_.Exception.Message; $status.Text='Repair could not complete. No remote identity was trusted. See Diagnostics.'}
    })
    $details.Add_Click({
        [Windows.Forms.MessageBox]::Show(('Launcher: 2026.09.19.2 | PID: '+$PID+[Environment]::NewLine+
            'Pairing profile: '+$ConfigPath+[Environment]::NewLine+
            'File exists now: '+[IO.File]::Exists($ConfigPath)+[Environment]::NewLine+$state.Error),'LanPilot diagnostics') | Out-Null
    })
    $connect.Add_Click({
        try {
            if(-not $state.Ready){
                $target=$address.Text.Trim();$parsed=$null
                if(-not [Net.IPAddress]::TryParse($target,[ref]$parsed) -or $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){throw 'Enter a private LAN IPv4 address.'}
                $octets=$parsed.GetAddressBytes()
                if($parsed.ToString() -cne $target -or -not ($octets[0] -eq 10 -or $octets[0] -eq 127 -or ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or ($octets[0] -eq 192 -and $octets[1] -eq 168))){throw 'Enter a canonical private LAN IPv4 address.'}
                if(-not (Test-Path -LiteralPath $pairingPath -PathType Leaf)){throw 'Pairing component is missing. Install the current verified LanPilot package.'}
                $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$pairingPath;$start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.Arguments='--pair '+$target
                $state.PairingProcess=[Diagnostics.Process]::Start($start); & $refresh
                $status.Text='Compare the pairing information in the LanPilot pairing window and on your Mac.';return
            }
            $candidate=$state.Settings | ConvertTo-Json | ConvertFrom-Json
            $candidate.host=$address.Text.Trim()
            $candidate.control=if($control.SelectedIndex -eq 1){'interactive'}else{'view-only'}
            $null=Get-LanPilotTlsArguments $candidate
            $null=Test-LanPilotTlsReadiness $candidate
            if(-not (Test-Path -LiteralPath $ViewerPath -PathType Leaf)){throw 'Viewer is missing. Reinstall the verified LanPilot package.'}
            Save-LanPilotTlsSettings $ConfigPath $candidate
            Save-LanPilotRecovery $ConfigPath
            $state.Settings=$candidate
            $state.Clipboard=$clipboard.Checked -and $control.SelectedIndex -eq 1
            $viewerArguments=@(Get-LanPilotTlsArguments $candidate)
            if($state.Clipboard){$viewerArguments+=@('--clipboard','text')}
            $viewerArguments+=@('--startup-ui','launcher')
            $start=[Diagnostics.ProcessStartInfo]::new([IO.Path]::GetFullPath($ViewerPath))
            $start.UseShellExecute=$false;$start.CreateNoWindow=$true
            $start.WorkingDirectory=Split-Path -Parent ([IO.Path]::GetFullPath($ViewerPath))
            $start.Arguments=(@($viewerArguments|ForEach-Object {'"'+$_+'"'}) -join ' ')
            $state.ViewerProcess=[Diagnostics.Process]::Start($start)
            $connect.Enabled=$false;$address.Enabled=$false;$control.Enabled=$false;$clipboard.Enabled=$false
            $retry.Enabled=$false
            $status.ForeColor=[Drawing.Color]::DimGray
            $status.Text=('Connecting to '+$candidate.host+':'+$candidate.port+'...')
            $viewerPoll.Start()
        } catch {$status.Text='Cannot connect: '+$_.Exception.Message; $status.ForeColor=[Drawing.Color]::Firebrick}
    })
    $viewerPoll=[Windows.Forms.Timer]::new();$viewerPoll.Interval=100
    $viewerPoll.Add_Tick({
        $viewer=$state.ViewerProcess
        if($null -eq $viewer){return}
        $viewer.Refresh()
        if($viewer.HasExited){
            $code=$viewer.ExitCode;$viewer.Dispose();$state.ViewerProcess=$null;$viewerPoll.Stop()
            if($code -eq 0){$form.Close();return}
            & $refresh
            $address.Enabled=$true;$control.Enabled=$true;$retry.Enabled=$true
            $status.ForeColor=[Drawing.Color]::Firebrick
            $status.Text=('Cannot connect to Mac at '+$state.Settings.host+':'+$state.Settings.port+'. Check that the Mac is awake and LanPilot is installed and running. You can retry here; your pairing is kept.')
            if(-not $CheckViewerFailure){$form.Show()}
        }elseif($viewer.MainWindowHandle -ne [IntPtr]::Zero){
            # The Viewer remains hidden until both TLS channels are verified.
            # Application.Run keeps this connection form alive while hidden.
            $form.Hide()
        }
    })
    try {
        if($CheckViewerFailure){
            if(-not $CheckLayout){throw 'Viewer-failure fixture requires layout-only mode.'}
            $context=[Windows.Forms.ApplicationContext]::new()
            $fake=[Diagnostics.ProcessStartInfo]::new((Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'))
            $fake.UseShellExecute=$false;$fake.CreateNoWindow=$true
            $fake.Arguments='-NoProfile -NonInteractive -Command exit 7'
            $state.ViewerProcess=[Diagnostics.Process]::Start($fake)
            $deadline=[Windows.Forms.Timer]::new();$deadline.Interval=5000
            $deadline.Add_Tick({$context.ExitThread()})
            $viewerPoll.Add_Tick({if($null -eq $state.ViewerProcess){$context.ExitThread()}})
            try{$deadline.Start();$viewerPoll.Start();[Windows.Forms.Application]::Run($context)}
            finally{$deadline.Stop();$deadline.Dispose();$context.Dispose()}
            if($null -ne $state.ViewerProcess -or $form.Visible -or -not $connect.Enabled -or
                -not $status.Text.Contains(('Cannot connect to Mac at '+$state.Settings.host+':'+$state.Settings.port))){throw 'Failed Viewer did not return to a retryable connection state.'}
            Write-Output 'TLS viewer-failure workflow PASS: retry_enabled=1 endpoint_shown=1 UI=0 network=0'
            return
        }
        if($CheckEventLoop){
            $context=[Windows.Forms.ApplicationContext]::new()
            $probe=[Windows.Forms.Timer]::new(); $probe.Interval=25
            $probeState=@{Error='';Ticks=0}
            $probe.Add_Tick({
                try {
                    Read-SavedPairing; & $refresh
                    if(-not $state.Ready){throw $state.Error}
                    if(-not $connect.Enabled -or $address.Text -cne $state.Settings.host){throw 'Event-loop binding failed'}
                } catch {$probeState.Error=$_.Exception.ToString()}
                $probeState.Ticks++
                if($probeState.Error -or $probeState.Ticks -ge 3){$context.ExitThread()}
            })
            try {$probe.Start(); [Windows.Forms.Application]::Run($context)}
            finally {$probe.Stop(); $probe.Dispose(); $context.Dispose()}
            if($probeState.Error){throw $probeState.Error}
            Write-Output 'TLS event-loop PASS: real_callbacks=3 pairing_loaded=1 UI=0 network=0'
            return
        }
        if($CheckLayout){
            if($ExpectUnavailable){
                if($state.Ready -or $connect.Text -cne 'Pair with Mac'){throw 'Unavailable pairing allowed desktop connection'}
                if(@($form.Controls | Where-Object {$_ -is [Windows.Forms.TextBox]}).Count -ne 1){throw 'Unavailable pairing exposes trust entry'}
                Write-Output 'TLS unavailable layout PASS: desktop_admission=0 trust_fields=0; UI=0 network=0'
                return
            }
            if(-not $state.Ready){throw 'Expected existing valid pairing for layout check.'}
            if($address.Text -cne $state.Settings.host -or -not $connect.Enabled){throw 'Saved device not bound'}
            if(@($form.Controls | Where-Object {$_ -is [Windows.Forms.TextBox]}).Count -ne 1){throw 'User must not edit trust fields'}
            Write-Output 'TLS layout PASS: pairing_loaded=1 editable_text_fields=1 trust_fields=0; UI=0 network=0'
            return
        }
        [Windows.Forms.Application]::Run($form)
        return
    } finally {
        $viewerPoll.Stop();$viewerPoll.Dispose()
        if($null -ne $state.ViewerProcess){
            if(-not $state.ViewerProcess.HasExited){
                $null=$state.ViewerProcess.CloseMainWindow()
                if(-not $state.ViewerProcess.WaitForExit(2000)){$state.ViewerProcess.Kill();$state.ViewerProcess.WaitForExit()}
            }
            $state.ViewerProcess.Dispose();$state.ViewerProcess=$null
        }
        $reload.Stop();$reload.Dispose()
        if($null -ne $state.PairingProcess){if(-not $state.PairingProcess.HasExited){$null=$state.PairingProcess.CloseMainWindow()};$state.PairingProcess.Dispose();$state.PairingProcess=$null}
        $form.Dispose()
    }
}
$arguments=Get-LanPilotTlsArguments $state.Settings
if($state.Clipboard){$arguments+=@('--clipboard','text')}
$null=Test-LanPilotTlsReadiness $state.Settings
if(-not (Test-Path -LiteralPath $ViewerPath -PathType Leaf)){throw 'Viewer is missing. Reinstall the verified LanPilot package.'}
$start=[Diagnostics.ProcessStartInfo]::new([IO.Path]::GetFullPath($ViewerPath))
$start.UseShellExecute=$true; $start.WindowStyle=[Diagnostics.ProcessWindowStyle]::Normal
$start.WorkingDirectory=Split-Path -Parent ([IO.Path]::GetFullPath($ViewerPath))
$start.Arguments=(@($arguments | ForEach-Object {'"'+$_+'"'}) -join ' ')
$null=[Diagnostics.Process]::Start($start)
