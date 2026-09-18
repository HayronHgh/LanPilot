[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $env:LOCALAPPDATA 'RemoteWorkspaceNode\desktop.json'),
    [ValidateSet('h264', 'snapshot-only', 'raw-rect-experimental')]
    [string]$Hybrid,
    [ValidateSet('baseline', 'low-latency')]
    [string]$EncoderMode = 'low-latency',
    [switch]$Trace,
    [switch]$ConnectImmediately
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-AbsoluteWindowsPath([string]$Path) {
    return $Path -match '^(?:[A-Za-z]:[\\/]|\\\\[^\\]+\\[^\\]+[\\/])'
}

function Save-ConnectionSettings([string]$Path, $Settings) {
    $parent = Split-Path -Parent $Path
    $null = New-Item -ItemType Directory -Path $parent -Force
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllText($temporary, ($Settings | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
        if (Test-Path -LiteralPath $Path) {
            # Windows PowerShell converts $null to an empty string for this
            # string parameter. NullString preserves a real CLR null backup path.
            [IO.File]::Replace($temporary, $Path, [NullString]::Value)
        } else {
            [IO.File]::Move($temporary, $Path)
        }
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
    }
}

if (-not (Test-AbsoluteWindowsPath $ConfigPath)) {
    throw 'ConfigPath must be absolute.'
}
$config = [pscustomobject]@{
    schema = 1; host = ''; sshKey = ''; remoteAgent = ''; hybrid = 'h264'; control = 'view'
}
$loadError = ''
if (Test-Path -LiteralPath $ConfigPath -PathType Leaf) {
    try {
        if ((Get-Item -LiteralPath $ConfigPath).Length -gt 65536) {
            throw 'Connection settings exceed 64 KiB.'
        }
        $saved = Get-Content -Raw -LiteralPath $ConfigPath -Encoding UTF8 | ConvertFrom-Json
        foreach ($name in @('host', 'sshKey', 'remoteAgent', 'hybrid', 'control')) {
            if ($saved.PSObject.Properties.Name -contains $name) { $config.$name = $saved.$name }
        }
        # Existing preview profiles were interactive before this option existed.
        if ($saved.PSObject.Properties.Name -notcontains 'control') { $config.control = 'interactive' }
    } catch { $loadError = 'Saved settings could not be read. Please enter the connection details again.' }
}

function Assert-ConnectionSettings($Settings) {
    if ($Settings.host -notmatch '^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+$') {
        throw 'Enter a Mac account and a host name or IPv4 address.'
    }
    if (-not (Test-AbsoluteWindowsPath $Settings.sshKey) -or
        -not (Test-Path -LiteralPath $Settings.sshKey -PathType Leaf)) {
        throw 'Choose an existing SSH private key file. No key will be created or copied.'
    }
    if ($Settings.remoteAgent -notmatch '^/[A-Za-z0-9/_.-]+$' -or $Settings.remoteAgent.Contains('..')) {
        throw 'Agent path must be an absolute Mac path without spaces or shell characters.'
    }
    if ($Settings.control -notin @('view', 'interactive')) { throw 'Select a valid control mode.' }
}

if (-not $ConnectImmediately) {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [Windows.Forms.Application]::EnableVisualStyles()
    $form = New-Object Windows.Forms.Form
    $form.Text = 'Remote Workspace - Connect to Mac'
    $form.ClientSize = New-Object Drawing.Size(640, 620)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.AutoScaleMode = 'Dpi'
    $form.Font = New-Object Drawing.Font('Segoe UI', 10)
    $form.BackColor = [Drawing.Color]::FromArgb(245, 247, 250)

    function Add-Label([string]$Text, [int]$X, [int]$Y, [int]$Width, [int]$Height) {
        $label = New-Object Windows.Forms.Label
        $label.Text = $Text
        $label.SetBounds($X, $Y, $Width, $Height)
        $form.Controls.Add($label)
        return $label
    }
    function Add-Field([string]$Label, [int]$Y, [string]$Value, [int]$Width = 576) {
        $null = Add-Label $Label 32 $Y 576 24
        $field = New-Object Windows.Forms.TextBox
        $field.SetBounds(32, ($Y + 26), $Width, 30)
        $field.Text = $Value
        $field.MaxLength = 2048
        $field.AccessibleName = $Label
        $form.Controls.Add($field)
        return $field
    }
    $heading = Add-Label 'Connect to your Mac' 32 24 576 38
    $heading.Font = New-Object Drawing.Font('Segoe UI', 21, [Drawing.FontStyle]::Bold)
    $subtitle = Add-Label 'Your desktop, keyboard and mouse over an encrypted LAN connection.' 32 68 576 40
    $subtitle.ForeColor = [Drawing.Color]::FromArgb(80, 92, 110)
    $parts = ([string]$config.host).Split('@')
    $hostValue = ''; $userValue = ''
    if ($parts.Length -eq 2) { $userValue = $parts[0]; $hostValue = $parts[1] }
    $hostField = Add-Field 'Mac address or hostname' 112 $hostValue
    $userField = Add-Field 'Mac account' 180 $userValue
    $keyField = Add-Field 'SSH private key' 248 ([string]$config.sshKey) 466
    $browse = New-Object Windows.Forms.Button
    $browse.Text = 'Browse...'
    $browse.SetBounds(510, 272, 98, 31)
    $form.Controls.Add($browse)
    $browse.Add_Click({
        $picker = New-Object Windows.Forms.OpenFileDialog
        $picker.Title = 'Choose an existing SSH private key'
        $picker.Filter = 'All files (*.*)|*.*'
        $picker.CheckFileExists = $true
        try { if ($picker.ShowDialog($form) -eq 'OK') { $keyField.Text = $picker.FileName } }
        finally { $picker.Dispose() }
    })
    $agentField = Add-Field 'Agent location on the Mac' 316 ([string]$config.remoteAgent)
    $null = Add-Label 'Connection mode' 32 384 200 24
    $mode = New-Object Windows.Forms.ComboBox
    $mode.SetBounds(32, 410, 300, 32)
    $mode.DropDownStyle = 'DropDownList'
    $mode.AccessibleName = 'Connection mode'
    $null = $mode.Items.Add('View only')
    $null = $mode.Items.Add('Control keyboard and mouse')
    $mode.SelectedIndex = if ($config.control -eq 'interactive') { 1 } else { 0 }
    $form.Controls.Add($mode)
    $remember = New-Object Windows.Forms.CheckBox
    $remember.Text = 'Remember this connection'
    $remember.Checked = $true
    $remember.SetBounds(350, 410, 258, 30)
    $form.Controls.Add($remember)
    $hint = Add-Label "Enable Remote Login, Screen Recording and Accessibility on the Mac.`nThe SSH key and host must already be trusted on this Windows account." 32 453 576 44
    $hint.ForeColor = [Drawing.Color]::FromArgb(80, 92, 110)
    $feedback = Add-Label $loadError 32 505 576 48
    $feedback.ForeColor = [Drawing.Color]::FromArgb(180, 42, 42)
    $cancel = New-Object Windows.Forms.Button
    $cancel.Text = 'Cancel'
    $cancel.SetBounds(350, 560, 100, 38)
    $cancel.DialogResult = 'Cancel'
    $form.Controls.Add($cancel)
    $connect = New-Object Windows.Forms.Button
    $connect.Text = 'Connect to Mac'
    $connect.SetBounds(464, 560, 144, 38)
    $connect.BackColor = [Drawing.Color]::FromArgb(38, 93, 204)
    $connect.ForeColor = [Drawing.Color]::White
    $connect.FlatStyle = 'Flat'
    $form.Controls.Add($connect)
    $form.AcceptButton = $connect
    $form.CancelButton = $cancel
    $userField.Add_Leave({
        if ([string]::IsNullOrWhiteSpace($agentField.Text) -and $userField.Text -match '^[A-Za-z0-9._-]+$') {
            $agentField.Text = '/Users/' + $userField.Text + '/.local/libexec/remoteworkspacenode/rwn-desktop-agent'
        }
    })
    $connect.Add_Click({
        try {
            $config.host = $userField.Text.Trim() + '@' + $hostField.Text.Trim()
            $config.sshKey = $keyField.Text.Trim()
            $config.remoteAgent = $agentField.Text.Trim()
            $config.control = if ($mode.SelectedIndex -eq 1) { 'interactive' } else { 'view' }
            Assert-ConnectionSettings $config
            if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'rwn-viewer.exe') -PathType Leaf)) {
                throw 'Viewer is missing. Reinstall Remote Workspace before connecting.'
            }
            if ($remember.Checked) {
                Save-ConnectionSettings $ConfigPath $config
            }
            $form.DialogResult = 'OK'
            $form.Close()
        } catch { $feedback.Text = $_.Exception.Message }
    })
    try { $result = $form.ShowDialog() } finally { $form.Dispose() }
    if ($result -ne 'OK') { exit 0 }
} elseif ($loadError) { throw $loadError }

Assert-ConnectionSettings $config
foreach ($name in @('host', 'sshKey', 'remoteAgent')) {
    $value = $config.$name
    if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value) -or
        $value.IndexOfAny([char[]]"`r`n`0") -ge 0) {
        throw "Desktop configuration field '$name' is invalid."
    }
}

if ($config.host -notmatch '^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+$') {
    throw 'Desktop configuration host must use user@host form.'
}
if (-not (Test-AbsoluteWindowsPath ([string]$config.sshKey)) -or
    -not (Test-Path -LiteralPath ([string]$config.sshKey) -PathType Leaf)) {
    throw 'Desktop configuration sshKey must be an existing absolute file.'
}
if (-not ([string]$config.remoteAgent).StartsWith('/') -or
    ([string]$config.remoteAgent).Contains('..')) {
    throw 'Desktop configuration remoteAgent must be an absolute canonical POSIX path.'
}

$viewer = Join-Path $PSScriptRoot 'rwn-viewer.exe'
if (-not (Test-Path -LiteralPath $viewer -PathType Leaf)) {
    throw "Viewer is missing from the installed directory: $viewer"
}

$selectedHybrid = if ($PSBoundParameters.ContainsKey('Hybrid')) {
    $Hybrid
} elseif ($config.hybrid -is [string]) {
    [string]$config.hybrid
} else {
    'h264'
}
if ($selectedHybrid -notin @('h264', 'snapshot-only', 'raw-rect-experimental')) {
    throw 'Desktop configuration hybrid mode is invalid.'
}

$arguments = @(
    [string]$config.host,
    [string]$config.sshKey,
    [string]$config.remoteAgent,
    '--profile', 'lan-quality',
    '--control', [string]$config.control,
    '--present', 'balanced',
    '--scale', 'fit',
    '--encoder', $EncoderMode,
    '--hybrid', $selectedHybrid
)

if ($Trace) {
    $traceRoot = Join-Path $env:LOCALAPPDATA 'RemoteWorkspaceNode\traces'
    New-Item -ItemType Directory -Path $traceRoot -Force | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $tracePath = Join-Path $traceRoot "desktop-$selectedHybrid-$stamp.jsonl"
    $arguments += @('--trace', $tracePath)
    Write-Host "Trace: $tracePath"
}

& $viewer @arguments
# Windows PowerShell does not populate LASTEXITCODE when a GUI-subsystem
# executable detaches successfully. Missing means the viewer was launched;
# command-not-found and other launch failures are already terminating errors.
$nativeExit = Get-Variable -Name LASTEXITCODE -ErrorAction SilentlyContinue
if ($null -ne $nativeExit) {
    exit [int]$nativeExit.Value
}
exit 0
