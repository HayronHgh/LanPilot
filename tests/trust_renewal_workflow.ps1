param([string]$PackagingDirectory=(Join-Path $PSScriptRoot '..\packaging\windows'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

$script=Join-Path ([IO.Path]::GetFullPath($PackagingDirectory)) 'Maintain-LanPilotTrust.ps1'
$hostPath=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('lanpilot-trust-renewal-'+[Guid]::NewGuid().ToString('N'))
$maintenance=Join-Path $testRoot 'maintenance'
$profile=Join-Path $maintenance 'trust-renewal.json'

function Write-Profile([bool]$Enabled,[datetime]$Refresh,[datetime]$Expires) {
    $value=[ordered]@{
        schema=1
        enabled=$Enabled
        nextRefreshUtc=$Refresh.ToUniversalTime().ToString('o')
        expiresUtc=$Expires.ToUniversalTime().ToString('o')
    } | ConvertTo-Json
    [IO.File]::WriteAllText($profile,$value,[Text.UTF8Encoding]::new($false))
}

function Invoke-Evaluation([datetime]$Now) {
    $start=[Diagnostics.ProcessStartInfo]::new($hostPath)
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
    $start.Arguments='-NoProfile -ExecutionPolicy Bypass -File "'+$script+'" -DataRoot "'+$testRoot+
        '" -ConfigPath "'+$profile+'" -EvaluateOnly -NowUtc "'+$Now.ToString('o')+'"'
    $process=[Diagnostics.Process]::Start($start)
    try {
        $output=$process.StandardOutput.ReadToEnd(); $errorText=$process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if($process.ExitCode){throw $errorText}
        return $output
    } finally {$process.Dispose()}
}

try {
    $null=New-Item -ItemType Directory -Path $maintenance
    $now=[datetime]'2030-01-02T03:04:05Z'
    Write-Profile $true $now.AddHours(4) $now.AddDays(7)
    if((Invoke-Evaluation $now) -notmatch 'trust_renewal=current'){throw 'Future refresh window was not treated as current.'}

    Write-Profile $true $now.AddMinutes(-1) $now.AddDays(1)
    if((Invoke-Evaluation $now) -notmatch 'trust_renewal=due'){throw 'Elapsed refresh window was not treated as due.'}

    Write-Profile $false $now.AddMinutes(-1) $now.AddDays(1)
    if((Invoke-Evaluation $now) -notmatch 'trust_renewal=disabled'){throw 'Disabled renewal profile was not honored.'}

    Write-Profile $true $now.AddDays(2) $now.AddDays(1)
    $rejected=$false
    try {$null=Invoke-Evaluation $now} catch {$rejected=$true}
    if(-not $rejected){throw 'Invalid validity window was accepted.'}

    Write-Output 'trust_renewal_workflow=PASS current=1 due=1 disabled=1 invalid_window_rejected=1 network=0 crypto=0'
} finally {
    if(Test-Path -LiteralPath $testRoot){Remove-Item -LiteralPath $testRoot -Recurse -Force}
}
