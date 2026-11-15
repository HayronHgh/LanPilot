Set-StrictMode -Version Latest

function Assert-LanPilotMaintenancePath([string]$Path) {
    if($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path -match '[\x00-\x1f"]' -or $Path.Substring(2).Contains(':')){
        throw 'Maintenance requires an absolute local path.'
    }
    $full=[IO.Path]::GetFullPath($Path)
    $cursor=$full
    while($cursor){
        if((Test-Path -LiteralPath $cursor) -and
           ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){
            throw 'Linked maintenance path rejected.'
        }
        $cursor=[IO.Path]::GetDirectoryName($cursor)
    }
    return $full
}

function Invoke-LanPilotBoundedProcess {
    param([string]$Executable,[string[]]$Arguments,[ValidateRange(1,120)][int]$TimeoutSeconds=45)
    $null=Assert-LanPilotMaintenancePath $Executable
    $quoted=@(foreach($value in $Arguments){
        if($value -match '[\x00-\x1f]'){throw 'Invalid native argument.'}
        $escaped=[regex]::Replace($value,'(\\*)"','$1$1\"')
        $escaped=[regex]::Replace($escaped,'(\\+)$','$1$1')
        '"'+$escaped+'"'
    })
    $start=[Diagnostics.ProcessStartInfo]::new($Executable)
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
    $start.Arguments=$quoted -join ' '
    $process=[Diagnostics.Process]::Start($start)
    $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
    try {
        if(-not $process.WaitForExit($TimeoutSeconds*1000)){
            # Only terminate the process tree created by this invocation.
            $kill=[Diagnostics.ProcessStartInfo]::new((Join-Path $env:SystemRoot 'System32\taskkill.exe'))
            $kill.UseShellExecute=$false; $kill.CreateNoWindow=$true
            $kill.RedirectStandardOutput=$true; $kill.RedirectStandardError=$true
            $kill.Arguments='/PID '+$process.Id+' /T /F'
            $killer=[Diagnostics.Process]::Start($kill)
            try {$null=$killer.WaitForExit(3000)} finally {$killer.Dispose()}
            if(-not $process.HasExited){$process.Kill()}
            $null=$process.WaitForExit(3000)
            return [pscustomobject]@{ExitCode=124;Output='';Error='Maintenance deadline exceeded.'}
        }
        return [pscustomobject]@{ExitCode=$process.ExitCode;Output=$stdout.GetAwaiter().GetResult();Error=$stderr.GetAwaiter().GetResult()}
    } finally {$process.Dispose()}
}

function Assert-LanPilotPhysicalFile([string]$Path) {
    $full=Assert-LanPilotMaintenancePath $Path
    if(-not ('LanPilotMaintenanceNativePath' -as [type])){
        Add-Type -TypeDefinition @'
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class LanPilotMaintenanceNativePath {
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 public static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path, uint length, uint flags);
}
'@
    }
    $stream=[IO.File]::OpenRead($full)
    try {
        $actual=[Text.StringBuilder]::new(32768)
        $length=[LanPilotMaintenanceNativePath]::GetFinalPathNameByHandle($stream.SafeFileHandle,$actual,32768,0)
        if(-not $length -or $length -ge 32768){throw 'Cannot verify physical maintenance storage.'}
        if(-not $actual.ToString().Equals(('\\?\'+$full),[StringComparison]::OrdinalIgnoreCase)){
            throw 'Maintenance storage is redirected. Run the installed user task to access canonical identity storage.'
        }
    } finally {$stream.Dispose()}
}

function Get-LanPilotVerifiedExpiry($Config) {
    foreach($field in @('openSslPath','localRootDer','localCrlDer')){
        $file=Assert-LanPilotMaintenancePath ([string]$Config.$field)
        if(-not (Test-Path -LiteralPath $file -PathType Leaf)){throw "Missing maintenance input: $field"}
    }
    Assert-LanPilotPhysicalFile $Config.localRootDer
    Assert-LanPilotPhysicalFile $Config.localCrlDer
    $result=Invoke-LanPilotBoundedProcess $Config.openSslPath @('crl','-inform','DER','-in',$Config.localCrlDer,
        '-verify','-CAfile',$Config.localRootDer,'-noout','-lastupdate','-nextupdate') 8
    if($result.ExitCode -ne 0){throw 'CRL signature verification failed.'}
    $dates=@{}
    foreach($name in @('lastUpdate','nextUpdate')){
        $match=[regex]::Match($result.Output,'(?m)^'+$name+'=([^\r\n]+)')
        if(-not $match.Success){throw 'Signed CRL validity is missing.'}
        $value=($match.Groups[1].Value -replace '\s+',' ').Trim()
        $dates[$name]=[datetime]::ParseExact($value,"MMM d HH:mm:ss yyyy 'GMT'",[Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)
    }
    if($dates.nextUpdate -le $dates.lastUpdate){throw 'Signed CRL validity window is invalid.'}
    return [pscustomobject]@{IssuedUtc=$dates.lastUpdate;ExpiresUtc=$dates.nextUpdate}
}

function Get-LanPilotRenewalDecision {
    param([datetime]$NowUtc,[datetime]$ExpiresUtc,[datetime]$NextAttemptUtc=[datetime]::MinValue,[switch]$RequireReady)
    if($NowUtc -lt $ExpiresUtc.AddHours(-72)){return 'current'}
    if(-not $RequireReady -and $NowUtc -lt $NextAttemptUtc){return 'backoff'}
    return 'due'
}

function Get-LanPilotRetrySeconds([int]$FailureCount) {
    if($FailureCount -lt 1){throw 'Failure count must be positive.'}
    $seconds=@(60,300,1800,7200)[[Math]::Min($FailureCount-1,3)]
    return [Math]::Min(7200,$seconds+(Get-Random -Minimum 0 -Maximum ([int]($seconds/10)+1)))
}

function Save-LanPilotMaintenanceState([string]$Path,$Value) {
    $null=Assert-LanPilotMaintenancePath $Path
    $temp=$Path+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
    try {
        [IO.File]::WriteAllText($temp,($Value|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
        if(Test-Path -LiteralPath $Path){[IO.File]::Replace($temp,$Path,[NullString]::Value)}else{[IO.File]::Move($temp,$Path)}
    } finally {if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Force}}
}

Export-ModuleMember -Function Assert-LanPilotMaintenancePath,Invoke-LanPilotBoundedProcess,Get-LanPilotVerifiedExpiry,
    Get-LanPilotRenewalDecision,Get-LanPilotRetrySeconds,Save-LanPilotMaintenanceState,Assert-LanPilotPhysicalFile
