Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'TrustMaintenance.psm1') -Force

function Get-LanPilotInstallFileHash([string]$Path) {
    $file=Assert-LanPilotMaintenancePath $Path
    $stream=[IO.File]::OpenRead($file)
    try {
        $sha=[Security.Cryptography.SHA256]::Create()
        try{return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant()}
        finally{$sha.Dispose()}
    } finally{$stream.Dispose()}
}

function Get-LanPilotProgramFiles {
    # Program files only. No settings, certificates, private keys or logs.
    return @('rwn-viewer.exe','rwn-maintenance-launcher.exe',
        'Start-DesktopPreview.ps1','Start-LanPilot.ps1','Start-LanPilotTls.ps1',
        'TlsConnectionSettings.psm1','TrustMaintenance.psm1','ProductInstall.psm1',
        'Maintain-LanPilotTrust.ps1','Invoke-LanPilotTrustMaintenance.ps1',
        'Register-LanPilotMaintenance.ps1','Update-LanPilotTrustBundle.ps1',
        'Uninstall-DesktopPreview.ps1')
}

function Get-LanPilotProgramHashes([string]$Directory) {
    $root=Assert-LanPilotMaintenancePath $Directory
    $hashes=[ordered]@{}
    foreach($name in Get-LanPilotProgramFiles){
        $path=Assert-LanPilotMaintenancePath (Join-Path $root $name)
        $file=Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if($file.PSIsContainer -or $file.Length -lt 1 -or $file.Length -gt 268435456){
            throw ('Invalid program package member: '+$name)
        }
        if($file.Extension -in @('.ps1','.psm1') -and $file.Length -gt 1048576){throw 'Program script exceeds package bound.'}
        $hashes[$name]=Get-LanPilotInstallFileHash $path
    }
    return $hashes
}

function Test-LanPilotSamePrograms($Left,$Right) {
    foreach($name in Get-LanPilotProgramFiles){
        $leftHash=if($Left -is [Collections.IDictionary]){$Left[$name]}else{$Left.$name}
        $rightHash=if($Right -is [Collections.IDictionary]){$Right[$name]}else{$Right.$name}
        if($leftHash -cne $rightHash){return $false}
    }
    return $true
}

function Assert-LanPilotTransactionPath([string]$Path,[string]$Parent,[string]$Prefix) {
    $full=Assert-LanPilotMaintenancePath $Path
    if(-not [IO.Path]::GetDirectoryName($full).Equals($Parent,[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($full) -notmatch ('^'+[regex]::Escape($Prefix)+'[0-9a-f]{32}$')){
        throw 'Untrusted program transaction path.'
    }
    return $full
}

function Move-LanPilotFailedStage([string]$Stage,[string]$Maintenance) {
    if(Test-Path -LiteralPath $Stage){
        $destination=Join-Path $Maintenance ('program-quarantine-'+[Guid]::NewGuid().ToString('N'))
        [IO.Directory]::Move($Stage,$destination)
    }
}

function Repair-LanPilotProgramTransaction([string]$Journal,[string]$InstallRoot,[string]$Maintenance) {
    if(-not (Test-Path -LiteralPath $Journal -PathType Leaf)){return}
    if((Get-Item -LiteralPath $Journal).Length -gt 8192){throw 'Program transaction journal exceeds bound.'}
    $state=Get-Content -LiteralPath $Journal -Raw -Encoding UTF8|ConvertFrom-Json
    if(@(Compare-Object @('schema','phase','installRoot','stage','previous') @($state.PSObject.Properties.Name)).Count -or
       $state.schema -ne 1 -or $state.phase -cnotin @('prepared','activated','committed','rolled_back') -or
       -not ([string]$state.installRoot).Equals($InstallRoot,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Untrusted program transaction journal.'
    }
    $parent=[IO.Path]::GetDirectoryName($InstallRoot)
    $stage=Assert-LanPilotTransactionPath $state.stage $parent '.LanPilot-stage-'
    $previous=Assert-LanPilotTransactionPath $state.previous $Maintenance 'program-previous-'
    if($state.phase -in @('committed','rolled_back')){return}
    if(Test-Path -LiteralPath $previous -PathType Container){
        if(Test-Path -LiteralPath $InstallRoot){
            $failed=Join-Path $parent ('.LanPilot-stage-'+[Guid]::NewGuid().ToString('N'))
            [IO.Directory]::Move($InstallRoot,$failed)
            Move-LanPilotFailedStage $failed $Maintenance
        }
        [IO.Directory]::Move($previous,$InstallRoot)
    } elseif($state.phase -eq 'activated') {
        # An interrupted first install is not a proven activation. Quarantine it.
        if(Test-Path -LiteralPath $InstallRoot){
            $failed=Join-Path $parent ('.LanPilot-stage-'+[Guid]::NewGuid().ToString('N'))
            [IO.Directory]::Move($InstallRoot,$failed)
            Move-LanPilotFailedStage $failed $Maintenance
        }
    }
    Move-LanPilotFailedStage $stage $Maintenance
    $state.phase='rolled_back';Save-LanPilotMaintenanceState $Journal $state
}

function Get-LanPilotInstallPaths([string]$InstallRoot,[string]$DataRoot) {
    $install=Assert-LanPilotMaintenancePath $InstallRoot
    $data=Assert-LanPilotMaintenancePath $DataRoot
    if($data.Length -le 3){throw 'Persistent state may not use a drive root.'}
    $data=$data.TrimEnd([char[]]@('\','/'))
    if([IO.Path]::GetFileName($install) -cne 'LanPilot' -or
       $data.Equals($install,[StringComparison]::OrdinalIgnoreCase) -or
       $data.StartsWith($install+'\',[StringComparison]::OrdinalIgnoreCase) -or
       $install.StartsWith($data+'\',[StringComparison]::OrdinalIgnoreCase) -or
       -not [IO.Path]::GetPathRoot($install).Equals([IO.Path]::GetPathRoot($data),[StringComparison]::OrdinalIgnoreCase)){
        throw 'Program and persistent state require separate canonical roots on the same volume.'
    }
    return [pscustomobject]@{Install=$install;Data=$data;
        Runtime=(Assert-LanPilotMaintenancePath (Join-Path $install 'runtime'));
        Maintenance=(Assert-LanPilotMaintenancePath (Join-Path $data 'maintenance'))}
}

function Open-LanPilotUpdateLock($Paths) {
    # Kernel ownership survives deletion/recreation of the state directory and
    # cannot be bypassed by selecting another DataRoot for the same program.
    if(-not ('LanPilotInstallOperationLease' -as [type])){
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Threading;
using System.Collections.Generic;
public sealed class LanPilotInstallOperationLease : IDisposable {
 private static readonly object gate = new object();
 private static readonly HashSet<string> held = new HashSet<string>(StringComparer.Ordinal);
 private readonly string name;
 private Mutex mutex;
 private FileStream dataLock;
 private bool owned, disposed;
 private LanPilotInstallOperationLease(string value) { name = value; }
 public static LanPilotInstallOperationLease Acquire(string name) {
  lock(gate) { if(!held.Add(name)) throw new InvalidOperationException("LanPilot installation is busy."); }
  var lease = new LanPilotInstallOperationLease(name);
  try {
   lease.mutex = new Mutex(false, name);
   try { lease.owned = lease.mutex.WaitOne(0); }
   catch(AbandonedMutexException) { lease.owned = true; }
   if(!lease.owned) throw new InvalidOperationException("LanPilot installation is busy.");
   return lease;
  } catch { lease.Dispose(); throw; }
 }
 public void AttachDataLock(FileStream value) { dataLock = value; }
 public void ReleaseDataLock() { if(dataLock != null) { dataLock.Dispose(); dataLock = null; } }
 public void Dispose() {
  if(disposed) return;
  disposed = true;
  try { ReleaseDataLock(); }
  finally {
   try { if(owned) mutex.ReleaseMutex(); }
   finally {
    if(mutex != null) mutex.Dispose();
    lock(gate) { held.Remove(name); }
   }
  }
 }
}
'@
    }
    $sha=[Security.Cryptography.SHA256]::Create()
    try {$rootHash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Paths.Install.ToUpperInvariant())))).Replace('-','')}
    finally {$sha.Dispose()}
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $operation=[LanPilotInstallOperationLease]::Acquire(('Global\LanPilot.Install.'+$sid+'.'+$rootHash))
    $lock=$null
    try {
    $maintenance=$Paths.Maintenance
    $null=New-Item -ItemType Directory -Path $maintenance -Force
    try {$lock=[IO.File]::Open((Join-Path $maintenance 'program-update.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
    catch {throw 'LanPilot is updating. Wait for the active operation to finish; no lock file was removed.'}
    try {
        # An unpackaged child may still inherit development-host MSIX storage
        # redirection. Validate the actual open handle before program mutation.
        if(-not ('LanPilotProgramInstallContext' -as [type])){
            Add-Type -TypeDefinition @'
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class LanPilotProgramInstallContext {
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 public static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder path, uint count, uint flags);
}
'@
        }
        $physical=[Text.StringBuilder]::new(32768)
        $length=[LanPilotProgramInstallContext]::GetFinalPathNameByHandle($lock.SafeFileHandle,$physical,32768,0)
        if(-not $length -or $length -ge 32768 -or
           -not $physical.ToString().Equals(('\\?\'+(Join-Path $maintenance 'program-update.lock')),[StringComparison]::OrdinalIgnoreCase)){
            throw 'Install state is redirected. Run the installer from Windows Explorer. Programs were not changed.'
        }
        $operation.AttachDataLock($lock)
        return $operation
    } catch {$lock.Dispose();throw}
    } catch {if($lock){$lock.Dispose()};$operation.Dispose();throw}
}

function Get-LanPilotBootstrapFiles {
    return @('LanPilot.exe','Start-LanPilotBootstrap.ps1','ProductInstall.psm1','TrustMaintenance.psm1','Uninstall-DesktopPreview.ps1')
}

function Assert-LanPilotHashMap($Map) {
    if($null -eq $Map){throw 'Runtime hash inventory is missing.'}
    $names=if($Map -is [Collections.IDictionary]){@($Map.Keys)}else{@($Map.PSObject.Properties.Name)}
    if(@(Compare-Object @(Get-LanPilotProgramFiles) $names).Count){throw 'Unexpected runtime hash inventory.'}
    foreach($name in Get-LanPilotProgramFiles){
        $hash=if($Map -is [Collections.IDictionary]){$Map[$name]}else{$Map.$name}
        if($hash -isnot [string] -or $hash -cnotmatch '^[0-9a-f]{64}$'){throw 'Invalid runtime hash.'}
    }
}

function Initialize-LanPilotBootstrap([string]$Source,$Paths) {
    $directory=Assert-LanPilotMaintenancePath (Join-Path $Paths.Install 'bootstrap')
    $marker=Join-Path $directory 'bootstrap-state.json'
    if(Test-Path -LiteralPath $marker){Test-LanPilotBootstrap $Paths;return}
    $null=New-Item -ItemType Directory -Path $directory -Force
    $hashes=[ordered]@{}
    foreach($name in Get-LanPilotBootstrapFiles){
        $from=Assert-LanPilotMaintenancePath (Join-Path $Source $name)
        $to=if($name -eq 'LanPilot.exe'){Join-Path $Paths.Install $name}else{Join-Path $directory $name}
        $hash=Get-LanPilotInstallFileHash $from
        if(Test-Path -LiteralPath $to){
            if((Get-LanPilotInstallFileHash $to) -cne $hash){throw 'Incomplete bootstrap is from another package. Explicit bootstrap repair is required.'}
        } else {
            $temporary=$to+'.'+[Guid]::NewGuid().ToString('N')+'.new'
            Copy-Item -LiteralPath $from -Destination $temporary
            if((Get-LanPilotInstallFileHash $temporary) -cne $hash){throw 'Bootstrap staging hash mismatch.'}
            [IO.File]::Move($temporary,$to)
        }
        $hashes[$name]=$hash
    }
    Save-LanPilotMaintenanceState $marker ([ordered]@{schema=1;runtimeSchema=2;files=$hashes})
}

function Test-LanPilotBootstrap($Paths) {
    $directory=Assert-LanPilotMaintenancePath (Join-Path $Paths.Install 'bootstrap')
    $marker=Assert-LanPilotMaintenancePath (Join-Path $directory 'bootstrap-state.json')
    if((Get-Item -LiteralPath $marker).Length -gt 8192){throw 'Bootstrap marker exceeds bound.'}
    $state=Get-Content -LiteralPath $marker -Raw -Encoding UTF8|ConvertFrom-Json
    if($state.schema -ne 1 -or $state.runtimeSchema -ne 2 -or
       @(Compare-Object @(Get-LanPilotBootstrapFiles) @($state.files.PSObject.Properties.Name)).Count){throw 'Bootstrap contract is unsupported.'}
    foreach($name in Get-LanPilotBootstrapFiles){
        $file=if($name -eq 'LanPilot.exe'){Join-Path $Paths.Install $name}else{Join-Path $directory $name}
        $hash=$state.files.$name
        if($hash -isnot [string] -or $hash -cnotmatch '^[0-9a-f]{64}$' -or (Get-LanPilotInstallFileHash $file) -cne $hash){throw 'Stable bootstrap integrity check failed.'}
    }
}

function Read-LanPilotRuntimeJournal($Paths) {
    $journal=Assert-LanPilotMaintenancePath (Join-Path $Paths.Maintenance 'program-transaction.json')
    if(-not (Test-Path -LiteralPath $journal -PathType Leaf)){throw 'LanPilot runtime has not completed installation.'}
    if((Get-Item -LiteralPath $journal).Length -gt 8192){throw 'Runtime journal exceeds bound.'}
    $state=Get-Content -LiteralPath $journal -Raw -Encoding UTF8|ConvertFrom-Json
    if(@(Compare-Object @('schema','phase','installRoot','stage','previous','beforeHashes','afterHashes') @($state.PSObject.Properties.Name)).Count -or
       $state.schema -ne 2 -or $state.phase -cnotin @('prepared','activated','committed','rolled_back') -or
       -not ([string]$state.installRoot).Equals($Paths.Install,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Untrusted runtime journal.'
    }
    $null=Assert-LanPilotTransactionPath $state.stage $Paths.Install '.LanPilot-stage-'
    $null=Assert-LanPilotTransactionPath $state.previous $Paths.Maintenance 'program-previous-'
    if($null -ne $state.beforeHashes){Assert-LanPilotHashMap $state.beforeHashes}
    Assert-LanPilotHashMap $state.afterHashes
    return $state
}

function Assert-LanPilotRuntimeHashes([string]$Directory,$Hashes) {
    if($null -eq $Hashes -or -not (Test-LanPilotSamePrograms (Get-LanPilotProgramHashes $Directory) $Hashes)){
        throw 'Runtime integrity check failed. No unverified program was launched.'
    }
}

function Repair-LanPilotRuntimeTransaction($Paths) {
    $state=Read-LanPilotRuntimeJournal $Paths
    if($state.phase -eq 'committed'){Assert-LanPilotRuntimeHashes $Paths.Runtime $state.afterHashes;return $state}
    if($state.phase -eq 'rolled_back'){
        if($null -ne $state.beforeHashes){Assert-LanPilotRuntimeHashes $Paths.Runtime $state.beforeHashes}
        return $state
    }
    if(Test-Path -LiteralPath $state.previous -PathType Container){
        Assert-LanPilotRuntimeHashes $state.previous $state.beforeHashes
        if(Test-Path -LiteralPath $Paths.Runtime){Move-LanPilotFailedStage $Paths.Runtime $Paths.Maintenance}
        [IO.Directory]::Move($state.previous,$Paths.Runtime)
    } elseif($null -ne $state.beforeHashes){
        Assert-LanPilotRuntimeHashes $Paths.Runtime $state.beforeHashes
    } elseif(Test-Path -LiteralPath $Paths.Runtime){
        Move-LanPilotFailedStage $Paths.Runtime $Paths.Maintenance
    }
    Move-LanPilotFailedStage $state.stage $Paths.Maintenance
    $state.phase='rolled_back'
    Save-LanPilotMaintenanceState (Join-Path $Paths.Maintenance 'program-transaction.json') $state
    return $state
}

function Open-LanPilotInstalledRuntime([string]$InstallRoot,[string]$DataRoot) {
    $paths=Get-LanPilotInstallPaths $InstallRoot $DataRoot
    $lock=Open-LanPilotUpdateLock $paths
    try {
        Repair-LanPilotRemovalTransaction $paths
        Test-LanPilotBootstrap $paths
        $state=Repair-LanPilotRuntimeTransaction $paths
        if($state.phase -eq 'rolled_back' -and $null -eq $state.beforeHashes){throw 'No committed LanPilot runtime is available. Complete installation before launching.'}
        if(-not (Test-Path -LiteralPath $paths.Runtime -PathType Container)){throw 'No committed LanPilot runtime is available.'}
        $lease=[IO.File]::Open((Join-Path $paths.Maintenance 'runtime-in-use.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite)
        return [pscustomobject]@{Directory=$paths.Runtime;Lease=$lease;Recovered=($state.phase -eq 'rolled_back')}
    } finally {$lock.Dispose()}
}

function Assert-LanPilotRemovalTree([string]$Directory) {
    $root=Assert-LanPilotMaintenancePath $Directory
    if(-not (Test-Path -LiteralPath $root)){return}
    if(-not (Test-Path -LiteralPath $root -PathType Container)){throw 'Expected an owned removal directory.'}
    $pending=[Collections.Generic.Queue[string]]::new();$pending.Enqueue($root)
    $count=0
    while($pending.Count){
        foreach($entry in Get-ChildItem -LiteralPath $pending.Dequeue() -Force -ErrorAction Stop){
            if(++$count -gt 20000 -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)){
                throw 'Removal tree requires explicit review; no files were removed.'
            }
            if($entry.PSIsContainer){$pending.Enqueue($entry.FullName)}
        }
    }
}

function Read-LanPilotRemovalTransaction($Paths) {
    $file=Assert-LanPilotMaintenancePath (Join-Path $Paths.Maintenance 'program-removal.json')
    if(-not (Test-Path -LiteralPath $file -PathType Leaf)){return $null}
    if((Get-Item -LiteralPath $file).Length -gt 4096){throw 'Removal journal exceeds bound.'}
    $state=Get-Content -LiteralPath $file -Raw -Encoding UTF8|ConvertFrom-Json
    if(@(Compare-Object @('schema','phase','installRoot','retired','hadInstall') @($state.PSObject.Properties.Name)).Count -or
       ($state.schema -isnot [int] -and $state.schema -isnot [long]) -or $state.schema -ne 1 -or
       $state.hadInstall -isnot [bool] -or $state.phase -cnotin @('prepared','removed','rolled_back') -or
       -not ([string]$state.installRoot).Equals($Paths.Install,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Untrusted removal journal.'
    }
    $null=Assert-LanPilotTransactionPath $state.retired $Paths.Maintenance 'program-removed-'
    return $state
}

function Get-LanPilotRemovedJournal($Paths,$State) {
    $id=[IO.Path]::GetFileName([string]$State.retired).Substring('program-removed-'.Length)
    return (Assert-LanPilotMaintenancePath (Join-Path $Paths.Maintenance ('program-transaction-uninstalled-'+$id+'.json')))
}

function Repair-LanPilotRemovalTransaction($Paths) {
    $state=Read-LanPilotRemovalTransaction $Paths
    if($null -eq $state -or $state.phase -ne 'prepared'){return}
    $retired=Test-Path -LiteralPath $state.retired -PathType Container
    $installed=Test-Path -LiteralPath $Paths.Install -PathType Container
    if($retired){
        if($installed){throw 'Removal recovery found conflicting program directories.'}
        Assert-LanPilotRemovalTree $state.retired
        [IO.Directory]::Move($state.retired,$Paths.Install)
    } elseif(-not $installed -and $state.hadInstall){throw 'Removal recovery cannot find the previous programs.'}
    $archived=Get-LanPilotRemovedJournal $Paths $state
    $journal=Join-Path $Paths.Maintenance 'program-transaction.json'
    if(Test-Path -LiteralPath $archived -PathType Leaf){
        if(Test-Path -LiteralPath $journal){throw 'Removal recovery found conflicting runtime journals.'}
        [IO.File]::Move($archived,$journal)
    }
    $state.phase='rolled_back'
    Save-LanPilotMaintenanceState (Join-Path $Paths.Maintenance 'program-removal.json') $state
}

function Invoke-LanPilotProgramRemoval {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$InstallRoot,
          [Parameter(Mandatory)][string]$DataRoot,
          [scriptblock]$PrepareBindings={},[scriptblock]$Deactivate={},[scriptblock]$RestoreBindings={},
          [switch]$RemoveConfiguration,[switch]$CheckOnly)
    $paths=Get-LanPilotInstallPaths $InstallRoot $DataRoot
    $lock=Open-LanPilotUpdateLock $paths
    $lease=$null
    try {
        if($CheckOnly){
            $pending=Read-LanPilotRemovalTransaction $paths
            if($null -ne $pending -and $pending.phase -eq 'prepared'){throw 'Removal is pending; run a verified installer to repair it.'}
        }else{Repair-LanPilotRemovalTransaction $paths}
        try {$lease=[IO.File]::Open((Join-Path $paths.Maintenance 'runtime-in-use.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
        catch {throw 'Close LanPilot before removing it. Its active launch was not stopped.'}
        foreach($process in @(Get-Process -Name 'LanPilot','rwn-viewer','rwn-maintenance-launcher' -ErrorAction SilentlyContinue)){
            if(-not $process.Path -or $process.Path.StartsWith($paths.Install+'\',[StringComparison]::OrdinalIgnoreCase)){
                throw 'Close LanPilot before removing it. Its running process was not stopped.'
            }
        }
        Assert-LanPilotRemovalTree $paths.Install
        if($RemoveConfiguration){Assert-LanPilotRemovalTree $paths.Data}
        & $PrepareBindings
        if($CheckOnly){return [pscustomobject]@{Status='checked';ConfigurationRemoved=$false;CleanupPending=$false}}
        $id=[Guid]::NewGuid().ToString('N')
        $retired=Assert-LanPilotTransactionPath (Join-Path $paths.Maintenance ('program-removed-'+$id)) $paths.Maintenance 'program-removed-'
        $marker=Join-Path $paths.Maintenance 'program-removal.json'
        $state=[ordered]@{schema=1;phase='prepared';installRoot=$paths.Install;retired=$retired;
            hadInstall=[bool](Test-Path -LiteralPath $paths.Install -PathType Container)}
        Save-LanPilotMaintenanceState $marker $state
        $bindingsStarted=$false
        try {
            if(Test-Path -LiteralPath $paths.Install){[IO.Directory]::Move($paths.Install,$retired)}
            $bindingsStarted=$true
            & $Deactivate
            $journal=Assert-LanPilotMaintenancePath (Join-Path $paths.Maintenance 'program-transaction.json')
            if(Test-Path -LiteralPath $journal -PathType Leaf){[IO.File]::Move($journal,(Get-LanPilotRemovedJournal $paths $state))}
            $state.phase='removed';Save-LanPilotMaintenanceState $marker $state
        } catch {
            # Only fixed, validated local paths are recovered. A subsequent
            # installer also repairs pending removal before touching programs.
            Repair-LanPilotRemovalTransaction $paths
            if($bindingsStarted){& $RestoreBindings}
            throw
        }
        $cleanupPending=$false
        if(Test-Path -LiteralPath $retired){
            Assert-LanPilotRemovalTree $retired
            try {Remove-Item -LiteralPath $retired -Recurse -Force -ErrorAction Stop}
            catch {$cleanupPending=$true}
        }
        if($RemoveConfiguration){
            # The per-installation mutex stays owned while state-file handles
            # close. Another launch/install cannot recreate this directory
            # during deletion, even with a different DataRoot.
            $lease.Dispose();$lease=$null;$lock.ReleaseDataLock()
            Assert-LanPilotRemovalTree $paths.Data
            Remove-Item -LiteralPath $paths.Data -Recurse -Force -ErrorAction Stop
        }
        return [pscustomobject]@{Status='removed';ConfigurationRemoved=[bool]$RemoveConfiguration;CleanupPending=$cleanupPending}
    } finally {if($lease){$lease.Dispose()};$lock.Dispose()}
}

function Invoke-LanPilotProgramUpdate {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SourceDirectory,
          [Parameter(Mandatory)][string]$InstallRoot,
          [Parameter(Mandatory)][string]$DataRoot,
          [scriptblock]$Activate={})
    $source=Assert-LanPilotMaintenancePath $SourceDirectory
    $paths=Get-LanPilotInstallPaths $InstallRoot $DataRoot
    if($source.Equals($paths.Install,[StringComparison]::OrdinalIgnoreCase) -or
       $source.StartsWith($paths.Install+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Update package must be outside the active installation.'}
    $expected=Get-LanPilotProgramHashes $source
    foreach($name in Get-LanPilotBootstrapFiles){
        $file=Get-Item -LiteralPath (Assert-LanPilotMaintenancePath (Join-Path $source $name)) -ErrorAction Stop
        if($file.PSIsContainer -or $file.Length -lt 1 -or $file.Length -gt 16777216){throw 'Incomplete bootstrap package.'}
    }
    $lock=Open-LanPilotUpdateLock $paths
    $lease=$null
    try {
        Repair-LanPilotRemovalTransaction $paths
        $journal=Join-Path $paths.Maintenance 'program-transaction.json'
        $marker=Join-Path $paths.Install 'bootstrap\bootstrap-state.json'
        if((Test-Path -LiteralPath $journal) -and -not (Test-Path -LiteralPath $marker)){
            if((Get-Item -LiteralPath $journal).Length -gt 8192){throw 'Program transaction journal exceeds bound.'}
            $legacy=Get-Content -Raw -LiteralPath $journal|ConvertFrom-Json
            if($legacy.schema -eq 1){
                Repair-LanPilotProgramTransaction $journal $paths.Install $paths.Maintenance
                [IO.File]::Move($journal,(Join-Path $paths.Maintenance ('program-transaction-v1-'+[Guid]::NewGuid().ToString('N')+'.json')))
            }
        }
        $null=New-Item -ItemType Directory -Path $paths.Install -Force
        Initialize-LanPilotBootstrap $source $paths
        if(Test-Path -LiteralPath $journal){$null=Repair-LanPilotRuntimeTransaction $paths}
        if(Test-Path -LiteralPath $paths.Runtime -PathType Container){
            if(Test-LanPilotSamePrograms $expected (Get-LanPilotProgramHashes $paths.Runtime)){
                # Program bytes stay unchanged, but a repeated installation must
                # still reconcile the stable launch/maintenance bindings.
                & $Activate $paths.Runtime
                return [pscustomobject]@{Status='unchanged';ProgramFiles=$expected.Count;StateReplaced=$false;Runtime=$paths.Runtime}
            }
        }
        try {$lease=[IO.File]::Open((Join-Path $paths.Maintenance 'runtime-in-use.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
        catch {throw 'Close LanPilot before updating. Its active launch was not stopped.'}
        foreach($process in @(Get-Process -Name 'rwn-viewer' -ErrorAction SilentlyContinue)){
            if(-not $process.Path -or $process.Path.Equals((Join-Path $paths.Runtime 'rwn-viewer.exe'),[StringComparison]::OrdinalIgnoreCase) -or
                $process.Path.Equals((Join-Path $paths.Install 'rwn-viewer.exe'),[StringComparison]::OrdinalIgnoreCase)){
                throw 'Close LanPilot before updating. Its running connection was not stopped.'
            }
        }
        $before=if(Test-Path -LiteralPath $paths.Runtime){Get-LanPilotProgramHashes $paths.Runtime}else{$null}
        $id=[Guid]::NewGuid().ToString('N')
        $stage=Join-Path $paths.Install ('.LanPilot-stage-'+$id)
        $previous=Join-Path $paths.Maintenance ('program-previous-'+$id)
        $null=New-Item -ItemType Directory -Path $stage
        try {
            foreach($name in Get-LanPilotProgramFiles){Copy-Item -LiteralPath (Join-Path $source $name) -Destination (Join-Path $stage $name)}
            Assert-LanPilotRuntimeHashes $stage $expected
        } catch {Move-LanPilotFailedStage $stage $paths.Maintenance;throw}
        $state=[ordered]@{schema=2;phase='prepared';installRoot=$paths.Install;stage=$stage;previous=$previous;beforeHashes=$before;afterHashes=$expected}
        Save-LanPilotMaintenanceState $journal $state
        try {
            if(Test-Path -LiteralPath $paths.Runtime){[IO.Directory]::Move($paths.Runtime,$previous)}
            $state.phase='activated';Save-LanPilotMaintenanceState $journal $state
            [IO.Directory]::Move($stage,$paths.Runtime)
            Assert-LanPilotRuntimeHashes $paths.Runtime $expected
            & $Activate $paths.Runtime
            $state.phase='committed';Save-LanPilotMaintenanceState $journal $state
            return [pscustomobject]@{Status='updated';ProgramFiles=$expected.Count;StateReplaced=$false;Runtime=$paths.Runtime}
        } catch {$null=Repair-LanPilotRuntimeTransaction $paths;throw}
    } finally {if($lease){$lease.Dispose()};$lock.Dispose()}
}

Export-ModuleMember -Function Get-LanPilotProgramFiles,Get-LanPilotProgramHashes,Get-LanPilotInstallFileHash,Invoke-LanPilotProgramUpdate,Open-LanPilotInstalledRuntime,Invoke-LanPilotProgramRemoval
