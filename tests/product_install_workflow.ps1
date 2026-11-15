param([Parameter(Mandatory)][string]$Launcher,
      [string]$PackagingDirectory=(Join-Path $PSScriptRoot '..\packaging\windows'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$PackagingDirectory=[IO.Path]::GetFullPath($PackagingDirectory)
Import-Module (Join-Path $PackagingDirectory 'ProductInstall.psm1') -Force
Import-Module (Join-Path $PackagingDirectory 'TrustMaintenance.psm1')
$temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$root=Join-Path $temp ('lanpilot-install-'+[Guid]::NewGuid().ToString('N'))
$source=Join-Path $root 'package with spaces'
$install=Join-Path $root 'Programs with spaces\LanPilot'
$runtime=Join-Path $install 'runtime'
$data=Join-Path $root 'state with spaces'
$child=$null
function Check([bool]$Value,[string]$Reason){if(-not $Value){throw $Reason}}
function Reject([scriptblock]$Operation){$rejected=$false;try{& $Operation|Out-Null}catch{$rejected=$true};Check $rejected 'Unsafe update was accepted'}
function Same-Hash([string]$Path,[string]$Expected){Check ((Get-LanPilotInstallFileHash $Path) -ceq $Expected) ('Unexpected file change: '+$Path)}
function Launch([string[]]$Arguments,[bool]$Success=$true){
    $result=Invoke-LanPilotBoundedProcess (Join-Path $install 'LanPilot.exe') $Arguments 20
    Check (($result.ExitCode -eq 0) -eq $Success) ('Native launch result: '+$result.ExitCode+' '+$result.Error)
}
function Journal($State){[IO.File]::WriteAllText((Join-Path $data 'maintenance\program-transaction.json'),($State|ConvertTo-Json -Depth 6))}
try {
    $start=[IO.File]::ReadAllText((Join-Path $PackagingDirectory 'Start-LanPilot.ps1'))
    Check ($start.Contains('$Connection=''configure''')) 'Normal startup opens version chooser'
    $installer=[IO.File]::ReadAllText((Join-Path $PackagingDirectory 'Install-DesktopPreview.ps1'))
    Check ($installer.Contains('$Transport = ''tls''')) 'New installation defaults to legacy SSH'
    Check ($installer.Contains('$shortcut.TargetPath = Join-Path $InstallRoot ''LanPilot.exe''')) 'Shortcut bypasses stable bootstrap'
    $null=New-Item -ItemType Directory -Path $source
    $null=New-Item -ItemType Directory -Path (Join-Path $data 'connections'),(Join-Path $data 'identity')
    $profile=Join-Path $data 'connections\default.json';$identity=Join-Path $data 'identity\opaque-protected-identity'
    [IO.File]::WriteAllText($profile,'{"paired":"preserve","control":"view-only"}')
    [IO.File]::WriteAllBytes($identity,[byte[]]@(1,3,5,7))
    $profileHash=Get-LanPilotInstallFileHash $profile;$identityHash=Get-LanPilotInstallFileHash $identity
    foreach($name in Get-LanPilotProgramFiles){[IO.File]::WriteAllText((Join-Path $source $name),('version-one:'+ $name))}
    foreach($name in @('ProductInstall.psm1','TrustMaintenance.psm1','Start-LanPilotBootstrap.ps1')){
        Copy-Item -LiteralPath (Join-Path $PackagingDirectory $name) -Destination (Join-Path $source $name) -Force
    }
    Copy-Item -LiteralPath $Launcher -Destination (Join-Path $source 'LanPilot.exe')
    $bytes=[IO.File]::ReadAllBytes($Launcher);$pe=[BitConverter]::ToInt32($bytes,0x3c)
    Check ([BitConverter]::ToUInt16($bytes,$pe+24+68) -eq 2) 'Product launcher must use the GUI subsystem'
    # These runtime fixtures never use UI, network, tasks, registry, keys or clipboard.
    [IO.File]::WriteAllText((Join-Path $source 'Start-LanPilot.ps1'),@'
param([string]$DataRoot,[string]$Connection)
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class FixtureConsole{[DllImport("kernel32.dll")]public static extern IntPtr GetConsoleWindow();}'
Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class FixtureStartup{[StructLayout(LayoutKind.Sequential)]public struct Info{public uint cb;public IntPtr reserved,desktop,title;public uint x,y,width,height,charsX,charsY,fill,flags;public ushort show,reservedSize;public IntPtr reservedBytes,input,output,error;}[DllImport("kernel32.dll",EntryPoint="GetStartupInfoW")]public static extern void GetStartupInfo(out Info info);}'
$startup=[FixtureStartup+Info]::new();[FixtureStartup]::GetStartupInfo([ref]$startup)
$receipt=@{version=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'rwn-viewer.exe'));connection=$Connection;console=[FixtureConsole]::GetConsoleWindow().ToInt64();startupFlags=$startup.flags}
[IO.File]::WriteAllText((Join-Path $DataRoot 'maintenance\normal-launch.json'),($receipt|ConvertTo-Json))
'@)
    [IO.File]::WriteAllText((Join-Path $source 'Invoke-LanPilotTrustMaintenance.ps1'),@'
param([string]$DataRoot)
Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class FixtureConsole{[DllImport("kernel32.dll")]public static extern IntPtr GetConsoleWindow();}'
if(Test-Path -LiteralPath (Join-Path $DataRoot 'maintenance\hold')){
    $info=[Diagnostics.ProcessStartInfo]::new((Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'))
    $info.Arguments='-NoProfile -NonInteractive -Command Start-Sleep -Seconds 30'
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $nested=[Diagnostics.Process]::Start($info)
    [IO.File]::WriteAllText((Join-Path $DataRoot 'maintenance\child-pids'),([string]$PID+','+[string]$nested.Id))
    Start-Sleep -Seconds 30
}
[IO.File]::WriteAllText((Join-Path $DataRoot 'maintenance\maintenance-launch.json'),('{"console":'+[FixtureConsole]::GetConsoleWindow().ToInt64()+'}'))
'@)
    $result=Invoke-LanPilotProgramUpdate $source $install $data
    Check ($result.Status -eq 'updated' -and $result.ProgramFiles -eq 13 -and -not $result.StateReplaced) 'First install failed'
    $viewer=Join-Path $runtime 'rwn-viewer.exe';$firstHash=Get-LanPilotInstallFileHash $viewer
    $owner=& (Get-Module ProductInstall) {
        param($program,$state)
        Open-LanPilotUpdateLock (Get-LanPilotInstallPaths $program $state)
    } $install $data
    try {
        # One program installation must not be concurrently mutated through
        # another settings root (including a same-thread nested operation).
        Reject {Invoke-LanPilotProgramUpdate $source $install (Join-Path $root 'alternate state')}
        $owner.ReleaseDataLock()
        Reject {Invoke-LanPilotProgramUpdate $source $install (Join-Path $root 'alternate state')}
    } finally {$owner.Dispose()}
    $anchor=Get-LanPilotInstallFileHash (Join-Path $install 'LanPilot.exe')
    $bootstrap=Get-LanPilotInstallFileHash (Join-Path $install 'bootstrap\ProductInstall.psm1')
    $firstTime=(Get-Item -LiteralPath $viewer).LastWriteTimeUtc
    Check ((Invoke-LanPilotProgramUpdate $source $install $data).Status -eq 'unchanged' -and (Get-Item -LiteralPath $viewer).LastWriteTimeUtc -eq $firstTime) 'Identical package rewrote installation'
    $binding=Join-Path $data 'maintenance\activation-binding'
    $result=Invoke-LanPilotProgramUpdate $source $install $data -Activate {
        param($active)
        Import-Module (Join-Path $active 'TrustMaintenance.psm1') -Force
        [IO.File]::WriteAllText($binding,$active)
    }
    Check ((Test-Path -LiteralPath $binding) -and [IO.File]::ReadAllText($binding) -eq $runtime) 'Identical package skipped activation/binding repair'
    Check ((Get-Item -LiteralPath $viewer).LastWriteTimeUtc -eq $firstTime) 'Binding repair rewrote runtime'
    Reject {Invoke-LanPilotProgramUpdate $source $install $data -Activate {throw 'Synthetic binding repair failure'}}
    Check ((Get-Item -LiteralPath $viewer).LastWriteTimeUtc -eq $firstTime) 'Failed binding repair rewrote runtime'
    Same-Hash $profile $profileHash;Same-Hash $identity $identityHash
    Launch @('--data-root',$data)
    $receipt=Get-Content -Raw -LiteralPath (Join-Path $data 'maintenance\normal-launch.json')|ConvertFrom-Json
    Check ($receipt.version -eq 'version-one:rwn-viewer.exe' -and $receipt.console -eq 0 -and $receipt.connection -eq 'configure') 'Ordinary native launch failed or opened console'
    Check (($receipt.startupFlags -band 1) -eq 0) 'Ordinary GUI launch inherits STARTF_USESHOWWINDOW and hides its first window'
    Launch @('--maintenance','--data-root',$data)
    $receipt=Get-Content -Raw -LiteralPath (Join-Path $data 'maintenance\maintenance-launch.json')|ConvertFrom-Json
    Check ($receipt.console -eq 0) 'Maintenance opened console'
    [IO.File]::WriteAllText((Join-Path $data 'maintenance\hold'),'1')
    $info=[Diagnostics.ProcessStartInfo]::new((Join-Path $install 'LanPilot.exe'))
    $info.Arguments='--maintenance --data-root "'+$data+'"'
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $child=[Diagnostics.Process]::Start($info)
    $pidsFile=Join-Path $data 'maintenance\child-pids';$deadline=[Diagnostics.Stopwatch]::StartNew()
    while(-not (Test-Path -LiteralPath $pidsFile) -and -not $child.HasExited -and $deadline.Elapsed.TotalSeconds -lt 10){Start-Sleep -Milliseconds 20}
    Check (Test-Path -LiteralPath $pidsFile) 'Maintenance cleanup fixture did not start'
    $children=@((Get-Content -Raw -LiteralPath $pidsFile).Split(',')|ForEach-Object{[Diagnostics.Process]::GetProcessById([int]$_)})
    try {
        $child.Kill();$child.WaitForExit()
        foreach($process in $children){Check ($process.WaitForExit(3000)) 'Product maintenance termination orphaned a process'}
    } finally {foreach($process in $children){$process.Dispose()}}
    $child.Dispose();$child=$null
    Remove-Item -LiteralPath (Join-Path $data 'maintenance\hold')
    [IO.File]::WriteAllText((Join-Path $source 'rwn-viewer.exe'),'version-two')
    Reject {Invoke-LanPilotProgramUpdate $source $install $data -Activate {throw 'Synthetic activation failure'}}
    Same-Hash $viewer $firstHash
    $journal=Join-Path $data 'maintenance\program-transaction.json'
    Check ((Get-Content -Raw -LiteralPath $journal|ConvertFrom-Json).phase -eq 'rolled_back') 'Rollback not recorded'
    Check ((Invoke-LanPilotProgramUpdate $source $install $data).Status -eq 'updated') 'Upgrade failed'
    $currentHash=Get-LanPilotInstallFileHash $viewer;$inventory=Get-LanPilotProgramHashes $runtime
    $lease=Open-LanPilotInstalledRuntime $install $data
    try {
        Check ((Invoke-LanPilotProgramUpdate $source $install $data).Status -eq 'unchanged') 'Identical package failed while leased'
        [IO.File]::WriteAllText((Join-Path $source 'rwn-viewer.exe'),'version-three')
        Reject {Invoke-LanPilotProgramUpdate $source $install $data}
    } finally {$lease.Lease.Dispose()}
    $required=Join-Path $source 'TrustMaintenance.psm1';Remove-Item -LiteralPath $required
    Reject {Invoke-LanPilotProgramUpdate $source $install $data};Same-Hash $viewer $currentHash
    Copy-Item -LiteralPath (Join-Path $PackagingDirectory 'TrustMaintenance.psm1') -Destination $required
    Reject {Invoke-LanPilotProgramUpdate $source (Join-Path $root 'Programs\AnotherCopy') $data}
    Reject {Invoke-LanPilotProgramUpdate $source $install (Join-Path $install 'identity')}
    $lock=[IO.File]::Open((Join-Path $data 'maintenance\program-update.lock'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {Reject {Invoke-LanPilotProgramUpdate $source $install $data}}finally{$lock.Dispose()}
    # Kill our isolated updater after activation. Recover using ORDINARY startup.
    $killScript=Join-Path $root 'interrupt-update.ps1'
    [IO.File]::WriteAllText($killScript,@'
param([string]$Package,[string]$Install,[string]$Data)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $Package 'ProductInstall.psm1') -Force
Invoke-LanPilotProgramUpdate $Package $Install $Data -Activate {
    [IO.File]::WriteAllText((Join-Path $Data 'maintenance\interrupt-ready'),'ready')
    Start-Sleep -Seconds 30
}
'@)
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $info.Arguments='-NoProfile -ExecutionPolicy Bypass -File "'+$killScript+'" -Package "'+$source+'" -Install "'+$install+'" -Data "'+$data+'"'
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $child=[Diagnostics.Process]::Start($info)
    $ready=Join-Path $data 'maintenance\interrupt-ready';$deadline=[Diagnostics.Stopwatch]::StartNew()
    while(-not (Test-Path -LiteralPath $ready) -and -not $child.HasExited -and $deadline.Elapsed.TotalSeconds -lt 15){Start-Sleep -Milliseconds 20}
    if(-not (Test-Path -LiteralPath $ready)){
        if(-not $child.HasExited){$child.Kill();$child.WaitForExit()}
        throw ('Updater did not reach interruption point: '+$child.StandardError.ReadToEnd())
    }
    $child.Kill();$child.WaitForExit();$child.Dispose();$child=$null
    Check ([IO.File]::ReadAllText($viewer) -eq 'version-three') 'Interruption was not after activation'
    Launch @('--data-root',$data)
    $receipt=Get-Content -Raw -LiteralPath (Join-Path $data 'maintenance\normal-launch.json')|ConvertFrom-Json
    Check ($receipt.version -eq 'version-two' -and $receipt.console -eq 0) 'Normal launch failed to restore and launch prior runtime'
    Same-Hash $viewer $currentHash
    Check ((Get-Content -Raw -LiteralPath $journal|ConvertFrom-Json).phase -eq 'rolled_back') 'Startup recovery not recorded'
    foreach($phase in @('prepared','activated')){
        $id=[Guid]::NewGuid().ToString('N');$previous=Join-Path $data ('maintenance\program-previous-'+$id)
        $stage=Join-Path $install ('.LanPilot-stage-'+$id)
        [IO.Directory]::Move($runtime,$previous);$null=New-Item -ItemType Directory -Path $stage
        if($phase -eq 'activated'){
            $null=New-Item -ItemType Directory -Path $runtime
            [IO.File]::WriteAllText((Join-Path $runtime 'Start-LanPilot.ps1'),"throw 'MUST NOT EXECUTE'")
        }
        Journal ([ordered]@{schema=2;phase=$phase;installRoot=$install;stage=$stage;previous=$previous;beforeHashes=$inventory;afterHashes=(Get-LanPilotProgramHashes $source)})
        Launch @('--data-root',$data);Same-Hash $viewer $currentHash
        Check (-not (Test-Path -LiteralPath $stage)) 'Interrupted stage remained active'
    }
    Same-Hash (Join-Path $install 'LanPilot.exe') $anchor
    Same-Hash (Join-Path $install 'bootstrap\ProductInstall.psm1') $bootstrap
    Same-Hash $profile $profileHash;Same-Hash $identity $identityHash
    $freshInstall=Join-Path $root 'freshPrograms\LanPilot';$freshData=Join-Path $root 'freshState'
    Reject {Invoke-LanPilotProgramUpdate $source $freshInstall $freshData -Activate {throw 'Synthetic first-install failure'}}
    Check ((Test-Path -LiteralPath (Join-Path $freshInstall 'LanPilot.exe')) -and -not (Test-Path -LiteralPath (Join-Path $freshInstall 'runtime'))) 'Failed first install left active payload or lost bootstrap'
    $null=New-Item -ItemType Directory -Path (Join-Path $freshInstall 'runtime')
    Reject {$opened=Open-LanPilotInstalledRuntime $freshInstall $freshData;$opened.Lease.Dispose()}
    [IO.Directory]::Delete((Join-Path $freshInstall 'runtime'))
    Check ((Invoke-LanPilotProgramUpdate $source $freshInstall $freshData).Status -eq 'updated') 'First-install retry failed'
    $good=[IO.File]::ReadAllText($journal)
    $bad=$good|ConvertFrom-Json;$bad.stage=$root;Journal $bad
    Launch @('--check-startup','--data-root',$data) $false
    Reject {Invoke-LanPilotProgramUpdate $source $install $data};[IO.File]::WriteAllText($journal,$good)
    $bad=$good|ConvertFrom-Json;$bad.beforeHashes.'rwn-viewer.exe'='not-a-hash';Journal $bad
    Launch @('--check-startup','--data-root',$data) $false;[IO.File]::WriteAllText($journal,$good)
    $bootstrapScript=Join-Path $install 'bootstrap\Start-LanPilotBootstrap.ps1'
    [IO.File]::AppendAllText($bootstrapScript,"# integrity mutation")
    Launch @('--check-startup','--data-root',$data) $false
    Copy-Item -LiteralPath (Join-Path $source 'Start-LanPilotBootstrap.ps1') -Destination $bootstrapScript -Force
    [IO.File]::Move($bootstrapScript,($bootstrapScript+'.omitted'))
    Launch @('--check-startup','--data-root',$data) $false
    [IO.File]::Move(($bootstrapScript+'.omitted'),$bootstrapScript)
    Launch @('--check-startup','--data-root',$data)
    Launch @('--check-startup','--data-root','relative') $false
    Launch @('--check-startup','--maintenance','--data-root',$data) $false
    Launch @('--check-startup','--script','unexpected','--data-root',$data) $false
    Same-Hash $viewer $currentHash;Same-Hash $profile $profileHash;Same-Hash $identity $identityHash
    $bindings=Join-Path $data 'maintenance\fixture-bindings'
    [IO.File]::WriteAllText($bindings,'registered')
    $prepared=@{Calls=0}
    $result=Invoke-LanPilotProgramRemoval $install $data -CheckOnly -PrepareBindings {$prepared.Calls++} -Deactivate {throw 'Read-only removal probe invoked deletion'}
    Check ($result.Status -eq 'checked' -and $prepared.Calls -eq 1) 'Removal preflight skipped binding validation'
    Same-Hash $viewer $currentHash
    $outside=Join-Path $root 'unrelated fixture data'
    $null=New-Item -ItemType Directory -Path $outside
    [IO.File]::WriteAllText((Join-Path $outside 'preserve'),'keep')
    foreach($parent in @($install,$data)){
        $junction=Join-Path $parent 'foreign-link'
        $null=New-Item -ItemType Junction -Path $junction -Target $outside
        try {Reject {Invoke-LanPilotProgramRemoval $install $data -RemoveConfiguration}}
        finally {[IO.Directory]::Delete($junction)}
        Check ([IO.File]::ReadAllText((Join-Path $outside 'preserve')) -eq 'keep') 'Removal followed a linked directory'
        Same-Hash $viewer $currentHash
    }
    $owner=& (Get-Module ProductInstall) {
        param($program,$state)
        Open-LanPilotUpdateLock (Get-LanPilotInstallPaths $program $state)
    } $install $data
    try {Reject {Invoke-LanPilotProgramRemoval $install $data -Deactivate {[IO.File]::WriteAllText($bindings,'removed')}}}
    finally {$owner.Dispose()}
    Check ([IO.File]::ReadAllText($bindings) -eq 'registered') 'Busy removal touched registration bindings'
    $lease=Open-LanPilotInstalledRuntime $install $data
    try {Reject {Invoke-LanPilotProgramRemoval $install $data}}finally{$lease.Lease.Dispose()}
    Same-Hash $viewer $currentHash
    Reject {Invoke-LanPilotProgramRemoval $install $data -Deactivate {
        [IO.File]::WriteAllText($bindings,'removed');throw 'Synthetic binding removal failure'
    } -RestoreBindings {[IO.File]::WriteAllText($bindings,'registered')}}
    Check ([IO.File]::ReadAllText($bindings) -eq 'registered') 'Failed removal did not restore bindings'
    Same-Hash $viewer $currentHash;Same-Hash $profile $profileHash;Same-Hash $identity $identityHash
    $removal=Join-Path $data 'maintenance\program-removal.json'
    $goodRemoval=[IO.File]::ReadAllText($removal)
    $badRemoval=$goodRemoval|ConvertFrom-Json;$badRemoval.retired=$root
    [IO.File]::WriteAllText($removal,($badRemoval|ConvertTo-Json))
    Reject {Invoke-LanPilotProgramRemoval $install $data}
    [IO.File]::WriteAllText($removal,$goodRemoval)
    Same-Hash $viewer $currentHash
    $result=Invoke-LanPilotProgramRemoval $install $data -Deactivate {[IO.File]::WriteAllText($bindings,'removed')}
    Check ($result.Status -eq 'removed' -and -not $result.ConfigurationRemoved -and -not (Test-Path -LiteralPath $install)) 'Default removal left active programs'
    Same-Hash $profile $profileHash;Same-Hash $identity $identityHash
    Check (-not (Test-Path -LiteralPath $journal)) 'Uninstall left an active runtime journal'
    Check ((Invoke-LanPilotProgramUpdate $source $install $data).Status -eq 'updated') 'Reinstall with retained identity failed'
    Launch @('--check-startup','--data-root',$data)
    Same-Hash $profile $profileHash;Same-Hash $identity $identityHash
    $result=Invoke-LanPilotProgramRemoval $install $data -RemoveConfiguration
    Check ($result.ConfigurationRemoved -and -not (Test-Path -LiteralPath $data) -and -not (Test-Path -LiteralPath $install)) 'Explicit fixture state removal failed'
    # Terminate a remover after program retirement but before binding commit.
    # The next verified installer must recover programs/journal before compare.
    $removeScript=Join-Path $root 'interrupt-removal.ps1'
    [IO.File]::WriteAllText($removeScript,@'
param([string]$Package,[string]$Install,[string]$Data)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $Package 'ProductInstall.psm1') -Force
Invoke-LanPilotProgramRemoval $Install $Data -Deactivate {
    [IO.File]::WriteAllText((Join-Path $Data 'maintenance\removal-ready'),'ready')
    Start-Sleep -Seconds 30
}
'@)
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $info.Arguments='-NoProfile -ExecutionPolicy Bypass -File "'+$removeScript+'" -Package "'+$source+'" -Install "'+$freshInstall+'" -Data "'+$freshData+'"'
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $child=[Diagnostics.Process]::Start($info)
    $ready=Join-Path $freshData 'maintenance\removal-ready';$deadline=[Diagnostics.Stopwatch]::StartNew()
    while(-not (Test-Path -LiteralPath $ready) -and -not $child.HasExited -and $deadline.Elapsed.TotalSeconds -lt 15){Start-Sleep -Milliseconds 20}
    if(-not (Test-Path -LiteralPath $ready)){
        if(-not $child.HasExited){$child.Kill();$child.WaitForExit()}
        throw ('Remover did not reach interruption point: '+$child.StandardError.ReadToEnd())
    }
    Reject {Invoke-LanPilotProgramUpdate $source $freshInstall (Join-Path $root 'competing state')}
    $child.Kill();$child.WaitForExit();$child.Dispose();$child=$null
    Check (-not (Test-Path -LiteralPath $freshInstall)) 'Removal interruption was not after retirement'
    Reject {Invoke-LanPilotProgramRemoval $freshInstall $freshData -CheckOnly}
    Check (-not (Test-Path -LiteralPath $freshInstall)) 'Read-only preflight repaired pending removal'
    Check ((Invoke-LanPilotProgramUpdate $source $freshInstall $freshData).Status -eq 'unchanged') 'Interrupted removal did not recover known programs'
    $recovered=Get-Content -Raw -LiteralPath (Join-Path $freshData 'maintenance\program-removal.json')|ConvertFrom-Json
    Check ($recovered.phase -eq 'rolled_back') 'Interrupted removal recovery was not recorded'
    Write-Output 'product_install_workflow=PASS first_install=1 identical_noop=1 upgrade=1 activation_rollback=1 killed_updater_normal_startup_recovery=1 damaged_candidate_recovery=1 first_install_quarantine=1 stable_bootstrap=1 runtime_lease=1 windowless_startup=1 windowless_maintenance=1 orphaned_maintenance_children=0 journal_path_guard=1 installation_owner=1 removal_serialized=1 removal_rollback=1 removal_recovery=1 default_state_preserved=1 retained_state_reinstall=1 explicit_fixture_state_removal=1 actual_install=0'
} finally {
    if($child){if(-not $child.HasExited){$child.Kill();$child.WaitForExit()};$child.Dispose()}
    $resolved=[IO.Path]::GetFullPath($root)
    if(-not $resolved.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -notmatch '^lanpilot-install-[0-9a-f]{32}$'){throw 'Refusing unexpected fixture cleanup target.'}
    if(Test-Path -LiteralPath $resolved){Remove-Item -LiteralPath $resolved -Recurse -Force}
}
