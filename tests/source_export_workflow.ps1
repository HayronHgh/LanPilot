param([string]$PackagingDirectory=(Join-Path $PSScriptRoot '..\packaging'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PackagingDirectory 'SourceExport.psm1') -Force
function Check([bool]$Value,[string]$Reason){if(-not $Value){throw $Reason}}
function Hash([string]$Path){
    $sha=[Security.Cryptography.SHA256]::Create()
    $stream=[IO.File]::OpenRead($Path)
    try{return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant()}
    finally{$stream.Dispose();$sha.Dispose()}
}
function Reject([scriptblock]$Action){$rejected=$false;try{& $Action|Out-Null}catch{$rejected=$true};Check $rejected 'Unsafe source export accepted'}
$root=Join-Path ([IO.Path]::GetTempPath()) ('lanpilot-source-'+[guid]::NewGuid().ToString('N'))
$source=Join-Path $root 'source'
$catalog=Get-LanPilotSourceCatalog
$utf8=[Text.UTF8Encoding]::new($false)
function Put([string]$Relative,[string]$Text){
    $path=Join-Path $source $Relative
    $null=New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force
    [IO.File]::WriteAllText($path,$Text,$utf8)
}
try {
    $null=New-Item -ItemType Directory -Path $source
    foreach($folder in $catalog.Folders){$null=New-Item -ItemType Directory -Path (Join-Path $source $folder) -Force}
    foreach($file in $catalog.Files){Put $file "# LanPilot source fixture`n"}
    Put 'core/fixture.cpp' "// exact public bytes`n"
    Put 'tests/CMakeLists.txt' '# fixture'
    $packageOutput='set(CPACK_PACKAGE_DIRECTORY "${PROJECT_SOURCE_DIR}/out/packages")'
    Put 'CMakeLists.txt' $packageOutput
    Put '.git/private.cpp' 'ignored history'
    Put 'core/.git/private.cpp' 'ignored nested history'
    Put 'core/private.env' 'ignored environment'
    $one=Join-Path $source 'out/first'
    $result=Export-LanPilotPublicSource $source $one
    Check ($result.Status -eq 'STAGED' -and -not $result.HistoryCopied) 'Wrong source export status'
    $manifestPath=Join-Path $one 'source-manifest.json'
    $bytes=[IO.File]::ReadAllBytes($manifestPath)
    Check (-not ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191)) 'Manifest has BOM'
    $manifest=[IO.File]::ReadAllText($manifestPath)|ConvertFrom-Json
    Check ($manifest.schema -eq 1 -and $manifest.product -ceq 'LanPilot' -and $manifest.files.Count -eq $result.Files) 'Invalid source inventory'
    $previous=''
    foreach($entry in $manifest.files){
        Check ($previous -ceq '' -or [StringComparer]::Ordinal.Compare($previous,[string]$entry.path) -lt 0) 'Unstable source ordering'
        $previous=[string]$entry.path
        $path=Join-Path $one $entry.path
        Check ((Get-Item -LiteralPath $path).Length -eq $entry.bytes) 'Wrong byte size'
        Check ((Hash $path) -ceq $entry.sha256) 'Wrong source hash'
    }
    # The Mac installer loads these at runtime, beyond CMake's literal
    # dependency scan. They must survive a clean public source export.
    foreach($name in @('welcome.html','conclusion.html')){
        $relative='packaging/macos/personal-resources/'+$name
        Check (Test-Path -LiteralPath (Join-Path $one $relative) -PathType Leaf) 'Mac installer presentation omitted'
        Check ((Hash (Join-Path $one $relative)) -ceq (Hash (Join-Path $source $relative))) 'Mac installer presentation changed'
    }
    Check (-not (Test-Path -LiteralPath (Join-Path $one '.git'))) 'History copied'
    Check (-not (Test-Path -LiteralPath (Join-Path $one 'core/.git'))) 'Nested history copied'
    Check (-not (Test-Path -LiteralPath (Join-Path $one 'core/private.env'))) 'Environment copied'
    Check (-not (Test-Path -LiteralPath (Join-Path $source 'out/packages'))) 'Export created a generated package directory'
    $manifestHash=Hash $manifestPath
    Reject {Export-LanPilotPublicSource $source $one}
    Check ((Hash $manifestPath) -ceq $manifestHash) 'Existing export changed'
    $two=Join-Path $source 'out/second'
    Export-LanPilotPublicSource $source $two|Out-Null
    Check ((Hash (Join-Path $two 'source-manifest.json')) -ceq $manifestHash) 'Source inventory is not deterministic'
    Reject {Export-LanPilotPublicSource $source (Join-Path $root 'outside')}
    Reject {Export-LanPilotPublicSource $source 'relative'}

    $rejected=Join-Path $source 'out/rejected'
    Put 'core/fixture.cpp' 'PRIVATE_WORKFLOW_PERSON'
    Reject {Export-LanPilotPublicSource $source $rejected -ForbiddenTokens @('PRIVATE_WORKFLOW_PERSON')}
    Check (-not (Test-Path -LiteralPath $rejected)) 'Privacy failure wrote output'
    Put 'core/fixture.cpp' ('-----BEGIN '+'PRIVATE KEY-----')
    Reject {Export-LanPilotPublicSource $source $rejected}
    Put 'core/fixture.cpp' ('ghp_'+('a'*40))
    Reject {Export-LanPilotPublicSource $source $rejected}
    [IO.File]::WriteAllBytes((Join-Path $source 'core/fixture.cpp'),[byte[]]@(255,254,0))
    Reject {Export-LanPilotPublicSource $source $rejected}
    [IO.File]::WriteAllBytes((Join-Path $source 'core/fixture.cpp'),[Array]::CreateInstance([byte],8MB+1))
    Reject {Export-LanPilotPublicSource $source $rejected}
    Put 'core/fixture.cpp' '// restored'
    Put 'tests/CMakeLists.txt' 'add_test(NAME missing COMMAND powershell -File "${CMAKE_CURRENT_SOURCE_DIR}/missing_workflow.ps1")'
    Reject {Export-LanPilotPublicSource $source $rejected}
    Check (-not (Test-Path -LiteralPath $rejected)) 'Missing dependency wrote output'
    Put 'tests/CMakeLists.txt' '# restored'
    Put 'CMakeLists.txt' 'add_test(NAME missing COMMAND powershell -File "${PROJECT_SOURCE_DIR}/out/missing_workflow.ps1")'
    Reject {Export-LanPilotPublicSource $source $rejected}
    Check (-not (Test-Path -LiteralPath $rejected)) 'Generated-directory exception hid a missing input'
    Put 'CMakeLists.txt' $packageOutput
    $external=Join-Path $root 'external';$null=New-Item -ItemType Directory -Path $external
    $junction=Join-Path $source 'core/linked'
    $null=New-Item -ItemType Junction -Path $junction -Target $external
    try{Reject {Export-LanPilotPublicSource $source $rejected}}
    finally{[IO.Directory]::Delete($junction)}
    $redirect=Join-Path $source 'out/redirect'
    $null=New-Item -ItemType Junction -Path $redirect -Target $external
    try{Reject {Export-LanPilotPublicSource $source (Join-Path $redirect 'child')}}
    finally{[IO.Directory]::Delete($redirect)}
    Check (-not (Test-Path -LiteralPath (Join-Path $external 'child'))) 'Redirected output escaped source'
    Write-Output 'source_export=PASS deterministic=1 privacy=1 dependency_closure=1 linked_paths_rejected=1 history_copied=0 isolated=1'
} finally {
    # Only the new, resolved temporary fixture. Remove junctions without recursion
    # before the fixture tree, even if an assertion aborted the normal flow.
    foreach($link in @((Join-Path $source 'core/linked'),(Join-Path $source 'out/redirect'))){
        if(Test-Path -LiteralPath $link){[IO.Directory]::Delete($link)}
    }
    $expected=[IO.Path]::GetFullPath($root)
    if(-not $expected.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()),[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe fixture cleanup'}
    if(Test-Path -LiteralPath $expected){Remove-Item -LiteralPath $expected -Recurse -Force}
}
