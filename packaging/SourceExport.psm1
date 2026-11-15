Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Get-LanPilotSourceCatalog {
    [pscustomobject]@{
        Files=[string[]]@(
            'README.md','README.en.md','CONTRIBUTING.md','LICENSE','CMakeLists.txt','build.ps1','CMakePresets.json',
            '.gitignore','.gitattributes','.remoteignore','remote-workspace.toml','.github/workflows/ci.yml',
            'doc/public-guide.md','doc/desktop-preview-install.md','doc/public-releases.md','doc/release-readiness.md',
            'doc/product-status.md','doc/tls-setup-security.md','doc/mac-application-lifecycle.md',
            'doc/native-enrollment-certificates.md','doc/native-enrollment-pairing.md','doc/native-enrollment-identity.md',
            'doc/native-enrollment-journal.md',
            'doc/native-enrollment-completion.md',
            'doc/native-enrollment-configuration.md',
            'doc/native-enrollment-setup.md',
            'doc/native-status-renewal.md',
            'desktop/include/rwn/desktop/session_reconnect.hpp',
            'doc/session-reconnect.md',
            'doc/install-once-release-acceptance.md',
            'doc/macos-native-installer.md',
            'doc/personal-installers.md',
            'viewer/connection_startup.hpp',
            'doc/native-credential-renewal.md',
            'doc/mac-program-updates.md','doc/agent-shutdown.md','doc/mac-service-quiescence.md','doc/windows-install-lifecycle.md',
            'packaging/Export-PublicSource.ps1','packaging/SourceExport.psm1','packaging/DesktopPackage.cmake',
            'packaging/DESKTOP-README.md','packaging/release-manifest.toml.in',
            'packaging/windows/Setup.cmake','packaging/windows/Build-SetupPayload.ps1',
            'packaging/windows/Setup-Driver.ps1','tests/setup_workflow.ps1',
            'packaging/windows/Setup.manifest',
            'desktop-agent/macos/Info.plist.in','desktop-agent/macos/com.lanpilot.desktop.service.plist',
            'desktop-agent/macos/program_store.inc',
            'packaging/windows/Install-DesktopPreview.ps1','packaging/windows/Start-DesktopPreview.ps1',
            'packaging/windows/Start-LanPilot.ps1','packaging/windows/Start-LanPilotBootstrap.ps1',
            'packaging/windows/Start-LanPilotTls.ps1','packaging/windows/TlsConnectionSettings.psm1',
            'packaging/windows/Maintain-LanPilotTrust.ps1','packaging/windows/Invoke-LanPilotTrustMaintenance.ps1',
            'packaging/windows/Register-LanPilotMaintenance.ps1','packaging/windows/TrustMaintenance.psm1',
            'packaging/windows/ProductInstall.psm1','packaging/windows/Uninstall-DesktopPreview.ps1',
            'packaging/windows/Update-LanPilotTrustBundle.ps1','packaging/windows/Initialize-LanPilotAuthority.ps1',
            'packaging/windows/New-LanPilotWindowsIdentity.ps1',
            'packaging/macos/install-desktop-preview.sh','packaging/macos/uninstall-desktop-preview.sh',
            'packaging/macos/build-native-installer.py','packaging/macos/installer-preinstall.sh',
            'tests/mac_installer_workflow.py',
            'packaging/macos/build-personal-installer.py','packaging/macos/personal-runtime-check.sh',
            'tests/personal_installer_workflow.py',
            'packaging/macos/personal-resources/welcome.html',
            'packaging/macos/personal-resources/conclusion.html',
            'doc/architecture.md','doc/engineering-study-guide.zh-TW.md',
            'doc/assets/lanpilot-architecture.svg',
            'packaging/macos/LanPilot-Authorize.command','packaging/macos/New-LanPilotLaunchAgent.ps1',
            'packaging/macos/check-tls-resources.sh','packaging/macos/import-tls-identity.sh',
            'packaging/macos/install-tls-service.sh','packaging/macos/prepare-tls-identity.sh',
            'tests/tls_connection_settings_workflow.ps1','tests/tls_identity_readiness_workflow.ps1',
            'tests/enrollment_configuration_reader.ps1',
            'tests/product_install_workflow.ps1','tests/maintenance_launcher_workflow.ps1',
            'tests/lanpilot_product_layout_workflow.ps1','tests/trust_renewal_workflow.ps1',
            'tests/background_trust_workflow.ps1','tests/source_export_workflow.ps1',
            'tests/mac_launch_agent_workflow.ps1','tests/mac_tls_resources_workflow.sh')
        Folders=[string[]]@('audio','broker','build-worker','client','config','core','desktop','desktop-agent',
            'node','platform','protocol','tests','tools','transport','viewer')
        Extensions=[string[]]@('.cpp','.hpp','.h','.mm','.proto','.cmake','.toml','.tsv')
    }
}

function Assert-LanPilotSourceDirectory([string]$Path) {
    $item=Get-Item -LiteralPath $Path -Force
    if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){
        throw 'Source export does not follow linked directories.'
    }
}
function Get-LanPilotSourceSelection([string]$Root) {
    $catalog=Get-LanPilotSourceCatalog
    $paths=[Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal)
    foreach($relative in $catalog.Files){$null=$paths.Add($relative)}
    foreach($folder in $catalog.Folders){
        $pending=[Collections.Generic.Queue[string]]::new();$pending.Enqueue((Join-Path $Root $folder))
        while($pending.Count){
            $directory=$pending.Dequeue();Assert-LanPilotSourceDirectory $directory
            foreach($entry in Get-ChildItem -LiteralPath $directory -Force){
                if($entry.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Source export does not follow linked entries.'}
                if($entry.PSIsContainer){
                    if($entry.Name -notin @('.git','.codex','.aws')){$pending.Enqueue($entry.FullName)}
                }elseif($entry.Name -eq 'CMakeLists.txt' -or $entry.Extension -in $catalog.Extensions){
                    $null=$paths.Add($entry.FullName.Substring($Root.Length+1).Replace('\','/'))
                }
            }
        }
    }
    return ,$paths
}
function Get-LanPilotSourceHash([byte[]]$Bytes) {
    $hasher=[Security.Cryptography.SHA256]::Create()
    try{return ([BitConverter]::ToString($hasher.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}
    finally{$hasher.Dispose()}
}

function Export-LanPilotPublicSource {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SourceRoot,[Parameter(Mandatory)][string]$Destination,
          [string[]]$ForbiddenTokens=@())
    if(-not [IO.Path]::IsPathRooted($SourceRoot) -or -not [IO.Path]::IsPathRooted($Destination)){
        throw 'Source and export paths must be absolute.'
    }
    $root=[IO.Path]::GetFullPath($SourceRoot)
    if($root -eq [IO.Path]::GetPathRoot($root)){throw 'A project directory is required, not a drive root.'}
    $root=$root.TrimEnd([IO.Path]::DirectorySeparatorChar)
    $target=[IO.Path]::GetFullPath($Destination)
    $comparison=if([IO.Path]::DirectorySeparatorChar -eq '\'){[StringComparison]::OrdinalIgnoreCase}else{[StringComparison]::Ordinal}
    $parent=Join-Path $root 'out'
    if(-not $target.StartsWith($parent+[IO.Path]::DirectorySeparatorChar,$comparison)){
        throw 'Export must be a new directory inside project out/.'
    }
    if(Test-Path -LiteralPath $target){throw 'Export destination already exists.'}
    # Neither a linked source ancestor nor a redirected output parent is an
    # authority to read/write elsewhere. Do this before creating output.
    foreach($path in @($root,(Split-Path -Parent $target))){
        for($cursor=$path;$cursor;$cursor=Split-Path -Parent $cursor){
            if(Test-Path -LiteralPath $cursor){Assert-LanPilotSourceDirectory $cursor}
            if($cursor -eq [IO.Path]::GetPathRoot($cursor)){break}
        }
    }
    $selected=Get-LanPilotSourceSelection $root
    if($selected.Count -gt 2048){throw 'Source file count exceeds publication bounds.'}
    $snapshot=[Collections.Generic.List[object]]::new();[long]$total=0
    $utf8=[Text.UTF8Encoding]::new($false,$true)
    foreach($relative in $selected){
        if($relative -notmatch '^[A-Za-z0-9._/-]+$' -or $relative.Split('/') -contains '..' -or
           $relative.StartsWith('/')){throw 'Noncanonical source path.'}
        $file=Get-Item -LiteralPath (Join-Path $root $relative) -Force
        if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){
            throw 'Selected source must be a regular unlinked file.'
        }
        # Explicit catalog entries also need ancestor checks (not all belong to
        # the recursively selected folders).
        for($cursor=$file.DirectoryName;$cursor.Length -ge $root.Length;$cursor=Split-Path -Parent $cursor){
            Assert-LanPilotSourceDirectory $cursor;if($cursor.Equals($root,$comparison)){break}
        }
        if($file.Length -gt 8MB){throw 'Source file exceeds publication bounds.'}
        $bytes=[IO.File]::ReadAllBytes($file.FullName)
        if($bytes.Length -gt 8MB -or $total+$bytes.Length -gt 64MB){throw 'Source snapshot exceeds publication bounds.'}
        $text=$utf8.GetString($bytes)
        foreach($token in $ForbiddenTokens){
            if($token -and $text.IndexOf($token,[StringComparison]::OrdinalIgnoreCase) -ge 0){throw "Private marker found in $relative"}
        }
        if($text -match '-----BEGIN (OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}'){
            throw "Credential marker found in $relative"
        }
        $total+=$bytes.Length
        $snapshot.Add([pscustomobject]@{Path=$relative;Data=$bytes;Hash=(Get-LanPilotSourceHash $bytes)})
    }
    # Reject omitted literal CMake resource dependencies before an apparently
    # successful publication. Generated/binary-directory and dynamic references
    # remain the compiler/test suite's responsibility.
    foreach($item in $snapshot){
        if($item.Path -notmatch '(?:CMakeLists\.txt|\.cmake)$'){continue}
        $text=$utf8.GetString($item.Data)
        foreach($match in [regex]::Matches($text,'\$\{(PROJECT_SOURCE_DIR|CMAKE_CURRENT_SOURCE_DIR)\}/([^"\s;$)]+)')){
            # CPack's fixed output directory is generated, not an input. The
            # clean checkout need not already contain it. Keep this exception
            # command-specific: source/test references under out/ still fail.
            $lineStart=$text.LastIndexOf("`n",$match.Index)+1
            $lineEnd=$text.IndexOf("`n",$match.Index);if($lineEnd -lt 0){$lineEnd=$text.Length}
            $line=$text.Substring($lineStart,$lineEnd-$lineStart).Trim()
            if($line -cmatch '^set\(CPACK_PACKAGE_DIRECTORY "\$\{PROJECT_SOURCE_DIR\}/out/packages"\)$'){continue}
            $base=if($match.Groups[1].Value -eq 'PROJECT_SOURCE_DIR'){$root}else{Split-Path -Parent (Join-Path $root $item.Path)}
            $resource=[IO.Path]::GetFullPath((Join-Path $base $match.Groups[2].Value))
            if(-not $resource.StartsWith($root+[IO.Path]::DirectorySeparatorChar,$comparison)){throw 'CMake resource escapes source root.'}
            if(Test-Path -LiteralPath $resource -PathType Container){continue}
            $relative=$resource.Substring($root.Length+1).Replace('\','/')
            if(-not $selected.Contains($relative)){throw "CMake resource omitted from source export: $relative"}
        }
    }
    $null=New-Item -ItemType Directory -Path $target
    $records=[Collections.Generic.List[object]]::new()
    foreach($item in $snapshot){
        $destination=Join-Path $target $item.Path
        $null=New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force
        # Copy the exact bytes which passed privacy checks, not a second read
        # from a possibly changed working-tree file.
        [IO.File]::WriteAllBytes($destination,$item.Data)
        if((Get-LanPilotSourceHash ([IO.File]::ReadAllBytes($destination))) -cne $item.Hash){throw 'Source copy hash mismatch.'}
        $records.Add([ordered]@{path=$item.Path;bytes=$item.Data.Length;sha256=$item.Hash})
    }
    # Created LAST. A partial export has no completion manifest. This is an
    # integrity inventory, never a substitute for signed publisher verification.
    $manifest=[ordered]@{schema=1;product='LanPilot';files=@($records.ToArray())}
    $json=($manifest|ConvertTo-Json -Depth 6 -Compress)+"`n"
    [IO.File]::WriteAllText((Join-Path $target 'source-manifest.json'),$json,[Text.UTF8Encoding]::new($false))
    [pscustomobject]@{Status='STAGED';Files=$records.Count;Bytes=$total;HistoryCopied=$false}
}
Export-ModuleMember -Function Get-LanPilotSourceCatalog,Export-LanPilotPublicSource
