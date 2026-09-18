[CmdletBinding()]
param(
    [ValidateSet('dev', 'release')]
    [string]$Preset = 'dev',
    [switch]$Test
)

$ErrorActionPreference = 'Stop'
$cmake = 'C:/msys64/ucrt64/bin/cmake.exe'

& $cmake --preset $Preset
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $cmake --build --preset $Preset
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($Test) {
    & $cmake --build "build/$Preset" --target test
    exit $LASTEXITCODE
}
