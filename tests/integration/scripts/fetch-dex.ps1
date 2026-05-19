# Clone the dex source and build the dex binary.
# Dex doesn't publish prebuilt binaries, and its module path predates Go
# modules' /vN/ convention, which breaks 'go install ...@latest'. Cloning the
# tag and running 'go build' from the working tree is the supported path.
#
# Usage:
#   ./fetch-dex.ps1                  # builds the version pinned below
#   ./fetch-dex.ps1 -Version v2.45.1
#   ./fetch-dex.ps1 -Dest C:\tools\dex

param(
    [string]$Version = "v2.45.1",
    [string]$Dest = "",
    [switch]$Force
)

# Durable cache: %LOCALAPPDATA%\ziti-tunnel-test-dex\<version>
if (-not $Dest) {
    $cacheRoot = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:USERPROFILE }
    $Dest = Join-Path (Join-Path $cacheRoot "ziti-tunnel-test-dex") $Version
}

$ErrorActionPreference = "Stop"

if (-not (Get-Command go -ErrorAction SilentlyContinue)) { throw "go is not on PATH -- install Go first" }
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw "git is not on PATH" }

New-Item -ItemType Directory -Force -Path $Dest | Out-Null
$srcDir = Join-Path $Dest "src"
$dexExe = Join-Path $Dest "dex.exe"

if ((Test-Path $dexExe) -and -not $Force) {
    Write-Host "dex already built at $dexExe (use -Force to rebuild)"
    Write-Host ""
    Write-Host "run tests with:"
    Write-Host "  go -C tests/integration test -run TestPKCEUp -v -zet-bin <path> -ziti-bin <path> -pkce-bin `"$dexExe`""
    return
}

if (Test-Path $srcDir) {
    Write-Host "removing stale clone at $srcDir"
    Remove-Item -Recurse -Force $srcDir
}

Write-Host "cloning dex $Version into $srcDir"
& git clone --depth 1 --branch $Version https://github.com/dexidp/dex.git $srcDir
if ($LASTEXITCODE -ne 0) { throw "git clone failed (exit $LASTEXITCODE)" }

Write-Host "building dex.exe -> $dexExe"
Push-Location $srcDir
try {
    # Force auto-toolchain so Go downloads whatever version dex's go.mod requires.
    $env:GOTOOLCHAIN = "auto"
    & go build -o $dexExe ./cmd/dex
    if ($LASTEXITCODE -ne 0) { throw "go build failed (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "dex binary: $dexExe"
Write-Host ""
Write-Host "run tests with:"
Write-Host "  go -C tests/integration test -run TestPKCEUp -v -zet-bin <path> -ziti-bin <path> -pkce-bin `"$dexExe`""
