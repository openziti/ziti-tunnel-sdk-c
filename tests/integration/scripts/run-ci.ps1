<#
Run the integration test suite end-to-end the same way CI does on Windows.
Lets a local dev reproduce a CI failure with one command.

Required input:
  $env:ZET_BIN   Absolute path to a ziti-edge-tunnel.exe.
  $env:ZITI_BIN  Absolute path to a ziti binary. CI obtains it (a release or a main build).

Optional input:
  $env:TEST_HOME      Working dir for overlay, logs, caches. Defaults to a temp dir.
  $env:IDP_VERSION    dex version tag (default: fetch-dex.sh's pinned version).
  $env:ZET_BIN_B      ziti-edge-tunnel.exe for zetB. Defaults to ZET_BIN.

Flags:
  -InstallCert  Install the test overlay CA into OS trust for the run and remove
                it on exit. Off by default so the script does not mutate a normal
                user's trust store.

Requires: go. Run as Administrator when using -InstallCert, because
installing the test overlay CA into Cert:\LocalMachine\Root requires it.
#>

#Requires -Version 7.0

param([switch]$InstallCert)

$ErrorActionPreference = "Stop"

if (-not $env:ZET_BIN) {
    Write-Error "ZET_BIN must point to a ziti-edge-tunnel.exe"
}
if (-not (Test-Path $env:ZET_BIN)) {
    Write-Error "ZET_BIN=$($env:ZET_BIN) does not exist"
}
if (-not $env:ZITI_BIN) {
    Write-Error "ZITI_BIN must point to a ziti binary"
}
if (-not (Test-Path $env:ZITI_BIN)) {
    Write-Error "ZITI_BIN=$($env:ZITI_BIN) does not exist"
}

foreach ($tool in @("go")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Error "missing required tool: $tool"
    }
}

$testHome = if ($env:TEST_HOME) { $env:TEST_HOME } else {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ziti-tunnel-test-{0}" -f ([System.Guid]::NewGuid().ToString("N").Substring(0, 8)))
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    $tmp
}
Write-Host "TEST_HOME=$testHome"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path

# ---- ziti CLI ---------------------------------------------------------------
$zitiBin = $env:ZITI_BIN
Write-Host "ZITI_BIN=$zitiBin"

# ---- Build/fetch dex --------------------------------------------------------
$dexDir = Join-Path $testHome "dex"
$fetchDex = Join-Path $PSScriptRoot "fetch-dex.ps1"
if ($env:IDP_VERSION) {
    & $fetchDex -Dest $dexDir -Version $env:IDP_VERSION
} else {
    & $fetchDex -Dest $dexDir
}
if ($LASTEXITCODE -ne 0) { Write-Error "fetch-dex.ps1 failed (exit $LASTEXITCODE)" }
$idpBin = Join-Path $dexDir "dex.exe"
Write-Host "IDP_BIN=$idpBin"

$zetBin = $env:ZET_BIN
$zetBinB = if ($env:ZET_BIN_B) { $env:ZET_BIN_B } else { $zetBin }
Write-Host "ZET_BIN=$zetBin"
Write-Host "ZET_BIN_B=$zetBinB"

Write-Host "ziti version: $(& $zitiBin version)"
Write-Host "zetA version: $(& $zetBin version)"
Write-Host "zetB version: $(& $zetBinB version)"
Write-Host "dex version:  $(& $idpBin version | Select-Object -First 1)"

# ---- Seed test overlay PKI --------------------------------------------------
# Seed at $testHome\overlay (where the test framework's own quickstart runs)
# so its second quickstart reuses this PKI, ensuring the cert we install into
# OS trust matches the cert the test's controller serves.
$overlayHome = Join-Path $testHome "overlay"
Write-Host "Seeding test overlay PKI at $overlayHome"
$qs = Start-Process $zitiBin -ArgumentList @(
    "edge", "quickstart",
    "--home=$overlayHome",
    "--ctrl-address=localhost", "--ctrl-port=1280",
    "--router-address=localhost", "--router-port=3022"
) -PassThru -NoNewWindow
$sw = [Diagnostics.Stopwatch]::StartNew()
while ($true) {
    $ctrlOk = $false; $rtrOk = $false
    try {
        $r = Invoke-WebRequest -Uri "https://localhost:1280/" -SkipCertificateCheck -TimeoutSec 2 -ErrorAction Stop
        if ($r.StatusCode -lt 500) { $ctrlOk = $true }
    } catch { }
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $c.Connect("localhost", 3022)
        $c.Close()
        $rtrOk = $true
    } catch { }
    if ($ctrlOk -and $rtrOk) { break }
    if ($sw.Elapsed.TotalSeconds -gt 120) {
        Stop-Process -Id $qs.Id -Force -ErrorAction SilentlyContinue
        Write-Error "overlay never came up within 120s"
    }
    Start-Sleep -Seconds 1
}
Stop-Process -Id $qs.Id -Force
$qs.WaitForExit()

# ---- CA trust -----------------------------------------------------------------
# The harness installs the overlay CA into OS trust after the fixture import and
# removes it at teardown when ziti.autoTrustCa is set.
if (-not $InstallCert) {
    Write-Warning "autoTrustCa disabled (pass -InstallCert to enable); tests that require the controller cert to be trusted may fail"
}

try {
    # ---- Write config.json --------------------------------------------------
    Push-Location (Join-Path $repoRoot "tests\integration")
    $cfg = [ordered]@{
        testHome = $testHome
        ziti = [ordered]@{ binary = $zitiBin; url = ""; user = "admin"; password = "admin"; autoTrustCa = [bool]$InstallCert }
        zetA = [ordered]@{ binary = $zetBin;  verbosity = 4; tlsuvDebug = 0 }
        zetB = [ordered]@{ binary = $zetBinB; verbosity = 4; tlsuvDebug = 0 }
        idp  = [ordered]@{
            useTestHarnessIdP = $true
            binary         = $idpBin
            issuer         = ""
            clientId       = "ziti-test"
            extraClientIds = @("ziti-test-2", "ziti-test-3")
            audience       = "ziti-test"
            scopes         = "openid profile email"
            password       = "password"
        }
    }
    $cfg | ConvertTo-Json -Depth 10 | Set-Content -Path config.json -Encoding utf8
    Get-Content config.json

    # ---- Run tests ------------------------------------------------------------
    go test ./... -v -timeout 20m -config config.json
    $exitCode = $LASTEXITCODE
}
finally {
    Pop-Location -ErrorAction SilentlyContinue
}

exit $exitCode
