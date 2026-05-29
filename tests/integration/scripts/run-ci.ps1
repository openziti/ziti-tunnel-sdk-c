<#
Run the integration test suite end-to-end the same way CI does on Windows.
Lets a local dev reproduce a CI failure with one command.

Required input:
  $env:ZET_BIN  Absolute path to a built ziti-edge-tunnel.exe.

Optional input:
  $env:TEST_HOME      Working dir for overlay, logs, caches. Defaults to a temp dir.
  $env:ZITI_VERSION   ziti release tag to download (default: newest non-prerelease).
  $env:IDP_VERSION    dex version tag (default: fetch-dex.sh's pinned version).
  $env:ZET1_VERSION   If set, downloads this ZET release and uses it as ZET_BIN.
  $env:ZET2_VERSION   If set, downloads this ZET release and uses it as ZET_BIN_B.

Flags:
  -InstallCert  Install the test overlay CA into OS trust for the run and remove
                it on exit. Off by default so the script does not mutate a normal
                user's trust store.

Requires: go, gh, git. Run as Administrator when using -InstallCert, because
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

foreach ($tool in @("go", "gh", "git")) {
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

# ---- Resolve ziti version ---------------------------------------------------
$zitiVersion = $env:ZITI_VERSION
if (-not $zitiVersion) {
    $releases = gh release list --repo openziti/ziti --limit 50 --json tagName,isDraft,isPrerelease | ConvertFrom-Json
    $zitiVersion = ($releases | Where-Object { -not $_.isDraft -and -not $_.isPrerelease } | ForEach-Object tagName | Sort-Object { [version]($_ -replace '^v','') } | Select-Object -Last 1)
}
Write-Host "Using ziti $zitiVersion"

# ---- Download ziti CLI ------------------------------------------------------
$zitiDir = Join-Path $testHome "ziti-cli"
New-Item -ItemType Directory -Path $zitiDir -Force | Out-Null
Push-Location $zitiDir
gh release download --repo openziti/ziti $zitiVersion --pattern "ziti-windows-amd64-*.zip" --clobber
$zitiZip = (Get-ChildItem -Filter "*.zip" | Select-Object -First 1).FullName
Expand-Archive -Path $zitiZip -DestinationPath . -Force
$zitiBin = (Get-ChildItem -Recurse -Filter "ziti.exe" | Select-Object -First 1).FullName
Pop-Location
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

# ---- Optional ZET release overrides -----------------------------------------
$zetBin = $env:ZET_BIN
$zetBinB = if ($env:ZET_BIN_B) { $env:ZET_BIN_B } else { $zetBin }
$zetZip = "ziti-edge-tunnel-Windows_x86_64.zip"

if ($env:ZET1_VERSION) {
    $d = Join-Path $testHome "zet1"
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    Push-Location $d
    gh release download --repo openziti/ziti-tunnel-sdk-c $env:ZET1_VERSION --pattern $zetZip --clobber
    Expand-Archive -Path (Join-Path $d $zetZip) -DestinationPath . -Force
    $zetBin = (Get-ChildItem -Recurse -Filter "ziti-edge-tunnel.exe" | Select-Object -First 1).FullName
    Pop-Location
}
if ($env:ZET2_VERSION) {
    $d = Join-Path $testHome "zet2"
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    Push-Location $d
    gh release download --repo openziti/ziti-tunnel-sdk-c $env:ZET2_VERSION --pattern $zetZip --clobber
    Expand-Archive -Path (Join-Path $d $zetZip) -DestinationPath . -Force
    $zetBinB = (Get-ChildItem -Recurse -Filter "ziti-edge-tunnel.exe" | Select-Object -First 1).FullName
    Pop-Location
}
Write-Host "ZET_BIN=$zetBin"
Write-Host "ZET_BIN_B=$zetBinB"

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

# ---- Install CA into OS trust -----------------------------------------------
$caCert = Join-Path $overlayHome "pki\root-ca\certs\root-ca.cert"
$importedCert = $null
if ($InstallCert) {
    $importedCert = Import-Certificate -FilePath $caCert -CertStoreLocation Cert:\LocalMachine\Root
} else {
    Write-Warning "skipping test CA install into OS trust (pass -InstallCert to enable); tests that require the controller cert to be trusted may fail"
}

try {
    # ---- Write config.json --------------------------------------------------
    Push-Location (Join-Path $repoRoot "tests\integration")
    $cfg = [ordered]@{
        testHome = $testHome
        ziti = [ordered]@{ binary = $zitiBin; url = ""; user = "admin"; password = "admin" }
        zetA = [ordered]@{ binary = $zetBin;  verbosity = 4; tlsuvDebug = 0 }
        zetB = [ordered]@{ binary = $zetBinB; verbosity = 4; tlsuvDebug = 0 }
        idp  = [ordered]@{
            useTestHarnessIdP = $true
            binary         = $idpBin
            issuer         = ""
            clientId       = "ziti-test"
            extraClientIds = @("ziti-test-2", "ziti-test-3")
            audience       = "ziti-test"
            sub            = ""
            scopes         = "openid profile email"
            user = [ordered]@{
                email    = "test@example.com"
                username = "test"
                userID   = "08a8684b-db88-4b73-90a9-3cd1661f5466"
                password = "password"
            }
        }
    }
    $cfg | ConvertTo-Json -Depth 10 | Set-Content -Path config.json -Encoding utf8
    Get-Content config.json

    # ---- Run tests ------------------------------------------------------------
    go test ./... -v -timeout 20m -config config.json
    $exitCode = $LASTEXITCODE
}
finally {
    if ($importedCert) {
        Get-ChildItem Cert:\LocalMachine\Root |
            Where-Object { $_.Thumbprint -eq $importedCert.Thumbprint } |
            Remove-Item -ErrorAction SilentlyContinue
    }
    Pop-Location -ErrorAction SilentlyContinue
}

exit $exitCode
