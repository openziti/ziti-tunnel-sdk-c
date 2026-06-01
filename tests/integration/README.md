# Integration Tests

These tests run `ziti-edge-tunnel` against an OpenZiti controller over its IPC socket.

Two choices in the config decide what a run needs:

1. **Controller** - let the suite stand one up for you (`ziti edge quickstart`), or point it at a running quickstart/controller URL.
2. **IdP** - the external-auth tests need an identity provider. The harness can run a local one for you, you can point at an external one (Auth0, Keycloak, ...), or you can configure none and those tests skip.

Grab the binaries, copy the config that matches your case from [Choosing a mode](#choosing-a-mode), and run it.

## Requirements

- **Go** (the version the repo builds with).
- **Elevation.** The tests open a TUN device, so run them as **root** (Linux/macOS, via `sudo`) or **Administrator** (Windows). Unelevated runs fail immediately with a clear message.
- **A `ziti` CLI binary** to manage the controller. It must be able to talk to your controller's management API; matching the controller's major version is safest.
- **A `ziti-edge-tunnel` binary** (the thing under test).
- **A `dex` binary** only if you want the harness to run a local IdP (see [The IdP](#the-idp)).

## Getting the binaries

- **`ziti` CLI** - download a release from <https://github.com/openziti/ziti/releases> and unpack it.
- **`ziti-edge-tunnel`** - build it from this repo (see the top-level build docs) or download a release from <https://github.com/openziti/ziti-tunnel-sdk-c/releases>.
- **`dex`** - dex ships no prebuilt binaries, so build it with the helper script (see [The IdP](#the-idp)). Skip this unless you want to run external-auth tests with a local IdP.

## Choosing a mode

Copy one of these, fill in the binary paths, and save it (any name; `config*.json` is gitignored except the example, so `config.json`, `config-local.json`, etc. all work).

### A. Local quickstart, no IdP (minimal)

The smallest run. The harness stands up a controller and runs everything except the external-auth tests (those skip with no IdP configured). No dex, no cert trust needed.

```json
{
  "testHome": "/tmp/ziti-it",
  "ziti": {
    "binary": "/path/to/ziti",
    "url": "",
    "user": "admin",
    "password": "admin"
  },
  "zetA": {
    "binary": "/path/to/ziti-edge-tunnel",
    "verbosity": 4,
    "tlsuvDebug": 0
  },
  "idp": {
    "useTestHarnessIdP": false
  }
}
```

Anything omitted falls back to its zero value, so the host-side tunneler (`zetB`) is left out here: when its `binary` is empty the harness reuses `zetA`'s.

### B. Local quickstart + harness IdP (full suite)

Runs the external-auth tests too. Needs a `dex` binary and the overlay CA trusted (see [The IdP](#the-idp) and [Trusting the test CA](#trusting-the-test-ca)).

```json
{
  "testHome": "/tmp/ziti-it",
  "ziti": {
    "binary": "/path/to/ziti",
    "url": "",
    "user": "admin",
    "password": "admin"
  },
  "zetA": {
    "binary": "/path/to/ziti-edge-tunnel",
    "verbosity": 4,
    "tlsuvDebug": 0
  },
  "zetB": {
    "binary": "",
    "verbosity": 4,
    "tlsuvDebug": 0
  },
  "idp": {
    "useTestHarnessIdP": true,
    "binary": "/path/to/dex",
    "clientId": "ziti-test",
    "extraClientIds": ["ziti-test-2", "ziti-test-3"],
    "audience": "ziti-test",
    "scopes": "openid profile email",
    "user": {
      "email": "test@example.com",
      "username": "test",
      "userID": "08a8684b-db88-4b73-90a9-3cd1661f5466",
      "password": "password"
    }
  }
}
```

### C. Your own controller + external IdP

Targets a controller you already run and an IdP you already have. The harness does not create the signer here; it **adopts** the one named by `signerName`, which must already exist on the controller. Set `sub` to the value of whatever claim that signer matches on (its `claimsProperty`), and `issuer` to your IdP.

```json
{
  "testHome": "/tmp/ziti-it",
  "ziti": {
    "binary": "/path/to/ziti",
    "url": "https://ctrl.example.com:8441",
    "user": "admin",
    "password": "REDACTED"
  },
  "zetA": {
    "binary": "/path/to/ziti-edge-tunnel",
    "verbosity": 4,
    "tlsuvDebug": 0
  },
  "zetB": {
    "binary": "",
    "verbosity": 4,
    "tlsuvDebug": 0
  },
  "idp": {
    "useTestHarnessIdP": false,
    "issuer": "https://your-tenant.example.com/",
    "signerName": "my-existing-signer",
    "sub": "the-users-subject-claim",
    "user": {
      "email": "user@example.com",
      "password": "REDACTED"
    }
  }
}
```

To use your own controller but skip external-auth entirely, use this shape with `issuer` and `signerName` empty.

> **Invalid combination:** an external controller (`ziti.url` set) with `useTestHarnessIdP: true` is rejected at startup. The harness IdP binds to localhost, so a remote controller can't reach it to validate tokens.

## Running

1. Save your chosen config, e.g. `tests/integration/config.json`.
2. Make sure the `binary` paths in it point at real files.
3. From `tests/integration/`, run elevated with `-config`:

   ```bash
   # Linux / macOS
   sudo go test -v -config config.json
   ```

   ```powershell
   # Windows, from an elevated PowerShell
   go test -v -config config.json
   ```

To run a single "set" of tests, add `-run`, e.g. `-run TestExternalAuthSingleSigner`.

## Config reference

The suite hard-requires only **`ziti.binary`** and **`zetA.binary`**; everything else depends on the mode.

| Field | Meaning |
|-------|---------|
| `testHome` | Working dir for the overlay, logs, and IdP files. |
| `ziti.binary` | Path to the `ziti` CLI. **Required.** |
| `ziti.url` | Controller URL. **Empty = stand up a local quickstart overlay.** Set = use that controller. |
| `ziti.user` / `ziti.password` | Admin credentials (quickstart default is `admin` / `admin`). |
| `zetA` / `zetB` | The two tunnelers (client and host). `zetA.binary` is **required**; `zetB.binary` empty reuses it. `verbosity` and `tlsuvDebug` raise log detail (higher is noisier; `4` / `0` are fine defaults). |
| `idp.useTestHarnessIdP` | `true` = harness runs a local IdP from `idp.binary`. `false` = external IdP, or none. |
| `idp.binary` | Path to the local IdP binary (dex). Required when `useTestHarnessIdP` is `true`. |
| `idp.issuer` | External IdP issuer URL. **Empty = no IdP; external-auth tests skip.** |
| `idp.signerName` | Name of an existing `ext-jwt-signer` to adopt. Required for an external IdP. |
| `idp.clientId` | OIDC client id (used by the harness IdP and by any signer the harness creates). |
| `idp.audience` | Expected token audience for a signer the harness creates. External IdP: the token's `aud` (often the controller URL). Harness IdP: the client id. |
| `idp.scopes` | Space-separated OIDC scopes requested by a created signer. |
| `idp.sub` | The identity's `externalId`, which must match the signer's matched claim. Empty falls back to `idp.user.email`. |
| `idp.extraClientIds` | Extra client ids; only the multi-signer test uses these. |
| `idp.user` | The IdP login user. `email` / `password` drive the login; `username` / `userID` seed the harness IdP's user record. |

## The IdP

The external-auth tests run an OAuth2 PKCE login, so they need an IdP. Three states:

- **None** - `useTestHarnessIdP: false` with an empty `issuer`. The tests skip.
- **Harness IdP** - `useTestHarnessIdP: true`. The harness starts dex locally and seeds the user. Build dex first:

  ```bash
  # Linux / macOS
  ./scripts/fetch-dex.sh
  VERSION=v2.45.1 DEST=/opt/dex ./scripts/fetch-dex.sh
  ```

  ```powershell
  # Windows
  .\scripts\fetch-dex.ps1
  .\scripts\fetch-dex.ps1 -Version v2.45.1 -Dest C:\tools\dex
  ```

  The script prints the built binary path; put it in `idp.binary`. (It needs Go and git on PATH.)
- **External IdP** - `useTestHarnessIdP: false` with `issuer` + `signerName` (mode C). The login form is read generically, so dex, Keycloak, and Auth0 all work; the IdP user must be a username/password (database) user, not a social login. The signer matches one claim (its `claimsProperty`) against the identity's `externalId`, so `idp.sub` (or `idp.user.email` when `sub` is empty) must equal that claim's value in the token.

## Trusting the test CA

To test by-URL enrollment you must trust the controller's CA in the OS store; with no JWT to carry it, those tests fall back to OS trust and skip when it's missing.

- A controller with a publicly trusted cert needs nothing.
- For a **local quickstart** overlay, trust its generated CA at `<testHome>/overlay/pki/root-ca/certs/root-ca.cert`:

  ```powershell
  # Windows (elevated)
  Import-Certificate -FilePath "<testHome>\overlay\pki\root-ca\certs\root-ca.cert" -CertStoreLocation Cert:\LocalMachine\Root
  ```

  ```bash
  # Linux
  sudo cp <testHome>/overlay/pki/root-ca/certs/root-ca.cert /usr/local/share/ca-certificates/ziti-test.crt && sudo update-ca-certificates
  # macOS
  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <testHome>/overlay/pki/root-ca/certs/root-ca.cert
  ```

  The suite prints the matching removal command at teardown so you can undo it.

## Reproducing CI

`scripts/run-ci.sh` (and `run-ci.ps1` on Windows) do the whole thing end to end the way CI does: download `ziti`, build dex, seed PKI, write a config, and run the suite.

```bash
ZET_BIN=/path/to/ziti-edge-tunnel ./scripts/run-ci.sh
```

```powershell
$env:ZET_BIN = "C:\path\to\ziti-edge-tunnel.exe"; .\scripts\run-ci.ps1
```

They honor `TEST_HOME`, `ZITI_VERSION`, `IDP_VERSION`, `ZET1_VERSION`, `ZET2_VERSION`, and a `--install-cert` / `-InstallCert` flag that installs the overlay CA for the run and removes it afterward. Without that flag they leave your trust store untouched.
