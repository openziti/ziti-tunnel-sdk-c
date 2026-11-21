# Extra Authorize Parameters for External JWT Signers

`ziti-edge-tunnel` can add query parameters to the authorize request that it sends to the OpenID Connect (OIDC)
provider of an external JWT signer. This page is for operators whose provider needs a parameter that the signer
configuration on the controller cannot express.

A common case is a provider that returns a refresh token only on request, for example with `access_type=offline`.
Without a refresh token the tunneler cannot renew an expired token and asks for a new login in the browser.

## Configuration

Set the environment variable `ZITI_EXT_AUTH_PARAMS` before the tunneler starts:

```
ZITI_EXT_AUTH_PARAMS=access_type=offline
```

Several parameters are separated with `&`: `name=value&name=value`.

- Values are written literally. The tunneler URL-encodes names and values, so a value must not be encoded
  beforehand, and a value cannot contain `&`.
- An entry without a name or without `=` is skipped with a warning.
- The parameters apply to every loaded identity, and to the primary and the secondary external signer of each.
  They do not apply to the login during enrollment of a new identity.
- The authorize URL, including these parameters, appears in the log at `INFO` level. Do not put secrets in it.
