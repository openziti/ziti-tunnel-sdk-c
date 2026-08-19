# TOTP / MFA States

`ziti-edge-tunnel` tracks two flags per identity, both persisted in `config.json` and both reported to clients
in the `tunnel_identity` payload:

- **`MfaEnabled`** - the identity has a verified TOTP enrollment. The client owns this value. It is written when
  an enrollment is verified, when authentication with a code succeeds, and when an enrollment is removed.
- **`MfaNeeded`** - something is waiting on a TOTP code or on enrollment right now.

Enrolling TOTP makes the controller demand a code at authentication whether or not an auth policy requires it.
"The auth policy does not require MFA" therefore never means "MFA will not be asked for".

## States

| #   | Trigger                                                  | Policy requires MFA | MFA enrolled | `MfaEnabled` | `MfaNeeded` | Expected behavior                                               | Covered by                                                                     |
|-----|----------------------------------------------------------|---------------------|--------------|--------------|-------------|-----------------------------------------------------------------|--------------------------------------------------------------------------------|
| 1   | authenticating                                           | yes                 | yes          | true         | true        | prompt for a code                                               | `reauthUnderTotpRequiredPolicyAsksForCode`                                     |
| 2   | authenticating                                           | yes                 | no           | false        | true        | prompt to enroll                                                | `enrollCompletesWithTotpRequiredPolicy`                                        |
| 3   | authenticating                                           | no                  | yes          | true         | true        | prompt for a code; enrollment alone makes the controller ask     | `restartOffersCodePromptForEnrolledIdentity`, `reauthAcceptsValidTotp`          |
| 4   | authenticating                                           | no                  | no           | false        | false       | authenticates, no MFA involvement                               | `twoIdentitiesKeepSeparateMfaState`                                            |
| 5   | authenticated, moved onto a policy that now requires MFA | yes (new)           | yes          | true         | false       | keeps working                                                   | `policyAddedForEnrolledIdentityKeepsWorking`                                   |
| 6   | authenticated, moved onto a policy that now requires MFA | yes (new)           | no           | false        | true        | asked to enroll on the next authentication                      | `policyAddedForUnenrolledIdentityAsksToEnroll`                                 |
| 7   | authenticated, gains a service with an MFA posture check | n/a                 | yes          | true         | false       | service usable once the posture check passes, within one poll   | none                                                                           |
| 8   | authenticated, gains a service with an MFA posture check | n/a                 | no           | false        | false       | service granted but inaccessible; UI shows posture-check-needed | none                                                                           |

Row 6 says "on the next authentication" because that is what is verified: the test forces a re-authentication and
expects an enrollment request. Whether the controller tears down an established session the moment the policy
changes is not tested.

Rows 4 and 8 share `false`/`false`. They differ only in whether a posture-gated service is present, which is
reported through `tunnel_service` (`PostureChecks[]`, `IsAccessible`, and the timeout fields), not through these
two flags.

## Known limitation: enrollment that cannot authenticate

When an enrollment attempt fails with `ZITI_AUTHENTICATION_FAILED`, the client treats the identity as enrolled and
asks for a code. Only an enrolled identity fails that way on a controller that reports enrollment state, so the
inference holds there. It does not hold on the legacy api-session path, where a **never-enrolled** identity under a
TOTP-required policy fails identically, because that path refuses to enroll TOTP from a partially authenticated
session at all (openziti/ziti#3496, fixed for the OIDC path in ziti 2.0).

Both cases arrive as the same error code and the same status string, so the client cannot tell them apart. It
resolves them in favour of the enrolled identity: that is the state a client upgrading from a version that stored
the wrong value lands in, and guessing the other way leaves those users with an enrollment prompt that can never
succeed. The cost is that a never-enrolled identity on the legacy path gets marked enrolled - a user who is
already unable to enroll, for the same upstream reason.

## Not covered here

Each of these needs its own table and its own tests:

- an administrator clearing an identity's TOTP enrollment, leaving `MfaEnabled` stale
- MFA posture-check timeouts lapsing mid-session, which sets `MfaNeeded` without any change to policy or
  enrollment
- an enrollment that was started but never verified
- a user removing their own TOTP enrollment

`key_pass_challenge`, the keychain PIN prompt, shares the `mfa_status` enum and the `MfaNeeded` flag but is not
TOTP and does not belong in this table.
