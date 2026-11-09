# TOTP / MFA States

`ziti-edge-tunnel` tracks two flags per identity, both persisted in `config.json` and both reported to clients
in the `tunnel_identity` payload:

- **`MfaEnabled`** - the identity has a verified TOTP enrollment, as the controller reports it. The value can
  lag a change made on the controller (for example an administrator clearing the enrollment) by up to one
  service refresh interval (`-r`, 10 seconds by default), and no event is sent when it changes; it shows up
  in the next status or `identity` event. Until the identity first authenticates, it is the value from
  `config.json`.
- **`MfaNeeded`** - something is waiting on a TOTP code or on enrollment right now: a login that stopped for
  MFA, or an MFA posture check with no code since login or whose code is about to expire. It is set shortly
  before the code expires, so the user can be asked before access is lost.

The MFA timeout fields (`MfaMinTimeout`/`MfaMaxTimeout` and their `...Rem` counterparts on the identity,
`Timeout`/`TimeoutRemaining` on each service) are in seconds and describe MFA posture checks only: `-1` means
no timeout, and a remaining time of `0` means the code has expired or none was given.

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
| 8   | authenticated, gains a service with an MFA posture check | n/a                 | no           | false        | false       | service granted but inaccessible; UI shows posture-check-needed | `mfaCheckDeniesUntilMfaEnrolled`                                               |
| 9   | authenticated, the code of an MFA posture check expiring | n/a                 | yes          | true         | true        | prompt for a code; a new code clears it                         | none                                                                           |
| 10  | authenticated, an administrator clears TOTP enrollment   | no                  | no (new)     | false        | false       | reported as not enrolled within one refresh interval            | none                                                                           |
| 11  | restart after an administrator cleared TOTP enrollment   | no                  | no           | false        | false       | no prompt; the stored `true` is replaced when the identity loads | `adminRemovedMfaStopsPromptingAfterRestart`                                    |
| 12  | restart after the user removed their TOTP enrollment     | no                  | no           | false        | false       | no prompt                                                       | `removeMfaThenRestartStopsPrompting`                                           |

Row 6 says "on the next authentication" because that is what is verified: the test forces a re-authentication and
expects an enrollment request. Whether the controller tears down an established session the moment the policy
changes is not tested.

Row 7 is `false` because an enrolled identity gave a code when it logged in, and that code meets the posture
check until its timeout. Row 9 is the same identity once that timeout is near.

Rows 4 and 8 share `false`/`false`. They differ only in whether a posture-gated service is present, which is
reported through `tunnel_service` (`PostureChecks[]`, `IsAccessible`, and the timeout fields), not through these
two flags.

Row 10 depends on something asking for the identity's state: the change is reported the next time a status or
`identity` event is sent, or a client requests `Status`. No event is sent at the moment the controller's value
changes, because the SDK does not report one.

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

The controller's answer would replace that guess once the identity's data is loaded, but an identity in this state
never gets past the login that is waiting for MFA, so the guess stands.

## Not covered here

Each of these needs its own table and its own tests:

- an enrollment that was started but never verified. The controller does not count it as enrolled, so
  `MfaEnabled` stays `false`.

`key_pass_challenge`, the keychain PIN prompt, shares the `mfa_status` enum and the `MfaNeeded` flag but is not
TOTP and does not belong in this table.
