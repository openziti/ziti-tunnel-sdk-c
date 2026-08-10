---
name: debug ziti-edge-tunnel log
description: Diagnose a ziti-edge-tunnel log (journalctl capture, log file, or IPC dump) from Linux, macOS, or Windows. Collapses a huge verbose log into a signature histogram, establishes what the tunneler stopped doing rather than what it complained about, and traces the failure into ziti-sdk-c at the exact commit the binary was built from.
---

## Invocation

```
/debug ziti-edge-tunnel log [path to log, or a ticket number]
```

## What this skill is for

A `ziti-edge-tunnel` log at `--verbose=4` is 40,000+ lines for a single day, and 97% of it is DNS-resolver
chatter. The interesting failures are almost never a loud error. They are a thing the tunneler **stopped
doing** — a timer that never got re-armed, a refresh loop that never started, a channel that was never
opened. Errors are usually one symptom out of a chain, and the loudest error in the file is frequently a
red herring.

So the method here is *subtractive*. Collapse the log until what remains is small enough to read whole, then
ask what is missing from it. Only after that do you open source code.

This skill covers the tunneler and the C SDK it embeds. It does not cover the Windows desktop client's
feedback bundles — that is a different collection format with its own skill.

## Before you start

**Everything you conclude is bounded by the log window.** A `journalctl -b` capture covers one boot. A
capture taken after a restart usually does not contain the incident. Establish the window in step 3 and
state it in the report. "No evidence of X" and "X is outside the log window" are different findings.

**Absence of a log line proves nothing until you check three things:** that the window covers the event,
that the log level in effect would have emitted that line, and that you searched every rolled file.

**Logs are customer data.** Controller URLs, identity names and UUIDs, internal hostnames, service names,
intercept addresses, and the customer's IP ranges are all in there, and an IPC `ziti_dump` additionally
contains session state. Redact before anything goes in a public issue. When quoting evidence, quote the
smallest fragment that makes the point.

**Shell hygiene.** Use absolute paths and one command per invocation. Some environments block `cd`,
compound commands, and shell redirection; if `>` is rejected, use `tee`. If `git -C` and `--git-dir` are
blocked, `GIT_DIR=/path/to/repo/.git git show <ref>:<file>` gets you a file out of another checkout without
changing directory.

## Steps

### 1. Locate the log

In order of preference:

1. A path passed in the invocation.
2. A log or archive in the working directory.
3. **A ticket number** — list the ticket's attachments through whatever support-desk integration this
   session has, and let the operator choose which to download. Do not guess; a ticket usually carries
   email-signature images alongside the real artifact.

Read the ticket comments too, **including internal ones**. Prior analysis on the ticket tells you which
hypothesis you are testing and what has already been ruled in or out. Treat that analysis as a claim to
verify, not as a finding — earlier passes routinely contradict each other, and reconciling them against the
log is often the whole job.

If there is no log and no ticket, say so and stop.

### 2. Decide where files go, and say so

Put downloaded attachments, decompressed logs, and the write-up in one per-incident directory, and tell the
operator the path. Keep it **out of the repository working tree** so nothing lands in a commit.

Set the base directory from the environment, falling back to a temp path:

```bash
BASE="${ZITI_SUPPORT_DIR:-${TMPDIR:-/tmp}/ziti-support}"
INCIDENT="$BASE/<ticket-or-incident-id>"
mkdir -p "$INCIDENT"
```

Operators who triage regularly should export `ZITI_SUPPORT_DIR` once so every incident lands somewhere they
already look.

### 3. Establish the frame before reading anything

Four facts, from the first ~40 lines and the file's own boundaries. Get these wrong and every later
conclusion inherits the error.

```bash
gunzip -kf "$INCIDENT/<file>.gz"          # if compressed
LOG="$INCIDENT/<file>"
wc -lc "$LOG"
head -40 "$LOG"
tail -5  "$LOG"
```

Record:

| Fact | Where it comes from |
|---|---|
| **SDK version and commit** | `ziti_log_init() Ziti C SDK version X.Y.Z @gHHHHHHH` — the `@g` hash is the exact build. You need it in step 8. |
| **Tunneler version** | `create_tunneler_ctx() Ziti Tunneler SDK (vX.Y.Z)` |
| **Log window** | first and last timestamps |
| **Process identity** | the `[pid]` in each line. If it changes, the service restarted mid-log — split the analysis per process and never carry a conclusion across the boundary. |

Also note the uptime clock: every SDK line carries `(pid)[ seconds.millis]` since process start. That clock
is how you reason about ordering; wall time is how you talk to the customer. Keep both.

### 4. Collapse the log

Two passes. First drop the verbose levels:

```bash
grep -vE ' (DEBUG|TRACE|VERBOSE) ' "$LOG" | tee "$INCIDENT/nondebug.txt" | wc -l
```

Typical reduction is 40,000 → ~1,000. If it is not at least 10×, the log was captured at a lower level and
step 5's absence checks get weaker — note that.

Then normalize the survivors into signatures and count them:

```bash
sed -E 's/^.*\[[0-9]+\]: \([0-9]+\)\[[ 0-9.]+\] +//' "$INCIDENT/nondebug.txt" \
  | sed -E 's/[0-9a-f]{8}-[0-9a-f-]{20,}/UUID/g' \
  | sed -E 's/[0-9]+/N/g' \
  | sort | uniq -c | sort -rn | head -40
```

**Read this histogram before anything else.** A day of healthy operation collapses to a handful of
high-count periodic signatures plus a startup block. Anything with count 1 is either startup or the
incident. The shape of the tail is the diagnosis in outline.

If one repeated signature dominates and is clearly noise, filter it and re-run — do not scroll past it.

### 5. Count what is **absent**

This is the step that distinguishes a real diagnosis from a plausible one, and it is the step everyone
skips. Take the histogram and ask what a healthy log would contain that this one does not.

```bash
grep -cE 'channel\.c|edge_router|router'  "$LOG"   # router channels — 0 means never connected to the mesh
grep -cE 'update_services|service.*added' "$LOG"   # service list ever populated?
grep -c  'context event'                  "$LOG"   # how many ztx state transitions, total?
grep -cE 'posture'                        "$LOG"   # posture responses being submitted?
```

A zero here over a multi-hour window outweighs any error message. "Never connected to a router in 23 hours"
is a finding; "logged CONTROLLER_UNAVAILABLE at startup" is a symptom.

Pay attention to the *count* of state transitions too. A context that emits exactly one event and then goes
quiet for a day is wedged, no matter how healthy every other subsystem looks.

### 6. Histogram the controller requests

The SDK logs every controller call. The set and the counts are a compact description of what the context
believed it was doing:

```bash
grep -E 'start_request\(\)' "$LOG" \
  | sed -E 's/^.*start_request\(\) //' \
  | sed -E 's/[0-9a-f]{8}-[0-9a-f-]{20,}/UUID/g' \
  | sort | uniq -c | sort -rn
```

Interpretation:

- **A double-digit total over many hours means the refresh loop is not running.** A healthy context polls
  `/current-identity`, `/current-edge-routers`, and `/services` on `refresh_interval` forever.
- **One endpoint dominating** is a retry storm, not activity. Go to step 7.
- **A request that appears exactly once** — `/current-api-session`, `/.well-known/est/cacerts` — was fired
  from the post-auth bootstrap and never retried. If it failed that one time, suspect a callback that
  logs-and-returns.

Cross-check against the auth layer, which runs on its own timer and can stay healthy while the context is
dead:

```bash
grep -E 'legacy_auth|oidc|refresh in' "$LOG" | tail -20
```

**Token fresh + controller reachable + zero services is a coherent and common failure state.** Do not let a
healthy auth timer talk you out of a wedged context.

### 7. Bracket every failure with its nearest success

A burst of identical failures invites the conclusion that the underlying condition persisted. It usually
did not. Two questions, both cheap, and each one has overturned a published analysis.

**Where does the storm end?**

```bash
grep -n 'internal_version_cb\|failed: -' "$LOG" | tail -3     # line number of the last failure
sed -n '<that line>,+40p' "$LOG"                              # what came immediately after
```

The last retry in a storm frequently **succeeds** a few hundred milliseconds later. That single line
reframes the incident: the transient condition cleared on its own, and the bug is that nothing resumed.
Analyses that miss it land on "the network was down" for an outage where the network was fine the whole
time.

If a storm ends *without* success, find what stopped it — an exhausted retry budget, a state change, or a
callback that never fired again.

**What is the nearest success against the same target, in either direction?**

Find the closest successful operation on the same host, endpoint, or resource before and after the failure,
and quote the gap in milliseconds. A name that resolved successfully 3 ms before it returned `EAI_NONAME`
is not a DNS outage — it is a race, a handover, or a corrupted request, and the distinction changes both
the root cause and the fix. Report the gap as a number; "transient" is not a measurement.

**Does the iteration count match what the code's backoff implies?**

Count the retries, then read the pacing logic and predict what the count should have been. When the two
disagree, that mismatch is a second defect, not noise:

```bash
grep -c 'attempting to switch endpoint' "$LOG"    # actual
```

38 retries in 50 ms out of code that should have paced them a minute apart is a finding in its own right.
Chase it — it is independent of whatever you were originally diagnosing, and it will not show up any other
way.

**Suspect uptime-clock arithmetic in anything that fires early.** `uv_now()` returns milliseconds since
loop start, not epoch. Any expression of the form `now - SOME_INTERVAL` on an unsigned type underflows to a
huge value for the first `SOME_INTERVAL` of process life, so the comparison guarding it is always true and
the backoff silently does not exist. Startup-window incidents live in this blind spot. Grep the pacing code
for the pattern before you accept that a backoff was in effect:

```bash
grep -nE 'now - [A-Z_]+|uv_now\(.*\) - ' "$INCIDENT"/*.at-build
```

### 8. Open the source at the exact shipped commit

Only now. The log's `file.c:NNN` references are precise pointers, and line numbers drift between releases —
reading `main` will send you to the wrong function and it will look close enough to fool you.

Use the `@g` hash from step 3:

```bash
GIT_DIR=/path/to/ziti-sdk-c/.git git log --oneline -1 <hash>
GIT_DIR=/path/to/ziti-sdk-c/.git git show <hash>:library/ziti.c      | tee "$INCIDENT/ziti.c.at-build"
GIT_DIR=/path/to/ziti-sdk-c/.git git show <hash>:library/ziti_ctrl.c | tee "$INCIDENT/ziti_ctrl.c.at-build"
```

If the commit is not in a local checkout, fetch that ref or read the file at that tag from the forge. Do not
substitute a nearby version without saying so in the report.

Then read *only* the line numbers the log named, and their callers.

### 9. Trace the wedge: ask what arms the retry

For any "it stopped doing X" finding, the mechanical question is: **what schedules X, and who calls it?**

```bash
grep -n 'ziti_services_refresh\|refresh_deadline\|ztx_set_deadline' "$INCIDENT/ziti.c.at-build"
```

Then, for each call site, ask whether an error path can skip it. The recurring bug shape in this codebase:

```c
static void some_cb(result *r, const ziti_error *err, void *ctx) {
    if (err) {
        LOG(ERROR, "...");
        return;                 // <-- nothing rescheduled; the loop dies here
    }
    ...
    schedule_next_refresh(ztx); // <-- only reachable on success
}
```

If the *only* call that arms a timer sits below an early `return`, a single transient error stops that loop
permanently. Confirm it against the log: the request should appear exactly once, and its follow-on requests
never.

Check the layer above too. An auth or session layer that suppresses its "authenticated" callback when
nothing changed cannot restart a bootstrap that failed the first time — which is how a context stays dead
while its token stays fresh.

### 10. Write the report

Structure it so a reader can check you:

1. **Environment** — versions, commit, platform, identity, controller, log window, process continuity.
2. **What the customer reported**, and their timeline in their own terms.
3. **Prior analysis on the ticket**, including where it was wrong and why. Do not quietly overwrite a
   colleague's conclusion; show the evidence that moves it.
4. **What the log contains** — the counts table from steps 4-6, including the zeros. Counts are checkable;
   adjectives are not.
5. **The failure chain**, numbered, each step carrying a timestamp and a `file.c:line` at the build commit.
6. **Fixes**, ranked, each naming the file and function. Say which repo each one belongs in — a tunneler log
   very often describes an SDK bug, and the fix does not land here.
7. **Workaround**, if one exists. The IPC command surface (`RefreshIdentity`, `IdentityOnOff`) can force
   state transitions that a restart would otherwise be needed for — and if the workaround works, it
   confirms the diagnosis.
8. **What is still unverified.** Name every link you did not check. A chain with one honest gap is worth
   more than a seamless story with a silent guess in it.

## Which repo owns the bug

| Symptom | Owner |
|---|---|
| Controller connection, auth, api-session, service list, posture evaluation, router channels, retry and refresh timers | **ziti-sdk-c** (`library/ziti.c`, `ziti_ctrl.c`, `legacy_auth.c`, `oidc.c`, `posture.c`, `channel.c`) |
| Intercept matching, DNS assignment, TCP/UDP proxying, hosting | **ziti-tunnel-sdk-c** (`lib/ziti-tunnel/`, `lib/ziti-tunnel-cbs/`) |
| IPC command handling, event payloads, identity file loading, TUN setup, platform resolver integration | **ziti-edge-tunnel** (`programs/ziti-edge-tunnel/`) |

Rule of thumb: if the log line's prefix is `ziti-sdk:`, the fix is in the C SDK. `tunnel-sdk:` and
`tunnel-cbs:` are this repo. `ziti-edge-tunnel:` is the program.

## Failure modes of this skill

- **Reading top-down.** A 40,000-line log read sequentially costs an enormous amount of context and buries
  the finding. Always collapse first.
- **Stopping at the first error.** The first error is where the chain became visible, not where it started,
  and often not where the bug is.
- **Trusting a retry storm's implication.** Check where it ends, and bracket it with the nearest success in
  each direction (step 7). "Transient" without a measured gap is a guess.
- **Accepting a retry count without predicting it.** If the code says one attempt per minute and the log
  shows 38 in 50 ms, you have found a second bug. Do not round it off to "no backoff."
- **Reading `main` instead of the build commit.** Step 8 is not optional.
- **Believing a healthy subsystem.** A fresh token, a running process, and a reachable controller are
  compatible with a completely dead context.
- **Asserting the historical claim.** "This regressed in version N" requires reading version N-1. If you did
  not, label it as unverified rather than dropping it.
