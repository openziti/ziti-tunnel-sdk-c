# debug ziti-edge-tunnel log

A Claude Code skill for diagnosing `ziti-edge-tunnel` logs — a `journalctl` capture, a rolled log file, or an IPC
dump, from Linux, macOS, or Windows.

## Why it exists

At `--verbose=4` the tunneler writes tens of thousands of lines a day, and the great majority of it is DNS-resolver
chatter. Reading such a log front to back is slow, expensive, and tends to stop at the first loud error — which is
usually a symptom several steps downstream of the actual bug, and sometimes a red herring entirely.

The interesting failures in this stack are rarely loud. They are things the tunneler **stopped doing**: a refresh
timer that was never re-armed, a bootstrap that failed once and was never retried, a router channel that was never
opened. You find those by collapsing the log until it fits on a screen and then asking what is missing from it.

## What it does

1. Locates the log, from a path or a support ticket.
2. Puts every artifact in one per-incident directory, outside the repository tree.
3. Establishes the frame — SDK version and **build commit**, tunneler version, log window, process continuity.
4. Collapses the log: strips verbose levels, then normalizes what remains into a counted signature histogram.
5. Counts what is **absent** — zero router channels over a multi-hour window outweighs any error message.
6. Histograms the controller requests, which describes what the context believed it was doing.
7. Brackets every failure with its nearest success. The last retry in a storm often succeeds, which reframes the whole
   incident; a name that resolved 3 ms before it failed is a race, not an outage; and a retry count that disagrees
   with the code's own backoff is a second bug.
8. Opens `ziti-sdk-c` at the exact commit the binary was built from, because logged line numbers drift between
   releases.
9. Traces the wedge by asking what arms the retry timer and which error paths skip it.
10. Writes a report structured so a reader can check the work, including a list of what was left unverified.

## Install

Symlink it into your Claude Code skills directory:

```bash
ln -s "$(pwd)/docs/troubleshooting/debug-skill" ~/.claude/skills/debug-ziti-edge-tunnel-log
```

Then invoke it:

```
/debug ziti-edge-tunnel log /path/to/journalctl-ziti.out
/debug ziti-edge-tunnel log 12345          # a ticket number, if a support-desk integration is available
```

## Configuration

`ZITI_SUPPORT_DIR` sets the base directory for downloaded attachments, decompressed logs, and the write-up. Each
incident gets a subdirectory under it. Defaults to `$TMPDIR/ziti-support`. Export it once if you triage regularly, so
everything lands where you already look.

## Scope

Covers `ziti-edge-tunnel` and the embedded C SDK. Bugs found this way frequently belong in `ziti-sdk-c` rather than
this repository; the skill includes a table for attributing a finding to the right repo from the log line's prefix.

It does not cover the Windows desktop client's feedback bundles, which are a different collection format.

## A caution

Tunneler logs are customer data — controller URLs, identity names, internal hostnames, service names, and intercept
addresses, plus session state in any IPC dump. Redact before anything goes into a public issue.
