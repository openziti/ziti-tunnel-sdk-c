#!/usr/bin/env bash
#
# this script creates a debug bundle for systemd service unit ziti-edge-tunnel.service
#

set -euo pipefail

cd "$(mktemp -d)"
mkdir ./dumps
chgrp -R ziti "${PWD}"
chmod -R g+rwX "${PWD}"

NOW="$(date -u +'%Y-%m-%dT%H:%MZ')"
ZITI_VERSION=$(/opt/openziti/bin/ziti-edge-tunnel version)
LOG_FILE=ziti-edge-tunnel-${ZITI_VERSION#v}-${NOW}.log
BACKTRACE_FILE=ziti-edge-tunnel-${ZITI_VERSION#v}-${NOW}.backtrace
STRACE_FILE=ziti-edge-tunnel-${ZITI_VERSION#v}-${NOW}.strace
TUNNEL_STATUS_FILE=ziti-edge-tunnel-${ZITI_VERSION#v}-${NOW}.tunnel_status.json
SYSTEMD_RESOLVED_FILE=ziti-edge-tunnel-${ZITI_VERSION#v}-${NOW}.systemd-resolved
TARBALL=ziti-edge-tunnel-${ZITI_VERSION#v}-${NOW}.tgz

# get the PID from systemd
ZET_PID="$(systemctl show -p MainPID --value ziti-edge-tunnel.service)"
if [[ -z "${ZET_PID}" ]] || [[ "${ZET_PID}" == "0" ]];
then
    echo "ERROR: failed to get ziti-edge-tunnel.service PID" >&2
    exit 1
fi

# save the systemd-resolved state
(
    set +e
    set -x
    systemctl status systemd-resolved.service
    resolvectl status
    resolvectl dns ziti0
    resolvectl domain ziti0
    ls -l /etc/resolv.conf
    cat /etc/resolv.conf
) &> "${SYSTEMD_RESOLVED_FILE}"

# save the current service unit invocation's log messages
journalctl _SYSTEMD_INVOCATION_ID="$(systemctl show -p InvocationID --value ziti-edge-tunnel.service)" -l --no-pager \
&> "${LOG_FILE}"

# save the threads and backtrace
timeout --signal=SIGKILL 3s \
    gdb /opt/openziti/bin/ziti-edge-tunnel \
        --pid "${ZET_PID}" \
        --batch \
        --ex "set verbose on" \
        --ex "set pagination off" \
        --ex "info threads" \
        --ex "backtrace" \
        --ex "quit" \
    &> "${BACKTRACE_FILE}" \
    || echo "WARN: gdb backtrace timed out" >&2

# save 10s of strace calls
timeout --signal=SIGKILL 10s \
    strace --attach "${ZET_PID}" \
        --follow-forks \
        --absolute-timestamps=format:unix,precision:us \
        --syscall-times \
        --string-limit 4096 \
    &> "${STRACE_FILE}" \
    || true  # catch the expected timeout exit code
        # --trace=%network \
        # --trace=%process \
        # --trace=%signal \
        # --trace=%ipc \
        # --trace=%desc \
        # --trace=%memory \

# save the identity status dumps
timeout --signal=SIGKILL 3s \
    ziti-edge-tunnel dump -p ./dumps >/dev/null \
    || echo "WARN: failed to create dumps" >&2

# save the tunnel_status JSON
timeout --signal=SIGKILL 3s \
    ziti-edge-tunnel tunnel_status \
    | sed -E "s/(^received\sresponse\s<|>$)//g" > "${TUNNEL_STATUS_FILE}" \
    || echo "WARN: failed to get tunnel_status" >&2

tar -czf "/tmp/${TARBALL}" .

echo "INFO: debug bundle created at /tmp/${TARBALL} from files in ${PWD}"
