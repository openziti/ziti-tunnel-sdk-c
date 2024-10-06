#!/usr/bin/env bash
#
# create a debug bundle for systemd service unit ziti-edge-tunnel.service
#
# usage: sudo /opt/openziti/bin/debug.bash [UPLOAD_URL]

set -o errexit
set -o nounset
set -o pipefail

checkCommand() {
    if ! command -v "$1" &>/dev/null; then
        echo "NOTICE: install '$1' and try again." >&2
        $1
    fi
}

main() {
    # require commands
    declare -a BINS=(sed gdb strace tar timeout /opt/openziti/bin/ziti-edge-tunnel systemctl journalctl)
    for BIN in "${BINS[@]}"; do
        checkCommand "$BIN"
    done

    cd "$(mktemp -d)"
    mkdir ./dump ./stack ./backtrace
    chgrp -R ziti "${PWD}"
    chmod -R g+rwX "${PWD}"
    
    echo -n "(estimated runtime 60s) [."
    
    NOW=$(date -u +'%Y-%m-%dT%H:%MZ')
    ZITI_VERSION=$(/opt/openziti/bin/ziti-edge-tunnel version)
    PREFIX=ziti-edge-tunnel-${ZITI_VERSION#v}-${NOW}
    LOG_FILE=${PREFIX}.log
    STRACE_FILE=${PREFIX}.strace
    TUNNEL_STATUS_FILE=${PREFIX}.tunnel_status.json
    SYSTEMD_RESOLVED_FILE=${PREFIX}.systemd-resolved
    HOST_INFO_FILE=${PREFIX}.host
    TARBALL=${PREFIX}.tgz
    
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
        resolvectl dns
        resolvectl domain
        ls -l /etc/resolv.conf
        cat /etc/resolv.conf
    ) &> "${SYSTEMD_RESOLVED_FILE}"
    echo -n "."
    
    # save host info
    (
        set +e
        set -x
        hostnamectl; hostname
        ip link show; ip addr show; ip route show
        cat /etc/hosts /etc/*-release
    ) &> "${HOST_INFO_FILE}"
    echo -n "."
    
    # save the current service unit invocation's log messages
    journalctl _SYSTEMD_INVOCATION_ID="$(systemctl show -p InvocationID --value ziti-edge-tunnel.service)" -l --no-pager \
    &> "${LOG_FILE}"
    echo -n "."

    # save the call stack at intervals
    BTRACE_COUNT=1
    # allow parent env to override max count
    : "${BTRACE_MAX:=10}"
    BTRACE_MAX_LEN=$(( $(wc -c <<< "${BTRACE_MAX}") - 1 ))
    # compare decimal form of iterator to decimal max
    until [[ "10#${BTRACE_COUNT}" -gt "${BTRACE_MAX}" ]]
    do
        # save the threads and backtrace
        timeout --kill-after=1s 3s \
            gdb /opt/openziti/bin/ziti-edge-tunnel \
                --pid "${ZET_PID}" \
                --batch \
                --ex "set sysroot /" \
                --ex "set verbose on" \
                --ex "set pagination off" \
                --ex "info threads" \
                --ex "thread apply all backtrace" \
                --ex "quit" \
            &> "./backtrace/${BTRACE_COUNT}_of_${BTRACE_MAX}-$(date -u +'%Y-%m-%dT%H:%M:%SZ').backtrace" \
            || echo "WARN: gdb backtrace timed out" >&2
        echo -n "."
        sleep 1
        # increment decimal form of iterator
        BTRACE_COUNT=$((10#${BTRACE_COUNT} + 1))
        # pad the decimal form of iterator for filename sorting
        BTRACE_COUNT=$(printf "%0${BTRACE_MAX_LEN}d" "${BTRACE_COUNT}")
    done

    # save 10s of strace calls
    timeout --kill-after=1s 10s \
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
    echo -n "."
    
    # save the call stack at intervals
    STACK_COUNT=1
    # allow parent env to override max count
    : "${STACK_MAX:=3}"
    # find width of decimal max
    STACK_MAX_LEN=$(( $(wc -c <<< "${STACK_MAX}") - 1 ))
    # compare decimal form of iterator to decimal max
    until [[ "10#${STACK_COUNT}" -gt "${STACK_MAX}" ]]
    do
        cat "/proc/${ZET_PID}/stack" \
        > "./stack/${STACK_COUNT}_of_${STACK_MAX}-$(date -u +'%Y-%m-%dT%H:%M:%SZ').stack"
        echo -n "."
        # shellcheck disable=SC2034 # iterator is unused
        for i in {1..10}; do sleep 1; echo -n "."; done
        # increment decimal form of iterator
        STACK_COUNT=$((10#${STACK_COUNT} + 1))
        # pad the decimal form of iterator for filename sorting
        STACK_COUNT=$(printf "%0${STACK_MAX_LEN}d" "${STACK_COUNT}")
    done
    
    # save the identity status dumps
    timeout --kill-after=1s 3s \
        ziti-edge-tunnel dump -p ./dump >/dev/null \
        || echo "WARN: failed to create dumps" >&2
    echo -n "."
    
    # save the tunnel_status JSON
    timeout --kill-after=1s 3s \
        ziti-edge-tunnel tunnel_status \
        | sed -E "s/(^received\sresponse\s<|>$)//g" > "${TUNNEL_STATUS_FILE}" \
        || echo "WARN: failed to get tunnel_status" >&2
    echo -n "."
    
    tar -czf "/tmp/${TARBALL}" .
    echo -en ".]\n"
    
    echo "INFO: debug bundle created at /tmp/${TARBALL} from files in ${PWD}"

    if [[ -n "${1:-}" ]]
    then
        echo "INFO: uploading debug bundle to ${1}"
        curl -sSf -T "/tmp/${TARBALL}" "${1}"
    fi
}

main "$@"
