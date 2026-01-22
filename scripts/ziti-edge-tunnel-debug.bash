#!/usr/bin/env bash
#
# create a debug bundle for systemd service unit ziti-edge-tunnel.service
#
# usage: sudo /opt/openziti/bin/ziti-edge-tunnel-debug.bash [UPLOAD_URL]

set -o errexit
set -o nounset
set -o pipefail

checkCommand() {
    local optional=false
    if [[ "$1" == "--optional" ]]; then
        optional=true
        shift
    fi
    
    if ! command -v "$1" &>/dev/null; then
        if [[ "$optional" == "true" ]]; then
            echo "WARNING: '$1' is needed to enrich debug output. Install it for enhanced functionality." >&2
            return 0
        else
            echo "ERROR: '$1' is required but not installed. Please install it and try again." >&2
            exit 1
        fi
    fi
}

main() {
    # require commands
    declare -a BINS=(sed tar timeout /opt/openziti/bin/ziti-edge-tunnel systemctl journalctl)
    for BIN in "${BINS[@]}"; do
        checkCommand "$BIN"
    done
    
    # optional commands that enhance functionality
    declare -a OPT_BINS=(lsof gdb strace curl resolvectl)
    for BIN in "${OPT_BINS[@]}"; do
        checkCommand --optional "$BIN"
    done

    cd "$(mktemp -d)"
    mkdir ./dump
    chgrp -R ziti "${PWD}"
    chmod -R g+rwX "${PWD}"
    
    echo -n "(estimated runtime 60s) [."
    
    NOW=$(date -u +'%Y-%m-%dT%H:%MZ')
    SYSTEMD_SERVICE_UNIT="ziti-edge-tunnel.service"
    SYSTEMD_ENV_FILE="/opt/openziti/etc/ziti-edge-tunnel.env"
    ZITI_VERSION=$(/opt/openziti/bin/ziti-edge-tunnel version)
    PREFIX=ziti-edge-tunnel-${ZITI_VERSION#v}-${NOW}
    LOG_FILE=${PREFIX}.log
    STRACE_FILE=${PREFIX}.strace
    TUNNEL_STATUS_FILE=${PREFIX}.tunnel_status.json
    SYSTEMD_RESOLVED_FILE=${PREFIX}.systemd-resolved
    HOST_INFO_FILE=${PREFIX}.host
    OPEN_FILES_FILE=${PREFIX}.open_files
    TARBALL=${PREFIX}.tgz
    
    # get the aggregate service unit definition
    # shellcheck disable=SC2094
    systemctl cat "${SYSTEMD_SERVICE_UNIT}" > "${SYSTEMD_SERVICE_UNIT}"
    if [[ -s "${SYSTEMD_ENV_FILE}" ]]; then
        cp "${SYSTEMD_ENV_FILE}" .
    fi


    # get the PID from systemd
    ZET_PID="$(systemctl show -p MainPID --value "${SYSTEMD_SERVICE_UNIT}")"
    if [[ -z "${ZET_PID}" ]] || [[ "${ZET_PID}" == "0" ]];
    then
        echo -e "\nERROR: failed to get ${SYSTEMD_SERVICE_UNIT} PID\n" >&2
        exit 1
    fi
    
    # save the systemd-resolved state
    (
        set +e
        set -x
        systemctl status systemd-resolved.service
        if command -v resolvectl &>/dev/null; then
            resolvectl status
            resolvectl dns
            resolvectl domain
        else
            echo "resolvectl not available"
        fi
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
    
    # save open files and socket information with peer addresses from /proc
    # This provides detailed information about all open file descriptors including
    # network sockets with their peer addresses, Unix sockets, pipes, and regular files
    (
        set +e
        set +x
        
        # Create a temporary file to collect all data before formatting
        temp_file=$(mktemp)
        
        # First, capture summary if lsof is available
        if command -v lsof &>/dev/null; then
            LSOF_DNS_TIMEOUT_SECONDS=10
            lsof_tmp=$(mktemp)
            lsof_rc=0
            lsof_dns_timed_out=false

            if command -v timeout &>/dev/null; then
                timeout "${LSOF_DNS_TIMEOUT_SECONDS}s" lsof -Pp "$ZET_PID" &>"$lsof_tmp"
                lsof_rc=$?
            else
                lsof -Pp "$ZET_PID" &>"$lsof_tmp"
                lsof_rc=$?
            fi

            if [[ $lsof_rc -eq 124 ]]; then
                lsof_dns_timed_out=true
                echo "WARNING: lsof DNS resolution took longer than ${LSOF_DNS_TIMEOUT_SECONDS}s; re-running with -n (no name resolution)." >&2
                lsof -nPp "$ZET_PID" &>"$lsof_tmp"
                lsof_rc=$?
            fi

            lsof_output=$(cat "$lsof_tmp")
            rm -f "$lsof_tmp"
            
            # Total open files
            total_open=$(echo "$lsof_output" | wc -l)
            
            # Count by file types
            sock_count=$(echo "$lsof_output" | awk '$5 ~ /IPv[46]/ {count++} END {print count+0}')
            unix_count=$(echo "$lsof_output" | awk '$5 == "unix" {count++} END {print count+0}')
            file_count=$(echo "$lsof_output" | awk '$5 ~ /REG|DIR|LINK/ {count++} END {print count+0}')
            
            # Get truncated command
            cmd=$(ps -o args= -p "$ZET_PID" 2>/dev/null | sed 's|/opt/openziti/bin/||' | cut -d' ' -f1 || echo "unknown")
            
            # Print summary at the top
            echo -e "=== Summary ==="
            {
                echo -e "Open\tSock\tUnix\tFile\tCommand"
                printf '%d\t%d\t%d\t%d\t%s\n' "$total_open" "$sock_count" "$unix_count" "$file_count" "$cmd"
            } | column -t -s $'\t'
            echo ""
        else
            cmd=$(ps -o args= -p "$ZET_PID" 2>/dev/null | sed 's|/opt/openziti/bin/||' | cut -d' ' -f1 || echo "unknown")
            fd_listing=$(ls -l "/proc/${ZET_PID}/fd" 2>/dev/null | sed '1d')
            total_open=$(echo "$fd_listing" | wc -l)
            sock_count=$(echo "$fd_listing" | grep -c 'socket:\[' || true)

            echo "=== Summary ==="
            {
                echo -e "Open\tSock\tUnix\tFile\tCommand"
                printf '%d\t%d\t%s\t%s\t%s\n' "$total_open" "$sock_count" "-" "-" "$cmd"
            } | column -t -s $'\t'
            echo ""
        fi

        echo -e "=== Open Sockets ==="

        PEER_DNS_TIMEOUT_SECONDS=10
        peer_dns_enabled=false
        peer_dns_timed_out=false
        if command -v getent &>/dev/null; then
            peer_dns_enabled=true
        fi
        
        # Iterate through all file descriptors
        for fd_dir in "/proc/${ZET_PID}/fd"/*; do
            if [[ ! -e "$fd_dir" ]]; then
                continue
            fi
            
            fd=$(basename "$fd_dir")
            
            # Get file descriptor info
            fd_info=$(readlink "$fd_dir" 2>/dev/null || echo "deleted")
            
            # Get file descriptor flags from fdinfo
            fd_mode=""
            if [[ -f "/proc/${ZET_PID}/fdinfo/$fd" ]]; then
                fd_mode=$(grep "^flags:" "/proc/${ZET_PID}/fdinfo/$fd" 2>/dev/null | cut -f2- | sed 's/flags://;s/^ *//' || echo "")
            fi
            
            # Initialize variables
            fd_type="unknown"
            inode=""
            peer_addr=""
            peer_name=""
            peer_port=""
            path=""
            
            # Determine file type and extract details
            case "$fd_info" in
                socket:\[*\])
                    fd_type="socket"
                    # Extract inode from socket:[12345]
                    inode=$(echo "$fd_info" | sed 's/socket:\[\([0-9]*\)\]/\1/')
                    path="socket:[$inode]"
                    
                    # Get socket details from /proc/net/tcp
                    if [[ -f "/proc/net/tcp" ]]; then
                        # Look up socket in /proc/net/tcp (hex format)
                        socket_info=$(awk -v inode="$inode" '$10 == inode {print}' /proc/net/tcp 2>/dev/null | head -1)
                        if [[ -n "$socket_info" ]]; then
                            # Parse the socket info
                            # Format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
                            local_addr=$(echo "$socket_info" | awk '{print $2}')
                            rem_addr=$(echo "$socket_info" | awk '{print $3}')
                            
                            # Convert hex addresses to readable format
                            if [[ "$rem_addr" != "00000000:0000" ]]; then
                                # Convert remote address
                                hex_ip=$(echo "$rem_addr" | cut -d: -f1)
                                hex_port=$(echo "$rem_addr" | cut -d: -f2)
                                
                                # Convert hex IP to decimal
                                dec_ip=$(printf "%d.%d.%d.%d" 0x${hex_ip:6:2} 0x${hex_ip:4:2} 0x${hex_ip:2:2} 0x${hex_ip:0:2})
                                # Convert hex port to decimal
                                dec_port=$((0x$hex_port))
                                
                                peer_addr="$dec_ip"
                                peer_port="$dec_port"
                            fi
                        fi
                    fi
                    
                    # Also check /proc/net/tcp6 for IPv6 sockets
                    if [[ -z "$peer_addr" && -f "/proc/net/tcp6" ]]; then
                        socket_info=$(awk -v inode="$inode" '$10 == inode {print}' /proc/net/tcp6 2>/dev/null | head -1)
                        if [[ -n "$socket_info" ]]; then
                            local_addr=$(echo "$socket_info" | awk '{print $2}')
                            rem_addr=$(echo "$socket_info" | awk '{print $3}')
                            
                            if [[ "$rem_addr" != "00000000000000000000000000000000:0000" ]]; then
                                hex_ip=${rem_addr%:*}
                                hex_port=${rem_addr#*:}

                                # Convert IPv6 hex (32 nybbles) into 8 hextets
                                peer_addr=$(echo "$hex_ip" | sed 's/\(.\{4\}\)/\1:/g; s/:$//' | tr '[:upper:]' '[:lower:]')
                                dec_port=$((0x$hex_port))
                                peer_port="$dec_port"
                            fi
                        fi
                    fi
                    
                    # Check for Unix domain sockets
                    if [[ -z "$peer_addr" && -f "/proc/net/unix" ]]; then
                        unix_info=$(awk -v inode="$inode" '$7 == inode {print}' /proc/net/unix 2>/dev/null | head -1)
                        if [[ -n "$unix_info" ]]; then
                            # Format: Num RefCount Flags Protocol Type Inode Path
                            unix_path=$(echo "$unix_info" | awk '{print $8}')
                            if [[ -n "$unix_path" ]]; then
                                peer_addr="unix:$unix_path"
                            else
                                peer_addr="-"
                            fi
                            peer_port=""
                        fi
                    fi
                    ;;
                pipe:\[*\])
                    fd_type="pipe"
                    inode=$(echo "$fd_info" | sed 's/pipe:\[\([0-9]*\)\]/\1/')
                    path="pipe:[$inode]"
                    ;;
                anon_inode:\[*\])
                    fd_type="anon_inode"
                    path=$(echo "$fd_info" | sed 's/anon_inode:\[\(.*\)\]/\1/')
                    ;;
                /dev/*)
                    fd_type="dev"
                    path="$fd_info"
                    # Get inode from stat for device files
                    if [[ -e "$fd_dir" ]]; then
                        inode=$(stat -c "%i" "$fd_dir" 2>/dev/null || echo "")
                    fi
                    ;;
                /*)
                    fd_type="file"
                    path="$fd_info"
                    # Get inode from stat
                    if [[ -e "$fd_dir" ]]; then
                        inode=$(stat -c "%i" "$fd_dir" 2>/dev/null || echo "")
                    fi
                    ;;
                *)
                    fd_type="other"
                    path="$fd_info"
                    ;;
            esac
            
            # Get the command (truncated for readability)
            cmd=$(ps -o args= -p "$ZET_PID" 2>/dev/null | sed 's|/opt/openziti/bin/||' | cut -d' ' -f1 || echo "unknown")

            # Ensure stable columns (avoid empty fields collapsing in `column`)
            out_peer_addr=${peer_addr:-"-"}
            out_peer_name=${peer_name:-"-"}
            out_peer_port=${peer_port:-"-"}
            
            # Keep this table focused on sockets
            if [[ "$fd_type" != "socket" ]]; then
                continue
            fi

            # Attempt to resolve peer address (one-time timeout disables further lookups)
            if [[ "${peer_dns_enabled}" == "true" && "${peer_dns_timed_out}" != "true" ]]; then
                if [[ -n "${peer_addr}" && "${peer_addr}" != "-" && "${peer_addr}" != unix:* ]]; then
                    if command -v timeout &>/dev/null; then
                        resolved_line=$(timeout "${PEER_DNS_TIMEOUT_SECONDS}s" getent hosts "${peer_addr}" 2>/dev/null)
                        rc=$?
                        if [[ $rc -eq 124 ]]; then
                            peer_dns_timed_out=true
                            echo "WARNING: peer DNS resolution took longer than ${PEER_DNS_TIMEOUT_SECONDS}s; continuing without name resolution." >&2
                        else
                            resolved_name=$(echo "$resolved_line" | awk '{print $2}' | head -1)
                            if [[ -n "$resolved_name" ]]; then
                                out_peer_name="$resolved_name"
                            fi
                        fi
                    else
                        resolved_line=$(getent hosts "${peer_addr}" 2>/dev/null)
                        resolved_name=$(echo "$resolved_line" | awk '{print $2}' | head -1)
                        if [[ -n "$resolved_name" ]]; then
                            out_peer_name="$resolved_name"
                        fi
                    fi
                fi
            fi

            # Write to temp file
            printf '%s\t%s\t%s\n' \
                "$out_peer_name" "$out_peer_addr" "$out_peer_port" >> "$temp_file"
        done
        
        # Format detailed list with column (include header in same formatter for alignment)
        {
            echo -e "PeerName\tPeerAddr\tPeerPort"
            cat "$temp_file"
        } | column -t -s $'\t'
        rm -f "$temp_file"
        
    ) &> "${OPEN_FILES_FILE}"
    echo -n "."
    
    # save the current service unit invocation's log messages
    journalctl _SYSTEMD_INVOCATION_ID="$(systemctl show -p InvocationID --value "${SYSTEMD_SERVICE_UNIT}")" -l --no-pager \
    &> "${LOG_FILE}"
    echo -n "."

    # if stack then save it; else try backtrace
    if [[ -s "/proc/${ZET_PID}/stack" ]]; then
        mkdir ./stack
        # save the call stack at intervals
        STACK_COUNT=1
        # allow parent env to override max count
        : "${STACK_MAX:=3}"
        # find width of decimal max
        STACK_MAX_LEN=$(( $(wc -c <<< "${STACK_MAX}") - 1 ))
        # compare decimal form of iterator to decimal max
        until [[ "10#${STACK_COUNT}" -gt "${STACK_MAX}" ]]
        do
            STACK_TIME=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
            STACK_DIR="./stack/${STACK_COUNT}_of_${STACK_MAX}-${STACK_TIME}"
            mkdir "${STACK_DIR}"
            cat "/proc/${ZET_PID}/stack" > "${STACK_DIR}/stack"

            # Capture threads' stacks if task directory exists
            if [[ -d "/proc/${ZET_PID}/task" ]]; then
                mkdir -p "${STACK_DIR}/task"
                for TID_DIR in "/proc/${ZET_PID}/task/"*; do
                    TID=$(basename "${TID_DIR}")
                    cat "${TID_DIR}/stack" > "${STACK_DIR}/task/${TID}.stack"
                done
            fi
            echo -n "."
            # shellcheck disable=SC2034 # iterator is unused
            for i in {1..10}; do sleep 1; echo -n "."; done
            # increment decimal form of iterator
            STACK_COUNT=$((10#${STACK_COUNT} + 1))
            # pad the decimal form of iterator for filename sorting
            STACK_COUNT=$(printf "%0${STACK_MAX_LEN}d" "${STACK_COUNT}")
        done
    else
        echo -e "\nWARN: failed to get call stack in /proc/${ZET_PID}/stack because it doesn't exist or is empty\n" >&2
    fi

    if command -v gdb &>/dev/null; then
        mkdir ./backtrace
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
                || echo -e "\nWARN: gdb backtrace timed out\n" >&2
            echo -n "."
            sleep 1
            # increment decimal form of iterator
            BTRACE_COUNT=$((10#${BTRACE_COUNT} + 1))
            # pad the decimal form of iterator for filename sorting
            BTRACE_COUNT=$(printf "%0${BTRACE_MAX_LEN}d" "${BTRACE_COUNT}")
        done
    fi

    if command -v strace &>/dev/null; then
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
    fi

    # save the identity status dumps
    timeout --kill-after=1s 3s \
        ziti-edge-tunnel dump -p ./dump >/dev/null \
        || echo -e "\nWARN: failed to create dumps\n" >&2
    echo -n "."
    
    # save the tunnel_status JSON
    timeout --kill-after=1s 3s \
        ziti-edge-tunnel tunnel_status \
        | sed -E "s/(^received\sresponse\s<|>$)//g" > "${TUNNEL_STATUS_FILE}" \
        || echo -e "\nWARN: failed to get tunnel_status\n" >&2
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
