#!/usr/bin/env bash
set -euo pipefail

(( ${#} )) && {
    LOGFILE="${1}"
    shift
}

(( ${#} )) && {
    echo "ERROR: too many arguments" >&2
    exit 1
}

command -v gdate &>/dev/null && {
    date() {
        gdate "${@}"
    }
}

STARTSTAMP_LINE=$(grep -Pm1 'starting at \([0-9-]+T[0-9:.]+\)' "${LOGFILE}")
STARTOFFSET=$(grep -Po '^\([0-9]+\)\[(\s+)?\K[0-9.]+' <<< "${STARTSTAMP_LINE}")
STARTSTAMP=$(grep -Po 'starting at \(\K[0-9-]+T[0-9:.]+' <<< "${STARTSTAMP_LINE}")
REALSTARTSTAMP=$(date --utc --date "${STARTSTAMP} -${STARTOFFSET} seconds" +%Y-%m-%dT%H:%M:%S.%3NZ)

while read -r; do
    OFFSET=$(grep -Po '^\([0-9]+\)\[(\s+)?\K[0-9.]+' <<< "${REPLY}")
    MESSAGE=$(grep -Po '^\([0-9]+\)\[(\s+)?[0-9.]+(\s+)?\]\K.*' <<< "${REPLY}")
    UTCSTAMP=$(date --utc --date "${REALSTARTSTAMP} +${OFFSET} seconds" +%Y-%m-%dT%H:%M:%S.%3NZ)
    echo "${UTCSTAMP} ${MESSAGE}"
done < "${LOGFILE}"