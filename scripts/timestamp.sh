#!/usr/bin/env bash
#
# parse a log file with GNU date to convert ss.mmm offset to UTC timestamp
# hint: avoid needing this script by setting ZITI_TIME_FORMAT=utc in ziti-edge-tunnel env
#
# usage: timestamp.sh LOGFILE

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
    grep -qP '^\([0-9]+\)\[(\s+)?\K[0-9.]+' <<< "${REPLY}" || continue
    OFFSET=$(grep -Po '^\([0-9]+\)\[(\s+)?\K[0-9.]+' <<< "${REPLY}")
    MESSAGE=$(grep -Po '^\([0-9]+\)\[(\s+)?[0-9.]+(\s+)?\]\K.*' <<< "${REPLY}")
    UTCSTAMP=$(date --utc --date "${REALSTARTSTAMP} +${OFFSET} seconds" +%Y-%m-%dT%H:%M:%S.%3NZ)
    echo "${UTCSTAMP} ${MESSAGE}"
done < "${LOGFILE}"
