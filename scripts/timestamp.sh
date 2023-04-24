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

STARTSTAMP=$(grep -Pom1 'starting at \(\K[0-9-]+T[0-9:.]+' "${LOGFILE}")

while read -r; do
    OFFSET=$(grep -Po '^\([0-9]+\)\[(\s+)?\K[0-9.]+' <<< "${REPLY}")
    MESSAGE=$(grep -Po '^\([0-9]+\)\[(\s+)?[0-9.]+(\s+)?\]\K.*' <<< "${REPLY}")
    UTCSTAMP=$(date --utc --date "${STARTSTAMP} +${OFFSET} seconds" +%Y-%m-%dT%H:%M:%S.%3NZ)
    echo "${UTCSTAMP} ${MESSAGE}"
done < "${LOGFILE}"