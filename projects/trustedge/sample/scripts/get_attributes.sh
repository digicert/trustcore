#!/bin/bash

set -e

echo "{"
while test $# -gt 0
do
    case "$1" in
        location)
            VAL="US"
            ;;
        ip_address)
            VAL="127.0.0.1"
            ;;
        *)
            VAL="UNKNOWN"
            ;;
    esac
    if [ "$#" -gt 1 ]; then
        echo "    \"$1\": \"$VAL\","
    else
        echo "    \"$1\": \"$VAL\""
    fi
    shift
done
echo "}"