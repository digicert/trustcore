#!/usr/bin/env bash

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
cd "${SCRIPT_DIR}/../../src/websocket/testunit" || exit 1

failed=0
all_tests=(test_websocket_frame test_websocket_handshake test_websocket_websocket)
tests=("${all_tests[@]}")
if (( $# > 0 )); then
    tests=("$@")
fi

for test in "${tests[@]}"; do
    # Only known suite names may be executed
    if [[ ! " ${all_tests[*]} " =~ " ${test} " ]]; then
        echo "Unknown test suite: ${test}" >&2
        failed=1
        continue
    fi

    if [[ ! -x "${test}" ]]; then
        echo "Missing test binary: ${test}" >&2
        failed=1
        continue
    fi

    echo "> Executing ${test}"
    if ! "./${test}"; then
        echo "${test} failed" >&2
        failed=1
    fi
done

if (( failed != 0 )); then
    echo "NanoWS unit tests failed" >&2
    exit 1
fi

echo "All NanoWS unit tests passed"
