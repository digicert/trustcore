#!/usr/bin/env bash

SCRIPT_DIR=$( cd $(dirname $0) ; pwd -P )

if [[ $(uname -m) == "aarch64" ]]; then
    CRYPTO_ARCH="aarch64"
else
    CRYPTO_ARCH="linux-x86_64"
fi

# Set library path for both Mocana and crypto libraries
export LD_LIBRARY_PATH=${SCRIPT_DIR}/../../lib:${SCRIPT_DIR}/../../crypto_lib/${CRYPTO_ARCH}:$LD_LIBRARY_PATH
TEST_FAILED=false
echo "Running Unit Test..."
pushd ${SCRIPT_DIR}/../../src/ssh/testunit

if [ $# -eq 0 ]; then
    tests=$(find . -maxdepth 1 -type f -executable | grep -v streaming)

    while IFS= read -r cur_test; do
        echo ""
        echo "> Executing $cur_test"
        ./$cur_test
        if [ $? -ne 0 ]; then
            echo "$cur_test failed"
            TEST_FAILED=true
        fi
    done <<< "$tests"
else
    for cur_test in "$@"; do
        echo ""
        echo "> Executing $cur_test"
        ./$cur_test
        if [ $? -ne 0 ]; then
            echo "$cur_test failed"
            TEST_FAILED=true
        fi
    done
fi
popd

if [ "$TEST_FAILED" == true ]; then
    echo "Unit Test Failed"
    exit 1
fi


