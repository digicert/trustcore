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
pushd ${SCRIPT_DIR}/../../src/mqtt/testunit

STREAMING_MODE=false
for arg in "$@"; do
    if [ "$arg" == "--streaming" ]; then
        STREAMING_MODE=true
        shift
        break
    fi
done

if [ "$STREAMING_MODE" == "true" ]; then
    if [ -f "./test_mqtt_msg_streaming" ]; then
        if [ -n "$(find . -maxdepth 1 -type f -executable | grep -v streaming)" ]; then
            echo "WARNING: Both streaming and non-streaming binaries exist"
            echo "         If you recently switched build modes, consider cleaning"
            echo ""
        fi

        echo "> Executing test_mqtt_msg_streaming"
        ./test_mqtt_msg_streaming
        if [ $? -ne 0 ]; then
            echo "test_mqtt_msg_streaming failed"
            TEST_FAILED=true
        fi
    else
        echo "INFO: --streaming flag specified but test_mqtt_msg_streaming binary not found"
        echo "      Ignoring --streaming flag"
        echo ""
        STREAMING_MODE=false
    fi
fi

if [ "$STREAMING_MODE" == "false" ]; then
    if [ $# -eq 0 ]; then
        tests=$(find . -maxdepth 1 -type f -executable | grep -v streaming)

        if [ -z "$tests" ]; then
            if [ -f "./test_mqtt_msg_streaming" ]; then
                echo "INFO: Streaming binary detected"
                echo "      To run streaming tests, use: ./run.sh --streaming"
                popd
                exit 0
            else
                echo "ERROR: No test binaries found"
                popd
                exit 1
            fi
        fi

        if [ -f "./test_mqtt_msg_streaming" ] && [ -n "$tests" ]; then
            echo "WARNING: Both streaming and non-streaming binaries exist"
            echo "         If you recently switched build modes, consider cleaning"
            echo ""
        fi

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
fi
popd

if [ "$TEST_FAILED" == true ]; then
    echo "Unit Test Failed"
    exit 1
fi

echo ""
echo "All tests passed!"
exit 0