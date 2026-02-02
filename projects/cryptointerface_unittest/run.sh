#!/usr/bin/env bash

# Place us in the dir of this script
cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null

echo "Running Unit Test..."
pushd ../../src/crypto/test

../../../bin/crypto_interface_test $@
EXIT_CODE=$?

popd

if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ Unit Test Passed."
else
    echo "❌ Unit Test Failed."
fi

exit $EXIT_CODE
