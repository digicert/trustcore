#!/usr/bin/env bash

# Place us in the dir of this script
cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null

echo "Running Unit Test..."
pushd ../../src/crypto/test

valgrind --leak-check=full ../../../bin/crypto_interface_test $@

popd
