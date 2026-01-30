#!/usr/bin/env bash

echo "Running Unit Test..."
pushd ../../src/crypto/interop_test

../../../bin/crypto_interop_test $@

popd
