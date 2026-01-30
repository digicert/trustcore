#!/usr/bin/env bash

echo "Running Unit Test..."
pushd ../../src/crypto/test

../../../bin/crypto_test $@

popd
