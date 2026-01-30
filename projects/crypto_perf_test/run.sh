#!/usr/bin/env bash

echo "Running Unit Test..."
pushd ../../src/crypto/perf_test

../../../bin/crypto_perf_test $@

popd
