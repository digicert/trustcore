#!/usr/bin/env bash

echo "Running Unit Test..."
pushd ../../src/common/test

../../../bin/common_test $@

popd

