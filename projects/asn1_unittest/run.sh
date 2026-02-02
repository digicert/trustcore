#!/usr/bin/env bash

echo "Running Unit Test..."
pushd ../../src/asn1/test

../../../bin/asn1_test $@

popd

