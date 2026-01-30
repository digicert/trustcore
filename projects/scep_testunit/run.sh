#!/usr/bin/env bash

SCRIPT_DIR=$( cd $(dirname $0) ; pwd -P )

echo "Running SCEP Tests..."

pushd ${SCRIPT_DIR}/../../src/scep/testunit

if [ $# -eq 0 ]; then
    tests=$(find . -maxdepth 1 -type f -executable)

    while IFS= read -r cur_test; do
        echo "> Executing $cur_test"
        ./$cur_test
    done <<< "$tests"
else
    for cur_test in "$@"; do
        echo "> Executing $cur_test"
        ./$cur_test
    done
fi

popd
