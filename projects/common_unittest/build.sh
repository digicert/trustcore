#!/usr/bin/env bash

function show_usage
{
    echo "Build Common unit tests"
    echo "OPTIONS:"
    echo "--dpdk                 - Adds dpk hash implementation"
    exit
}

BUILD_OPTIONS=
INV_OPT=0

echo "Building Common Unit Test project."
. clean.sh

while test $# -gt 0
do
    case "$1" in
        --dpdk)
          echo "-- Building with dpdk enabled...";
          BUILD_OPTIONS+=" -DCM_ENABLE_DPDK=ON";
          ;;
        --help)
          INV_OPT=1
          ;;
        ?|-?)
          INV_OPT=1
          ;;
        --*)
          echo "Invalid option: $1"
          ;;
        *)
          echo "Argument: $1"
          ;;
    esac
    shift
done

if [ ${INV_OPT} -eq 1 ]; then
    show_usage
fi

echo "BUILD_OPTIONS=${BUILD_OPTIONS}"

cmake -DCMAKE_BUILD_TYPE=Debug CMakeLists.txt ${BUILD_OPTIONS}

make clean all
