#!/usr/bin/env bash

###
# Usage: ./build.sh [--gprof] [--test65] [--test70]
#
# --gprof     - Enable GPROF profiling
##

echo "Building Crypto Unit Test project."

BUILD_OPTIONS=
INV_OPT=0

while test $# -gt 0
do
    case "$1" in
        --gprof)
            echo " -- Building with GPROF enabled...";
            BUILD_OPTIONS+=" -DMOCANA_ENABLE_GPROF=ON"
            ;;
        --test65)
            echo " -- Running v6.5 API tests...";
            BUILD_OPTIONS+=" -DCT_65_TEST_ONLY=ON"
            ;;
        --test70)
            echo " -- Running v7.0 CAP API tests...";
            BUILD_OPTIONS+=" -DCT_CAP_TEST_ONLY=ON"
            ;;
        --*)
            echo "Invalid option: $1";
            INV_OPT=1
            ;;
    esac
    shift
done

if [ ${INV_OPT} -eq 1 ]; then
  exit
fi

if [ ! -z "${BUILD_OPTIONS}" ]; then
  echo "BUILD_OPTIONS=${BUILD_OPTIONS}"
fi

. clean.sh

cmake -GNinja -DCMAKE_BUILD_TYPE=Debug ${BUILD_OPTIONS} CMakeLists.txt -DCMAKE_C_FLAGS=-fdiagnostics-color=always
ninja clean
ninja
