#!/usr/bin/env bash

PROJECT_NAME=tap_api_example
######################
function show_usage
{
  echo ""
  echo "./build.sh --gdb --debug --suiteb [--tap-local | --tap-remote] --tpm2 --toolchain <string> --platform <string> --hw-accel <MAKETARGETS>"
  echo ""
  echo "   --help            - Build options information"
  echo "   --gdb             - Build a Debug version or Makefiles & Projects. (Release is default)"
  echo "   --debug           - Build with Mocana logging enabled for specific build executable."
  echo "   --toolchain <rpi32 | rpi64 | bbb> - Specify the toolchain to be used"
  echo "                        rpi32     For Raspberry Pi 32-bit"
  echo "                        rpi64     For Raspberry Pi 64-bit"
  echo "                        bbb       For BeagleBone Black"
  echo "   --tap-remote      - Building with tpm remote"
  echo "   --tap-local       - Building with tpm local"
  echo "   --tpm2            - Building with TPM2 support"
  echo "   --nanoroot         - Building with NANOROOT support"
  echo "   --clean           - Clean build"
  echo "   --platform <string> - Name the platform of the generated installer package."
  echo "   --cmake-opt       - Use this parameter to pass extra CMAKE parameters."
  echo "                        exa: --cmake-opt -D<MACRO>=<VALUE>"
  echo "   --hw-accel        - Build with hw acceleration."
  echo "   <MAKETARGETS>     - Make targets to build. ('all' is default)"
  echo ""
  exit -1
}

# Place us in the dir of this script
cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null
CURR_DIR=$(pwd)
unamestr=`uname`
echo "Building tap_api_example."

if [[ "$unamestr" == 'Darwin' ]]; then
    SHARED_LIB_NAME=${PROJECT_NAME}.dylib
else
    SHARED_LIB_NAME=${PROJECT_NAME}.so
fi

if [ -d "build" ]; then
    rm -rf build
    mkdir build
else
    mkdir build
fi

cd build
is_tap_remote_enabled=0
is_clean_build=0
is_32bit_build=0
is_64bit_build=0

BUILD_OPTIONS=
BUILD_TYPE=Release
BUILD_TGT=
ADD_ARGS=
INV_OPT=0
TARGET_PLATFORM=

source $CURR_DIR/../shared_cmake/get_toolchain.sh

while test $# -gt 0
do
    case "$1" in
        --help)
            INV_OPT=1
            ;;
        --gdb)
            echo "Enabling Debug build...";
            BUILD_TYPE="Debug";
            BUILD_OPTIONS+=" -DCMAKE_BUILD_TYPE=Debug"
            ;;
        --debug)
            echo "Building with Debug logs enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_DEBUG=ON"
            ;;
        --tap-remote)
            echo "Building with tap remote enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP_REMOTE=ON"
            ;;
        --tap-local)
            echo "Building with tap local enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP_REMOTE=OFF"
            ;;
        --tpm2)
            echo "Building with tpm2...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TPM2=ON"
            ;;
        --nanoroot)
            echo "Building with nanoroot support..";
            BUILD_OPTIONS+=" -DCM_ENABLE_SMP_NANOROOT=ON"
            ;;
        --platform)
            shift
            BUILD_OPTIONS+=" -DCP_SYSTEM_NAME=${1}"
            ;;
        --toolchain)
            shift
            TARGET_PLATFORM=$(get_platform "${1}") || INV_OPT=1
            XC_BIN_PATH=$(get_sysroot_bin "${1}") || INV_OPT=1
            export PATH=${XC_BIN_PATH}:$PATH
            ;;
        --x32)
            is_32bit_build=1;
            BUILD_OPTIONS+=" -DCM_BUILD_X32=ON"
            echo "Building for x32 machine...";
            ;;
        --x64)
            is_64bit_build=1;
            BUILD_OPTIONS+=" -DCM_BUILD_X64=ON"
            echo "Building for x64 machine...";
            ;;
        --clean)
            echo "Clean build";
            is_clean_build=1;
            ;;
        --cmake-opt)
            shift
            echo "Setting extra flags for cmake execution...";
            BUILD_OPTIONS+=" ${1}"
            ;;
        --hw-accel)
            echo "Building with hw accel enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_HW_ACCEL=ON"
            ;;
        --*)
            echo "Invalid option: $1";
            INV_OPT=1
            ;;
        *)
            echo "Adding Argument: $1";
            ADD_ARGS+=" $1"
            ;;
    esac
    shift
done

if [ ${INV_OPT} -eq 1 ]; then
  show_usage
fi

# Check if building for OSI
source $CURR_DIR/../../scripts/check_for_osi.sh
if [ ${OSI_BUILD} -eq 1 ]; then
    BUILD_OPTIONS+=" -DBUILD_FOR_OSI=ON"
fi

if [ $is_32bit_build -eq 1 -a $is_64bit_build -eq 1 ]; then
   echo "Error: Both the flags --x32 and --x64 should not be enabled. Either one of the flags --x32 or --x64 should be enabled."
   exit 1
fi

if [ ! -z "${BUILD_OPTIONS}" ]; then
  echo "BUILD_OPTIONS=${BUILD_OPTIONS}"
fi

if [ ! -z "${ADD_ARGS}" ]; then
  BUILD_TGT=${ADD_ARGS}
  echo "BUILD_TGT=${BUILD_TGT}"
else
  BUILD_TGT=all
fi

if [ $is_clean_build -eq 1 ]; then
    echo "Calling: clean.sh..."
    . clean.sh
    mkdir build
fi

echo "Calling: cmake ${TARGET_PLATFORM} -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} CMakeLists.txt ../."

cmake ${TARGET_PLATFORM} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} CMakeLists.txt ../.

echo "Calling: make ${BUILD_TGT}"
make ${BUILD_TGT}
