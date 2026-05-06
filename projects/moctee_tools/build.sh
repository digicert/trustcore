#!/usr/bin/env bash

PROJECT_NAME=moctee_tools
######################
function show_usage
{
  echo ""
  echo "./build.sh --gdb --debug [--tap-local | --tap-remote] --toolchain <string> <MAKETARGETS>"
  echo ""
  echo "   --gdb             - Build a Debug version or Makefiles & Projects. (Release is default)"
  echo "   --debug           - Build with Mocana logging enabled for specific build executable."
  echo "   --tap-local       - Build with TAP-Local enabled."
  echo "   --tap-remote      - Build with TAP-Remote enabled."
  echo "   --toolchain <rpi32 | rpi64 | bbb> - Specify the toolchain to be used"
  echo "                        rpi32     For Raspberry Pi 32-bit"
  echo "                        rpi64     For Raspberry Pi 64-bit"
  echo "                        bbb       For BeagleBone Black"
  echo "   --clean           - Clean build."
  echo "   --cmake-opt       - Use this parameter to pass extra CMAKE parameters."
  echo "                        exa: --cmake-opt -D<MACRO>=<VALUE>"
  echo "   <MAKETARGETS>     - Make targets to build. ('all' is default)"
  echo ""
  exit -1
}

# Place us in the dir of this script
CURR_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
MSS_DIR=$CURR_DIR/../..

unamestr=`uname`
printf "\n\nBuilding ${PROJECT_NAME}.\n\n\n"

if [[ "$unamestr" == 'Darwin' ]]; then
    SHARED_LIB_NAME=${PROJECT_NAME}.dylib
else
    SHARED_LIB_NAME=${PROJECT_NAME}.so
fi

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
        --tap-local)
            echo "Building with tap local...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP=ON -DCM_ENABLE_TAP_LOCAL=ON"
            ;;
        --tap-remote)
            echo "Building with tap remote...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP=ON -DCM_ENABLE_TAP_REMOTE=ON"
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
        --toolchain)
            shift
            TARGET_PLATFORM=$(get_platform "${1}") || INV_OPT=1
            XC_BIN_PATH=$(get_sysroot_bin "${1}") || INV_OPT=1
            export PATH=${XC_BIN_PATH}:$PATH
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

cd $CURR_DIR
if [ ! -d $CURR_DIR/build ]; then
    mkdir build
fi

if [ $is_clean_build -eq 1 ]; then
    echo "Calling: clean.sh..."
    . clean.sh
    mkdir build
fi

cd $CURR_DIR/build
echo "Calling: ${TARGET_PLATFORM} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} CMakeLists.txt ../."

cmake ${TARGET_PLATFORM} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} CMakeLists.txt ../.


echo "Calling: make ${BUILD_TGT}"
make ${BUILD_TGT}
