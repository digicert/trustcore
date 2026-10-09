#!/usr/bin/env bash

set -e

######################
function show_usage
{
  echo ""
  echo "./build.sh --gdb --debug --ssl --libtype <static | shared>"
  echo "           --cmake-opt -D<MACRO>=<VALUE> [--x32 | --x64] --toolchain <string> <MAKETARGETS>"
  echo ""
  echo "   --gdb             - Build a Debug version or Makefiles & Projects. (Release is default)"
  echo "   --debug           - Build with Mocana logging enabled for specific build executable."
  echo "   --libtype <static | shared> - Build a library either static type or shared type; default is shared."
  echo "   --toolchain <rpi32 | rpi64 | bbb | android> - Specify the toolchain to be used"
  echo "                        rpi32     For Raspberry Pi 32-bit"
  echo "                        rpi64     For Raspberry Pi 64-bit"
  echo "                        bbb       For BeagleBone Black"
  echo "                        android   For android"
  echo "   --x32             - Creates build for 32-bit machine."
  echo "   --x64             - Creates build for 64-bit machine. (default)"
  echo "   --ssl             - Build with SSL enabled (WSS support)."
  echo "   --cmake-opt       - Use this parameter to pass extra CMake parameters."
  echo "                        e.g. --cmake-opt -D<MACRO>=<VALUE>"
  echo "   nanows            - Build nanows library."
  echo "   <MAKETARGETS>     - Make targets to build. ('all' is default)"
  echo ""
  exit 1
}

# Place us in the dir of this script
cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null
CURR_DIR=$(pwd)

printf "\n\nBuilding NanoWS library.\n\n\n"

echo "Calling: clean.sh..."
. clean.sh

if [ -d "build" ]; then
    rm -rf build
    mkdir build
else
    mkdir build
fi

cd build

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
            echo "Enabling Debug build..."
            BUILD_TYPE="Debug"
            BUILD_OPTIONS+=" -DCMAKE_BUILD_TYPE=Debug"
            ;;
        --debug)
            echo "Building with Debug logs enabled..."
            BUILD_OPTIONS+=" -DCM_ENABLE_DEBUG=ON"
            ;;
        --libtype)
            case "$2" in
                static)
                    echo "Building static library..."
                    BUILD_OPTIONS+=" -DLIB_TYPE:STRING=STATIC"
                    ;;
                shared)
                    echo "Building shared library..."
                    BUILD_OPTIONS+=" -DLIB_TYPE:STRING=SHARED"
                    ;;
                *)
                    echo "Error reading libtype $2"
                    BUILD_OPTIONS+=" -DLIB_TYPE:STRING=SHARED"
                    ;;
            esac
            shift
            ;;
        --toolchain)
            shift
            TARGET_PLATFORM=$(get_platform "${1}") || INV_OPT=1
            XC_BIN_PATH=$(get_sysroot_bin "${1}") || INV_OPT=1
            export PATH=${XC_BIN_PATH}:$PATH
            ;;
        --x32)
            BUILD_OPTIONS+=" -DCM_BUILD_X32=ON"
            echo "Building for x32 machine..."
            ;;
        --x64)
            BUILD_OPTIONS+=" -DCM_BUILD_X64=ON"
            echo "Building for x64 machine..."
            ;;
        --cmake-opt)
            shift
            echo "Setting extra flags for cmake execution..."
            BUILD_OPTIONS+=" ${1}"
            ;;
        --ssl)
            echo "Building with SSL enabled..."
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL=ON"
            ;;
        --build-for-osi)
            echo "Enabling BUILD_FOR_OSI..."
            BUILD_OPTIONS+=" -DBUILD_FOR_OSI=ON"
            ;;
        nanows)
            BUILD_OPTIONS+=" -DCM_BUILD_NANOWS=ON"
            ADD_ARGS+=" nanows"
            ;;
        --*)
            echo "Invalid option: $1"
            INV_OPT=1
            ;;
        *)
            echo "Adding Argument: $1"
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

if [ ! -z "${BUILD_OPTIONS}" ]; then
    echo "BUILD_OPTIONS=${BUILD_OPTIONS}"
fi

if [ ! -z "${ADD_ARGS}" ]; then
    BUILD_TGT=${ADD_ARGS}
    echo "BUILD_TGT=${BUILD_TGT}"
else
    BUILD_TGT=all
fi

echo "Calling: cmake ${TARGET_PLATFORM} -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
      ${BUILD_OPTIONS} CMakeLists.txt ../."

cmake ${TARGET_PLATFORM} -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} \
      CMakeLists.txt ../.

echo "Calling: make ${BUILD_TGT}"
make ${BUILD_TGT}
