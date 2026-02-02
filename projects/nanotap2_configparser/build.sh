#!/usr/bin/env bash

PROJECT_NAME=libnanotap2_configparser
######################
function show_usage
{
  echo ""
  echo "./build.sh --gdb --debug --toolchain <string> <MAKETARGETS>"
  echo ""
  echo "   --help            - Build options information"
  echo "   --gdb             - Build a Debug version or Makefiles & Projects. (Release is default)"
  echo "   --pg              - Build with call stack tracing."
  echo "   --debug           - Build with Mocana logging enabled for specific build executable."
  echo "   --libtype <static | shared> - Build a library either static type or shared type default is shared."
  echo "   --toolchain <rpi32 | rpi64 | bbb> - Specify the toolchain to be used"
  echo "                        rpi32     For Raspberry Pi 32-bit"
  echo "                        rpi64     For Raspberry Pi 64-bit"
  echo "                        bbb       For BeagleBone Black"
  echo "   --x32             - Creates build for 32Bit machine. By default creates build for 64Bit machine."
  echo "   --x64             - Creates build for 64Bit machine. By default creates build for 64Bit machine."
  echo "   --cmake-opt       - Use this parameter to pass extra CMAKE parameters."
  echo "                        exa: --cmake-opt -D<MACRO>=<VALUE>"
  echo "   <MAKETARGETS>     - Make targets to build. ('all' is default)"
  echo ""
  exit -1
}

# Place us in the dir of this script
cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null
CURR_DIR=$(pwd)
unamestr=`uname`
echo "Building ${PROJECT_NAME}."

if [[ "$unamestr" == 'Darwin' ]]; then
    SHARED_LIB_NAME=${PROJECT_NAME}.dylib
else
    SHARED_LIB_NAME=${PROJECT_NAME}.so
fi

echo "Calling: clean.sh..."
. clean.sh
mkdir build
cd build

is_static_lib=0
is_suiteb_enabled=0
is_tap_enabled=0
is_tap_remote_enabled=0
is_tpm12_enabled=0
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
        --pg)
            echo "Enabling callstack tracing build...";
            BUILD_OPTIONS+=" -DCM_ENABLE_PG=ON"
            ;;
        --debug)
            echo "Building with Debug logs enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_DEBUG=ON"
            ;;
        --libtype)
            case "$2" in
                static)
                    is_static_lib=1;
		            echo "Building static library...";
                    BUILD_OPTIONS+=" -DLIB_TYPE:STRING=STATIC"
                    ;;
                shared)
                    echo "Building shared library...";
                    BUILD_OPTIONS+=" -DLIB_TYPE:STRING=SHARED"
                    ;;
                *)
                    echo "Error reading libtype $2";
                    BUILD_OPTIONS+=" -DLIB_TYPE:STRING=SHARED"
                    ;;
            esac
            shift
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
        --suiteb)
            ;;
        --tap-off)
            ;;
        --tap-local)
            ;;
        --tap-remote)
            ;;
        --tpm12)
            ;;
        --toolchain)
            shift
            TARGET_PLATFORM=$(get_platform "${1}") || INV_OPT=1
            XC_BIN_PATH=$(get_sysroot_bin "${1}") || INV_OPT=1
            export PATH=${XC_BIN_PATH}:$PATH
            ;;
        --cmake-opt)
            shift
            echo "Setting extra flags for cmake execution...";
            BUILD_OPTIONS+=" ${1}"
            ;;
        --build-for-osi)
            echo "Enabling BUILD_FOR_OSI...";
            BUILD_OPTIONS+=" -DBUILD_FOR_OSI=ON"
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

# Check if building for OSI
source $CURR_DIR/../../scripts/check_for_osi.sh
if [ ${OSI_BUILD} -eq 1 ]; then
    BUILD_OPTIONS+=" -DBUILD_FOR_OSI=ON"
fi

if [ ${INV_OPT} -eq 1 ]; then
  show_usage
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

if [ $is_32bit_build -eq 1 -a $is_64bit_build -eq 1 ]; then
   echo "Error: Both the flags --x32 and --x64 should not be enabled. Either one of the flags --x32 or --x64 should be enabled."
   exit 1
fi

if [ $is_tap_enabled -eq 1 -a $is_tpm12_enabled -eq 1 ]; then
   echo "Error: Both the flags --tap and --tpm12 should not be enabled. Either one of the flags --tap or --tpm12 should be enabled."
   exit 1
fi
if [ $is_tap_enabled -eq 0 -a $is_tap_remote_enabled -eq 1 ]; then
   echo "Error: Enable the flag --remote only in case if --tap is enabled."
   exit 1
fi
if [ $is_32bit_build -eq 1 -a $is_64bit_build -eq 1 ]; then
   echo "Error: Both the flags --x32 and --x64 should not be enabled. Either one of the flags --x32 or --x64 should be enabled."
   exit 1
fi

echo "Calling: cmake ${TARGET_PLATFORM} \
-DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} CMakeLists.txt ../."

cmake ${TARGET_PLATFORM} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} CMakeLists.txt ../.


echo "Calling: make ${BUILD_TGT}"
make ${BUILD_TGT}

