#!/usr/bin/env bash

set -e

######################
function show_usage
{
  echo ""
  echo "./build.sh --gdb --debug --libtype <static | shared> "
  echo "           --cmake-opt -D<MACRO>=<VALUE>"
  echo "           [--x32 | --x64] --toolchain <string> --platform <string> <MAKETARGETS>"
  echo ""
  echo "   --gdb             - Build a Debug version or Makefiles & Projects. (Release is default)"
  echo "   --debug           - Build with Mocana logging enabled for specific build executable."
  echo "   --libtype <static | shared> - Build a library either static type or shared type default is shared."
  echo "   --toolchain <rpi32 | rpi64 | bbb | android> - Specify the toolchain to be used"
  echo "                        rpi32     For Raspberry Pi 32-bit"
  echo "                        rpi64     For Raspberry Pi 64-bit"
  echo "                        bbb       For BeagleBone Black"
  echo "                        android   For android"
  echo "   --x32             - Creates build for 32Bit machine. By default creates build for 64Bit machine."
  echo "   --x64             - Creates build for 64Bit machine. By default creates build for 64Bit machine."
  echo "   --cmake-opt       - Use this parameter to pass extra CMAKE parameters."
  echo "                        exa: --cmake-opt -D<MACRO>=<VALUE>"
  echo "   --ssl             - Build with SSL enabled."
  echo "   --proxy           - Build with proxy support enabled."
  echo "   --async           - Build with asynchronous support enabled."
  echo "   --persist         - Build with peristence options enabled"
  echo "   --test            - Build with additional test only internal validation functions. DO NOT USE FOR PRODUCTION BUILD."
  echo "   --streaming       - Build with streaming support enabled."
  echo "   --unittest        - Build mqtt unittests"
  echo "   --enable-coverage - Build with gcov code coverage support."
  echo "   nanomqtt          - Build nanomqtt library."
  echo "   mqtt_client_sample       - Build mqtt client sample application."
  echo "   <MAKETARGETS>     - Make targets to build. ('all' is default)"
  echo ""
  exit -1
}

# Place us in the dir of this script
cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null
CURR_DIR=$(pwd)

unamestr=`uname`
printf "\n\nBuilding mqtt client library.\n\n\n"

if [[ "$unamestr" == 'Darwin' ]]; then
    SHARED_LIB_NAME=libnanomqtt.dylib
else
    SHARED_LIB_NAME=libnanomqtt.so
fi

echo "Calling: clean.sh..."
. clean.sh

if [ -d "build" ]; then
    rm -rf build
    mkdir build
else
    mkdir build
fi

cd build
is_static_lib=0
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
        --pqc)
            echo "Building with PQC enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_PQC=ON"
            ;;
        --disable-pqc)
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
        --cmake-opt)
            shift
            echo "Setting extra flags for cmake execution...";
            BUILD_OPTIONS+=" ${1}"
            ;;
        --ssl)
            echo "Building with SSL enabled..."
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL=ON"
            ;;
        --proxy)
            echo "Building with proxy support enabled..."
            BUILD_OPTIONS+=" -DCM_ENABLE_PROXY=ON"
            ;;
        --async)
            echo "Building with asynchronous support enabled..."
            BUILD_OPTIONS+=" -DCM_ENABLE_ASYNC=ON"
            ;;
        --scram)
            echo "Building with SCRAM authentication support enabled..."
            BUILD_OPTIONS+=" -DCM_ENABLE_SCRAM=ON"
            ;;
        --library)
            echo "Building client sample in library mode..."
            BUILD_OPTIONS+=" -DCM_BUILD_LIBRARY=ON"
            ;;
        --persist)
            echo "Building with persistence support enabled..."
            BUILD_OPTIONS+=" -DCM_ENABLE_PERSIST=ON"
            ;;
        --test)
            echo "Building with test validation enabled..."
            BUILD_OPTIONS+=" -DCM_ENABLE_MQTT_TEST=ON"
            ;;
        --streaming)
            echo "Building with streaming support enabled..."
            BUILD_OPTIONS+=" -DCM_ENABLE_STREAMING=ON"
            ;;
        --unittest)
            echo "Building with unittesting..."
            BUILD_OPTIONS+=" -DCM_BUILD_UNITTEST=ON"
            ;;
        --enable-coverage)
            echo "Building with gcov code coverage support..."
            BUILD_OPTIONS+=" -DCM_ENABLE_COVERAGE=ON"
            ;;
        --build-for-osi)
            echo "Enabling BUILD_FOR_OSI...";
            BUILD_OPTIONS+=" -DBUILD_FOR_OSI=ON"
            ;;
        nanomqtt)
            BUILD_OPTIONS+=" -DCM_BUILD_NANOMQTT=ON"
            ADD_ARGS+=" nanomqtt"
            ;;
        mqtt_client_sample)
            BUILD_OPTIONS+=" -DCM_BUILD_MQTT_CLIENT_SAMPLE=ON"
            ADD_ARGS+=" mqtt_client_sample"
            ;;
        mqtt_client_test)
            BUILD_OPTIONS+=" -DCM_BUILD_MQTT_CLIENT_TEST=ON"
            ADD_ARGS+=" mqtt_client_test"
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

echo "Calling: cmake ${TARGET_PLATFORM}\
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
      ${BUILD_OPTIONS} CMakeLists.txt ../."

cmake ${TARGET_PLATFORM} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} \
      CMakeLists.txt ../.


echo "Calling: make ${BUILD_TGT}"
make ${BUILD_TGT}

