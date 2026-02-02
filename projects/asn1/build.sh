#!/usr/bin/env bash

######################
function show_usage
{
  echo ""
  echo "./build.sh --gdb --debug --libtype <static | shared> --cms --cvc"
  echo "           --cmake-opt -D<MACRO>=<VALUE>"
  echo "           [--x32 | --x64] --toolchain <string> --platform <string> <MAKETARGETS>"
  echo ""
  echo "   --gdb             - Build a Debug version or Makefiles & Projects. (Release is default)"
  echo "   --pg              - Build with call stack tracing."
  echo "   --debug           - Build with Mocana logging enabled for specific build executable."
  echo "   --libtype <static | shared> - Build a library either static type or shared type default is shared."
  echo "   --cms             - Build this lib for a CMS project."
  echo "   --ipv6            - Build with IPV6 enabled."
  echo "   --no-cryptointerface - Build with Crypto Interface disabled."
  echo "   --cvc             - Build with CVC certificates."
  echo "   --toolchain <rpi32 | rpi64 | bbb | android> - Specify the toolchain to be used"
  echo "                        rpi32     For Raspberry Pi 32-bit"
  echo "                        rpi64     For Raspberry Pi 64-bit"
  echo "                        bbb       For BeagleBone Black"
  echo "                        android   For android"
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
printf "\n\nBuilding asn1 library.\n\n\n"

if [[ "$unamestr" == 'Darwin' ]]; then
    SHARED_LIB_NAME=libasn1.dylib
else
    SHARED_LIB_NAME=libasn1.so
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
        --pg)
            echo "Enabling callstack tracing build...";
            BUILD_OPTIONS+=" -DCM_ENABLE_PG=ON"
            ;;
        --debug)
            echo "Building with Debug logs enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_DEBUG=ON"
            ;;
        --build-for-osi)
            echo "Enabling BUILD_FOR_OSI...";
            BUILD_OPTIONS+=" -DBUILD_FOR_OSI=ON"
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
        --cms)
            echo "Building CMS ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_CMS=ON"
            ;;
        --ipv6)
            echo "Building with IPV6 enabled ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_IPV6=ON"
            ;;
        --mbed)
            ;;
        --mbed-path)
            shift
            ;;
        --suiteb)
            ;;
        --no-cryptointerface)
            echo "Building with crypto interface disabled ...";
            BUILD_OPTIONS+=" -DCM_DISABLE_CI=ON"
            ;;
        --cvc)
            echo "Building CV Certificates ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_CVC=ON"
            ;;
        --pqc)
            echo "PQC is enabled by default (legacy --pqc flag ignored)...";
            ;;
        --disable-suiteb)
            echo "Building with suiteb disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_SUITEB=ON";
            ;;
        --disable-pqc)
            echo "Building with pqc disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_PQC=ON";
            ;;
        --oqs)
            echo "PQC is enabled by default (legacy --oqs flag ignored)...";
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

echo "Calling: cmake ${TARGET_PLATFORM}\
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
      ${BUILD_OPTIONS} CMakeLists.txt ../."

cmake ${TARGET_PLATFORM} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} \
      CMakeLists.txt ../.


echo "Calling: make ${BUILD_TGT}"
make ${BUILD_TGT}

echo "Copying library to bin..."
if [ $is_static_lib -eq 0 ]; then
    cp libs/${SHARED_LIB_NAME} ../../../bin/
else
    cp libasn1.a ../../../bin_static/
fi
