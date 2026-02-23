#!/usr/bin/env bash

set -e

######################
function show_usage
{
  echo ""
  echo "./build.sh --gdb --debug --x32 --x64 --tap --fips --toolchain"
  echo ""
  echo "   --fips             - Build with FIPS"
  echo "   --tap              - Build TAP tests"
  echo "   --pkcs11           - Build TAP with PKCS11"
  echo "   --gdb              - Build a Debug version or Makefiles & Projects. (Release is default)."
  echo "   --debug            - Build with Mocana logging enabled for specific build executable."
  echo "   --x32              - Build for 32-bit platforms."
  echo "   --x64              - Build for 64-bit platforms."
  echo "   --toolchain <rpi32 | rpi64 | bbb | android> - Specify the toolchain to be used"
  echo "                        rpi32     For Raspberry Pi 32-bit"
  echo "                        rpi64     For Raspberry Pi 64-bit"
  echo "                        bbb       For BeagleBone Black"
  echo "                        android   For android"
  echo "   --build-for-osi    - Build for OSI environment"
  exit
}

# Place us in the dir of this script
cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null
CURR_DIR=$(pwd)

unamestr=`uname`

is_static_lib=0
is_suiteb_enabled=0
is_tap_enabled=0
is_pkcs11_enabled=0
is_tap_remote_enabled=0
is_32bit_build=0
is_64bit_build=0

BUILD_OPTIONS=
BUILD_TYPE=Release
BUILD_TGT=
ADD_ARGS=
INV_OPT=0
TARGET_PLATFORM=
TOOL_NAME="digiprov_test"
BUILD_FOR_OSI=0

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
        --toolchain)
            shift
            TARGET_PLATFORM=$(get_platform "${1}") || INV_OPT=1
            XC_BIN_PATH=$(get_sysroot_bin "${1}") || INV_OPT=1
            export PATH=${XC_BIN_PATH}:$PATH
            ;;
        --tap)
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP=ON"
            echo "Building with TAP"
            ;;
        --fips)
            BUILD_OPTIONS+=" -DCM_ENABLE_FIPS=ON"
            echo "Building with FIPS"
            ;;
        --pkcs11)
            BUILD_OPTIONS+=" -DCM_ENABLE_PKCS11=ON"
            echo "Building with TAP PKCS11"
            ;;
        --x32)
            BUILD_OPTIONS+=" -DCM_BUILD_X32=ON"
            echo "Building for x32 machine...";
            ;;
        --x64)
            BUILD_OPTIONS+=" -DCM_BUILD_X64=ON"
            echo "Building for x64 machine...";
            ;;
        --openssl_3_0_7)
            echo "Build with openssl 3.0.7...";
	    BUILD_OPTIONS+=" -DCM_OPENSSL_LIB=openssl-3.0.7"
            ;;
        --openssl_3_0_12)
            echo "Build with openssl 3.0.12...";
            BUILD_OPTIONS+=" -DCM_OPENSSL_LIB=openssl-3.0.12"
            ;;
        --build-for-osi)
            echo "Enabling BUILD_FOR_OSI...";
            BUILD_OPTIONS+=" -DBUILD_FOR_OSI=ON"
            BUILD_FOR_OSI=1
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

echo "Calling: clean.sh ${TOOL_NAME}"
. clean.sh ${TOOL_NAME}
mkdir build
cd build

echo "Calling: cmake ${TARGET_PLATFORM} \
-DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} CMakeLists.txt ../."

cmake ${TARGET_PLATFORM} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} CMakeLists.txt ../.


echo "Calling: make ${BUILD_TGT}"
make -j12 ${BUILD_TGT}

if [ ${OSI_BUILD} -eq 0 ] && [ ${BUILD_FOR_OSI} -eq 0 ]; then
    echo "Copying executable to bin..."
    cp ${TOOL_NAME} ../../../bin/
fi