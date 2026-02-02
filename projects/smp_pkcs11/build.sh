#!/usr/bin/env bash

######################
function show_usage
{
  echo ""
  echo "./build.sh --gdb --debug --toolchain <string> --platform <string> <MAKETARGETS>"
  echo ""
  echo "   --gdb             - Build a Debug version or Makefiles & Projects. (Release is default)"
  echo "   --pg              - Build with call stack tracing."
  echo "   --debug           - Build with Mocana logging enabled for specific build executable."
  echo "   --disable-suiteb  - Build with suiteb disabled."
  echo "   --libtype <static | shared> - Build a library either static type or shared type default is shared."
  echo "   --toolchain <rpi32 | rpi64 | bbb> - Specify the toolchain to be used"
  echo "                        rpi32     For Raspberry Pi 32-bit"
  echo "                        rpi64     For Raspberry Pi 64-bit"
  echo "                        bbb       For BeagleBone Black"
  echo "   --pkcs11-dynamic  - Enable dynamic loading for multiple pkcs11 libraries"
  echo "   --softhsm2        - Link to softhsm2 lib"
  echo "   --cloudhsm        - Link to cloudhsm lib"
  echo "   --pkcs11-tee      - Link to tee pkcs11 libs"
  echo "   --dssm            - Link to Digicert ssm pkcs11 libs"
  echo "   --platform <name> - Name the platform of the generated installer package."
  echo "   --x32             - Creates build for 32Bit machine. By default creates build for 64Bit machine."
  echo "   --x64             - Creates build for 64Bit machine. By default creates build for 64Bit machine."
  echo "   <MAKETARGETS>     - Make targets to build. ('all' is default)"
  echo ""
  exit -1
}

# Place us in the dir of this script
cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null

unamestr=`uname`

if [ -d "build" ]; then
    rm -rf build
    mkdir build
else
    mkdir build
fi

CURR_DIR=$(pwd)
source $CURR_DIR/../shared_cmake/get_toolchain.sh

cd build
is_static_lib=0
is_tap_enabled=0
is_tap_remote_enabled=0
is_tpm12_enabled=0
is_clean_build=0

BUILD_OPTIONS=
BUILD_TYPE=Release
BUILD_TGT=
ADD_ARGS=
CLEAN_LIBS_ARGS=
INV_OPT=0
TOOLCHAIN_FILE=
CMAKE_MOCANA_PLATFORM_NAME=

function set_toolchain_file()
{
    TARGET_PLATFORM=$(get_platform "${1}") || INV_OPT=1
    XC_BIN_PATH=$(get_sysroot_bin "${1}") || INV_OPT=1
    export PATH=${XC_BIN_PATH}:$PATH

    case "$1" in
        rpi32)
            echo "-- Setting toolchain for Raspberry Pi 32-bit";
            TOOLCHAIN_FILE="-DCMAKE_TOOLCHAIN_FILE=../shared_cmake/toolchains/arm-linux-gnu-toolchain.cmake"
            CMAKE_MOCANA_PLATFORM_NAME="-DCMAKE_MOCANA_PLATFORM=rpi3_raspbian_9.4"
            ;;
        rpi64)
            echo "-- Setting toolchain for Raspberry Pi 64-bit";
            TOOLCHAIN_FILE="-DCMAKE_TOOLCHAIN_FILE=../shared_cmake/toolchains/aarch64-linux-gnu-toolchain.cmake"
            CMAKE_MOCANA_PLATFORM_NAME="-DCMAKE_MOCANA_PLATFORM=rpi3_raspbian_9.4"
            ;;
        bbb)
            echo "-- Setting toolchain for BeagleBone Black";
            TOOLCHAIN_FILE="-DCMAKE_TOOLCHAIN_FILE=../shared_cmake/toolchains/arm-linux-gnu-toolchain.cmake"
            CMAKE_MOCANA_PLATFORM_NAME="-DCMAKE_MOCANA_PLATFORM=bbb_ubuntu_16.04"
            ;;
        avnet)
            echo "-- Setting toolchain for Avnet M18Qx LTE";
            TOOLCHAIN_FILE="-DCMAKE_TOOLCHAIN_FILE=../shared_cmake/toolchains/arm-oe-linux-gnueabi-toolchain.cmake"
            CMAKE_MOCANA_PLATFORM_NAME="-DCMAKE_MOCANA_PLATFORM=avnet_oelinux_3.18.20"
            ;;
    esac
}

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
        --suiteb)
            echo "Suiteb is enabled by default"
            ;;
        --disable-suiteb)
            echo "Building with suiteb disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_SUITEB=ON"
            ;;
        --platform)
            shift
            BUILD_OPTIONS+=" -DCP_SYSTEM_NAME=${1}"
            ;;
        --toolchain)
            shift
            echo "Setting toolchain for ${1}"
            set_toolchain_file $1
            ;;
        --clean)
            echo "Clean build";
            is_clean_build=1;
            CLEAN_LIBS_ARGS+=" libsmppkcs11"
            ;;
        --pkcs11-dynamic)
            echo "Building with dynamic loading";
            BUILD_OPTIONS+=" -DCM_ENABLE_DYNAMIC_LOAD=ON"
            ;;
        --softhsm2)
            echo "Building with softhsm2";
            BUILD_OPTIONS+=" -DCM_ENABLE_SOFTHSM=ON"
            ;;
        --cloudhsm)
            echo "Building with cloudhsm";
            BUILD_OPTIONS+=" -DCM_ENABLE_CLOUDHSM=ON"
            ;;
        --pkcs11-tee)
            echo "Building with tee pkcs11";
            BUILD_OPTIONS+=" -DCM_ENABLE_PKCS11_TEE=ON"
            ;;
        --dssm)
            echo "Building with Digicert ssm";
            BUILD_OPTIONS+=" -DCM_ENABLE_DSSM=ON"
            ;;
        --pkcs11-tools)
            echo "Building with support for pkcs11 tools";
            BUILD_OPTIONS+=" -DCM_ENABLE_PKCS11_TOOLS=ON"
            ;;
        --x32)
            is_32bit_build=1;
            BUILD_OPTIONS+=" -DCM_BUILD_X32=ON"
            echo "Building for x32 machine...";
            ;;
        --x64)
            BUILD_OPTIONS+=" -DCM_BUILD_X64=ON"
            echo "Building for x64 machine...";
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


if [ $is_clean_build -eq 1 ]; then
    echo "Calling: clean.sh..."
    . clean.sh "${CLEAN_LIBS_ARGS}"
    mkdir build
fi

echo "Calling: cmake ${TOOLCHAIN_FILE} ${CMAKE_MOCANA_PLATFORM_NAME} -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} CMakeLists.txt ../."
cmake ${TOOLCHAIN_FILE} \
      ${CMAKE_MOCANA_PLATFORM_NAME} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} CMakeLists.txt ../.

echo "Calling: make ${BUILD_TGT}"
make ${BUILD_TGT}
