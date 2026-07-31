#!/usr/bin/env bash

######################
function show_usage
{
  echo ""
  echo "./build.sh --gdb --debug --tap-remote [--tpm2 | --tpm12] --toolchain <string> --data-protect --hw-accel <MAKETARGETS>"
  echo ""
  echo "   --help            - Build options information"
  echo "   --gdb             - Build a Debug version or Makefiles & Projects. (Release is default)"
  echo "   --debug           - Build with Mocana logging enabled for specific build executable."
  echo "   --useloopbackaddr - Build TAP server to listen only on loopback address."
  echo "   --libtype <static | shared> - Build a library either static type or shared type default is shared."
  echo "   --toolchain <rpi32 | rpi64 | bbb> - Specify the toolchain to be used"
  echo "                        rpi32     For Raspberry Pi 32-bit"
  echo "                        rpi64     For Raspberry Pi 64-bit"
  echo "                        bbb       For BeagleBone Black"
  echo "   --tpm2            - Building with tpm2"
  echo "   --tpm12           - Building with tpm12"
  echo "   --pkcs11          - Building with pkcs11"
  echo "   --tee             - Building with TEE"
  echo "   --tap-remote      - Building with tpm remote"
  echo "   --clean           - Clean Build"
  echo "   --x32             - Creates build for 32Bit machine. By default creates build for 64Bit machine."
  echo "   --x64             - Creates build for 64Bit machine. By default creates build for 64Bit machine."
  echo "   --data-protect    - Build with data protection for the configuration files."
  echo "   --cred-ev         - Build with extended credential verification."
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
echo "Building nanotap_server."

if [ -d "build" ]; then
    rm -rf build
fi
mkdir build

is_static_lib=0
is_tap_enabled=0
is_tap_remote_enabled=0
is_tpm12_enabled=0
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
        --useloopbackaddr)
            echo "Building TAP server to only listen on loopback address...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAPS_LOOPBACK=ON"
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
            ;;
        --tap-off)
            ;;
        --tap-local)
            ;;
        --tap-remote)
            echo "Building with tap remote enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP_REMOTE=ON"
            ;;
        --tpm12)
            echo "Building with tpm12...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TPM=ON"
            ;;
        --tpm2)
            echo "Building with tpm2...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TPM2=ON"
            ;;
        --pkcs11)
            echo "Building with pkcs11...";
            BUILD_OPTIONS+=" -DCM_ENABLE_PKCS11=ON"
            ;;
        --tee)
            echo "Building with TEE...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TEE=ON"
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
        --data-protect)
            BUILD_OPTIONS+=" -DCM_ENABLE_DATA_PROTECT=ON"
            echo "Building with data protection enabled...";
            ;;
        --cred-ev)
            BUILD_OPTIONS+=" -DCM_ENABLE_CRED_EV=ON"
            echo "Building with extended credential validation...";
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

cd build

echo "Calling: cmake ${TARGET_PLATFORM} -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} CMakeLists.txt ../."
cmake ${TARGET_PLATFORM} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} CMakeLists.txt ../.


echo "Calling: make ${BUILD_TGT}"
make ${BUILD_TGT}
