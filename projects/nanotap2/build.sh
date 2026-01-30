#!/usr/bin/env bash

######################
function show_usage
{
  echo ""
  echo "./build.sh --gdb --debug --suiteb --tpm2 --tpm12 [--tap-off | --tap-local | --tap-remote] --data-protect --toolchain <string> <MAKETARGETS>"
  echo ""
  echo "   --help            - Build options information"
  echo "   --gdb             - Build a Debug version or Makefiles & Projects. (Release is default)"
  echo "   --pg              - Build with call stack tracing."
  echo "   --debug           - Build with Mocana logging enabled for specific build executable."
  echo "   --tpm2            - Build with support for TPM 2 SMP."
  echo "   --tpm12           - Build with support for TPM 1.2 SMP."
  echo "   --nanoroot         - Build with support for NANOROOT SMP."
  echo "   --libtype <static | shared> - Build a library either static type or shared type default is shared."
  echo "   --toolchain <rpi32 | rpi64 | bbb> - Specify the toolchain to be used"
  echo "                        rpi32     For Raspberry Pi 32-bit"
  echo "                        rpi64     For Raspberry Pi 64-bit"
  echo "                        bbb       For BeagleBone Black"
  echo "   --x32             - Creates build for 32Bit machine. By default creates build for 64Bit machine."
  echo "   --x64             - Creates build for 64Bit machine. By default creates build for 64Bit machine."
  echo "   --suiteb          - Build with suiteb enabled."
  echo "   --tpm2            - Build with tpm2."
  echo "   --tap-min         - Build smaller version (only libcommon and libplatform needed)."
  echo "   --clean           - Clean build."
  echo "   --openssl         - Build with openssl."
  echo "   --data-protect    - Build with data protection."
  echo "   --tcp-close-msg   - For unsecure comms send TCP close message."
  echo "   [--tap-off | --tap-local | --tap-remote]  - Build client libraries / executables with specific tap functionality"
  echo "     nanotap2        - Build Nanotap2 lib"
  echo "     clientcomm      - Build the clientcomm lib"
  echo "     tap_extern      - Building with tap extern lib"
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

if [ -d "build" ]; then
    rm -rf build
    mkdir build
else
    mkdir build
fi

is_static_lib=0
is_suiteb_enabled=0
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
CLEAN_LIBS_ARGS=
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
        --suiteb)
            is_suiteb_enabled=1;
            echo "Building with suiteb enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SUITEB=ON"
            ;;
        --tap-off)
            echo "-- Building without tap support... ";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP=OFF"
            ;;
        --tap-local)
             is_tap_enabled=1;
             echo "Building with tap local enabled...";
             BUILD_OPTIONS+=" -DCM_ENABLE_TAP=ON -DCM_ENABLE_TAP_LOCAL=ON"
             ;;
        --tap-remote)
             is_tap_remote_enabled=1;
             is_tap_enabled=1;
             echo "Building with tap remote enabled...";
             BUILD_OPTIONS+=" -DCM_ENABLE_TAP=ON -DCM_ENABLE_TAP_REMOTE=ON"
             ;;
        --pkcs11)
            echo "-- Building  with smp_pkcs11 support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SMP_PKCS11=ON"
            ;;
        --tee)
            echo "-- Building  with smp_tee support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SMP_TEE=ON"
            ;;
        --tap-min)
            echo "-- Building small version of nanotap2...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP_MIN=ON"
            ;;
        --tap-extern)
            echo "Building with tap extern...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP_EXTERN=ON"
            ;;
        --tpm2)
            echo "Building with tpm2...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TPM2=ON"
            ;;
        --tpm12)
            echo "Building with tpm12...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TPM=ON"
            ;;
        --nanoroot)
            echo "Building with smp_nanoroot support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SMP_NANOROOT=ON"
            ;;
        --ssl)
            echo "Building with ssl...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL=ON"
            ;;
        --data-protect)
            echo "Building with data protection...";
            BUILD_OPTIONS+=" -DCM_ENABLE_DATA_PROTECT=ON"
            ;;
        --tcp-close-msg)
            echo "Building with TCP close message...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TCP_CLOSE_MSG=ON"
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
        --openssl)
            BUILD_OPTIONS+=" -DCM_ENABLE_OPENSSL=ON"
            ;;
        nanotap2)
            echo "Build NANOTAP2 lib...";
            BUILD_OPTIONS+=" -DCM_BUILD_TAP_LIB=ON"
            ADD_ARGS+=" nanotap2"
            CLEAN_LIBS_ARGS+=" libnanotap2"
            ;;
        clientcomm)
            echo "Build the clientcomm lib...";
            BUILD_OPTIONS+=" -DCM_ENABLE_CLIENTCOMM=ON"
            ADD_ARGS+=" nanotap2_clientcomm"
            CLEAN_LIBS_ARGS+=" libnanotap2_clientcomm"
            ;;
        tap_extern)
            echo "Building with tap extern...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP_EXTERN_LIB=ON -DCM_ENABLE_TAP_EXTERN=ON"
            ADD_ARGS+=" tap_extern"
            CLEAN_LIBS_ARGS+=" libtap_extern"
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
        --build-for-osi)
            echo "Enabling BUILD_FOR_OSI...";
            BUILD_OPTIONS+=" -DBUILD_FOR_OSI=ON"
            ;;
        --export)
            BUILD_OPTIONS+=" -DCM_ENABLE_EXPORT_ED=ON"
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

if [ $is_clean_build -eq 1 ]; then
    echo "Calling: clean.sh..."
    . clean.sh "${CLEAN_LIBS_ARGS}"
    mkdir build
fi

cd $CURR_DIR/build
echo "Calling: cmake ${TARGET_PLATFORM} -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} CMakeLists.txt ../."
cmake ${TARGET_PLATFORM} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} CMakeLists.txt ../.


echo "Calling: make ${BUILD_TGT}"
make ${BUILD_TGT}
