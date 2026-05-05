#!/usr/bin/env bash

set -e

######################
function show_usage
{
  echo ""
  echo "./build.sh [options]"
  echo ""
  echo "   --help                 - Display this help menu"
  echo "   --gdb                  - Build a Debug version or Makefiles & Projects. (Release is default)."
  echo "   --debug                - Build with Mocana logging enabled for specific build executable."
  echo "   --export               - Build export edition."
  echo "   --cvc                  - Build with CV Certificate support."
  echo "   --enable-pc            - Enable Certificate/CSR printing."
  echo "   --pqc                  - Build with pqc hybrid key support."
  echo "   --oqs                  - Build with pqc/oqs hybrid key support."
  echo "   --pkcs11               - Build with pkcs11 support."
  echo "   --nanoroot             - Build with NanoROOT support."
  echo "   --pkcs11-dynamic       - Build with pkcs11 dynamic load support"
  echo "   --softhsm2             - Build with pkcs11 softhsm2 support."
  echo "   --cloudhsm             - Build with pkcs11 cloudhsm support."
  echo "   --mem-prof             - Build with memory profiling support."
  echo "   --custom-heap          - Build with custom heap support."
  echo "   --pkcs11-tee           - Build with pkcs11 tee support."
  echo "   --tee                  - Build with tee support."
  echo "   --dssm                 - Build with Digicert SSM support"
  echo "   --minimal              - Build with minimal code footprint."
  echo "   --tpm2                 - Build with tpm2 support."
  echo "   --digicert             - Build with Digicert scep support."
  echo "   --library              - Build trustedge binary as library"
  echo "   --unittest             - Build trustedge unittests"
  echo "   --debug-internals      - Build with internal debugging"
  echo "   --monolithic           - Build monolithic binary"
  echo "   --disable-est          - Disable EST (Enrollment over Secure Transport) support."
  echo "   --pre-release          - Specify pre-release string"
  echo "   --persist-artifact     - Enable persisting artifact payload."
  echo "   --generator <name>     - Specify the generator to be used. DEB, TGZ"
  echo "   --proxy                - Build with proxy support."
  echo "   --x32                  - Build for 32-bit platforms."
  echo "   --x64                  - Build for 64-bit platforms."
  echo "   --board <board>        - Build for Zephyr OS for <board>"
  echo "   --version-string       - Version information for release."
  echo "   --service-certificate  - Build trustedge installer with service certificate mode conf"
  echo "   --valgrind-tool <tool> - Enable valgrind with selected tool."
  echo "                              memcheck"
  echo "                              massif"
  echo "   --enable-coverage      - Build with gcov code coverage support."
  echo "   --enable-token-fallback - Enable fallback when authorization token missing."
  echo "   --toolchain <rpi32 | rpi64 | bbb | android> - Specify the toolchain to be used"
  echo "                        rpi32     For Raspberry Pi 32-bit"
  echo "                        rpi64     For Raspberry Pi 64-bit"
  echo "                        bbb       For BeagleBone Black"
  echo "                        android   For android"
  echo "   --cmake-opt         - Additional cmake options can be passed using this flag."
  echo ""
  exit 1
}

# Place us in the dir of this script
cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null
CURR_DIR=$(pwd)

printf "\n\nBuilding trustedge library and binary.\n\n\n"

echo "Calling: clean.sh..."
. clean.sh

if [ -d "build" ]; then
    rm -rf build
    mkdir build
else
    mkdir build
fi

cd build
is_32bit_build=0
is_64bit_build=0

BUILD_OPTIONS=
BUILD_TYPE=Release
BUILD_TGT=
ADD_ARGS=
INV_OPT=0
TARGET_PLATFORM=
RUN_UNITTEST=0
VERSION_STRING=""
ZEPHYR_BOARD=""
BUILD_FOR_OSI=0

source $CURR_DIR/../shared_cmake/get_toolchain.sh

while test $# -gt 0
do
    case "$1" in
        --help)
            INV_OPT=1
            ;;
        --gdb)
            BUILD_TYPE="Debug";
            BUILD_OPTIONS+=" -DCMAKE_BUILD_TYPE=Debug"
            ;;
        --debug)
            BUILD_OPTIONS+=" -DCM_ENABLE_DEBUG=ON"
            ;;
        --custom-heap)
            BUILD_OPTIONS+=" -DCM_ENABLE_CUSTOM_HEAP=ON"
            ;;
        --kmalloc)
            BUILD_OPTIONS+=" -DCM_ENABLE_K_MALLOC=ON"
            ;;
        --minimal)
            echo "Building with minimal code footprint";
            BUILD_OPTIONS+=" -DCM_ENABLE_MINIMAL=ON"
            ;;
        --export)
            echo "Building Export Edition library...";
            BUILD_OPTIONS+=" -DCM_ENABLE_EXPORT_ED=ON"
            ;;
        --cvc)
            echo "Building With CV Certificate support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_CVC=ON"
            ;;
        --enable-pc)
            echo "Building with Certificate/CSR printing enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_CERT_PRINT=ON"
            ;;
        --oqs)
            echo "Building With PQC/OQS hybrid support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_OQS=ON"
            ;;
        --pqc)
            echo "Building With PQC hybrid support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_PQC=ON"
            ;;
        --disable-pqc)
            echo "Building Without PQC hybrid support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_PQC=OFF"
            ;;
        --disable-rest-api)
            echo "Building Without REST API support...";
            BUILD_OPTIONS+=" -DCM_DISABLE_REST_API=ON"
            ;;
        --pkcs11)
            echo "-- Building with pkcs11 enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_PKCS11=ON"
            ;;
        --pkcs11-dynamic)
            ;;
        --nanoroot)
            echo "-- Building with NanoROOT enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_NANOROOT=ON"
            ;;
        --mem-prof)
            echo "Building with memory profiling support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_MEM_PROFILE=ON"
            ;;
        --softhsm2)
            echo "Building with softhsm2";
            BUILD_OPTIONS+=" -DCM_ENABLE_SOFTHSM=ON -DCM_ENABLE_PKCS11=ON"
            ;;
        --cloudhsm)
            echo "Building with cloudhsm";
            BUILD_OPTIONS+=" -DCM_ENABLE_CLOUDHSM=ON -DCM_ENABLE_PKCS11=ON"
            ;;
        --dssm)
            echo "Building with Digicert ssm";
            BUILD_OPTIONS+=" -DCM_ENABLE_DSSM=ON -DCM_ENABLE_PKCS11=ON"
            ;;
        --pkcs11-tee)
            echo "-- Building with tee pkcs11 enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_PKCS11_TEE=ON -DCM_ENABLE_PKCS11=ON"
            ;;
        --tee)
            echo "-- Building with tee enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TEE=ON"
            ;;
        --tpm2)
            echo "-- Building with tpm2 enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TPM2=ON"
            ;;
        --tap-local)
            echo "-- Building TAP local..."
            ;;
        --tap-remote)
            echo "-- Building TAP remote...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP_REMOTE=ON"
            ;;
        --digicert)
            echo "-- Building with Digicert scep support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_DIGICERT_SCEP=ON"
            ;;
        --library)
            BUILD_OPTIONS+=" -DCM_BUILD_LIBRARY=ON"
            ;;
        --unittest)
            BUILD_OPTIONS+=" -DCM_BUILD_UNITTEST=ON"
            RUN_UNITTEST=1
            ;;
        --debug-internals)
            BUILD_OPTIONS+=" -DCM_ENABLE_DEBUG_INTERNALS=ON"
            ;;
        --monolithic)
            BUILD_OPTIONS+=" -DCM_ENABLE_MONOLITHIC_BUILD=ON"
            ;;
        --build-for-osi)
            echo "Enabling BUILD_FOR_OSI...";
            BUILD_OPTIONS+=" -DBUILD_FOR_OSI=ON"
            BUILD_FOR_OSI=1
            ;;
        --persist-artifact)
            BUILD_OPTIONS+=" -DCM_ENABLE_PERSIST_ARTIFACT=ON"
            ;;
        --generator)
            if [ -z "$2" ]; then
                show_usage
            fi
            BUILD_OPTIONS+=" -DCM_GENERATOR_BUILD=$2"
            shift
            ;;
        --libtype)
            case "$2" in
                static)
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
        --board)
            case "$2" in
                native_sim)
                    echo "Building native_sim for Zephyr OS...";
                    ZEPHYR_BOARD="native_sim/native/64"
                    BUILD_OPTIONS+=" -DCM_ENABLE_ZEPHYR_OS=ON"
                    BOARD_OVERLAY="./boards/flash_size.overlay"
                    BOARD_CONF_FILE="no_optimization.conf"
                    ;;
                stm32h745i_disco)
                    echo "Building stm32h745i_disco for Zephyr OS...";
                    ZEPHYR_BOARD="stm32h745i_disco/stm32h745xx/m7"
                    BUILD_OPTIONS+=" -DCM_ENABLE_ZEPHYR_OS=ON"
                    BOARD_OVERLAY="./boards/stm32h745i_disco_stm32h745xx_m7.overlay"
                    BOARD_CONF_FILE="aggressive_optimization.conf"
                    ;;
                nrf5340dk)
                    echo "Building nrf5340dk for Zephyr OS...";
                    ZEPHYR_BOARD="nrf5340dk/nrf5340/cpuapp"
                    BUILD_OPTIONS+=" -DCM_ENABLE_ZEPHYR_OS=ON"
                    BOARD_OVERLAY=""
                    BOARD_CONF_FILE="aggressive_optimization.conf"
                    ;;
                nrf7002dk)
                    echo "Building nrf7002dk for Zephyr OS...";
                    ZEPHYR_BOARD="nrf7002dk/nrf5340/cpuapp"
                    BUILD_OPTIONS+=" -DCM_ENABLE_ZEPHYR_OS=ON"
                    BOARD_OVERLAY=""
                    BOARD_CONF_FILE="aggressive_optimization.conf"
                    ;;
                nucleo_h745zi_q)
                    echo "Building nucleo_h745zi_q for Zephyr OS...";
                    ZEPHYR_BOARD="nucleo_h745zi_q/stm32h745xx/m7"
                    BUILD_OPTIONS+=" -DCM_ENABLE_ZEPHYR_OS=ON"
                    BOARD_OVERLAY="./boards/nucleo_h745zi_q_stm32h745xx_m7.overlay"
                    BOARD_CONF_FILE="aggressive_optimization.conf"
                    ;;
                esp32s3_devkitc)
                    echo "Building ep32s3_devkitc for Zephyr OS...";
                    ZEPHYR_BOARD="esp32s3_devkitc/esp32s3/procpu"
                    BUILD_OPTIONS+=" -DCM_ENABLE_ZEPHYR_OS=ON"
                    BOARD_OVERLAY="./boards/esp32s3_devkitc.overlay"
                    BOARD_CONF_FILE="aggressive_optimization.conf"
                    ;;
                *)
                    echo "Error reading zephyr board: $2";
                    ;;
            esac
            shift
            ;;
        --proxy)
            BUILD_OPTIONS+=" -DCM_ENABLE_PROXY=ON"
            ;;
        --disable-est)
            BUILD_OPTIONS+=" -DCM_DISABLE_EST=ON"
            ;;
        --service-certificate)
            BUILD_OPTIONS+=" -DCM_CERTMODE_SERVICE_BUILD=ON"
            ;;
        --valgrind-tool)
            TOOL_NAME="$2"
            if [ "${TOOL_NAME}" = "memcheck" ]; then
                BUILD_OPTIONS+=" -DCM_ENABLE_VALGRIND_MEMCHECK=ON"
            elif [ "${TOOL_NAME}" = "massif" ]; then
                BUILD_OPTIONS+=" -DCM_ENABLE_VALGRIND_MASSIF=ON"
            else
                echo "unknown valgrind tool: $2"
                exit 1
            fi
            shift
            ;;
        --pre-release)
            if [ -z "$2" ]; then
                show_usage
            fi
            BUILD_OPTIONS+=" -DCM_PRE_RELEASE_STRING=$2"
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
            echo "Building for x32 machine...";
            ;;
        --x64)
            BUILD_OPTIONS+=" -DCM_BUILD_X64=ON"
            echo "Building for x64 machine...";
            ;;
        --version-string)
            shift
            VERSION_STRING="${1}"
            ;;
        --enable-coverage)
            BUILD_OPTIONS+=" -DCM_ENABLE_COVERAGE=ON"
            ;;
        --enable-token-fallback)
            BUILD_OPTIONS+=" -DCM_ENABLE_TOKEN_FALLBACK=ON"
            ;;
        --cmake-opt)
            shift
            echo "Setting additional cmake option: $1"
            BUILD_OPTIONS+=" $1"
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

if [ -z "${ZEPHYR_BOARD}" ]; then
    echo ""
    echo "Calling: cmake ${TARGET_PLATFORM}\
        -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
        ${BUILD_OPTIONS} CMakeLists.txt ../."

    if [ -z "${VERSION_STRING}" ]; then
    cmake ${TARGET_PLATFORM} \
        -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} \
        CMakeLists.txt ../.
    else
    cmake ${TARGET_PLATFORM} -DCM_VERSION_STRING=${VERSION_STRING} \
        -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} \
        CMakeLists.txt ../.
    fi


    echo "Calling: make ${BUILD_TGT}"
    make ${BUILD_TGT}

    if [ $RUN_UNITTEST -eq 1 ]; then
        ctest
    fi
else
    pushd ..
    echo "west build -b ${ZEPHYR_BOARD} --pristine -- -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS}"
    if [ -z "${BOARD_OVERLAY}" ]; then
        west build -b ${ZEPHYR_BOARD} --pristine -- -DEXTRA_CONF_FILE="${BOARD_CONF_FILE}" -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS}
    else
        west build -b ${ZEPHYR_BOARD} --pristine -- -DDTC_OVERLAY_FILE="${BOARD_OVERLAY}" -DEXTRA_CONF_FILE="${BOARD_CONF_FILE}" -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS}
    fi

    if [ ${OSI_BUILD} -eq 0 ] && [ ${BUILD_FOR_OSI} -eq 0 ]; then
        cp build/lib/libtrustedge.a ${CURR_DIR}/../../lib/
    else
        cp build/lib/libtrustedge.a ${CURR_DIR}/../../bin_static/
    fi
    popd || true
fi
