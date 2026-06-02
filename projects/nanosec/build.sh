#!/usr/bin/env bash
set -e

SCRIPTPATH="$(cd "$(dirname "$0")";pwd -P)"
TAP_OPT_ALLOWED=1

######################
function show_usage
{
  echo "options:"
  echo "   --help            - Show build options and targets"
  echo "   --gdb             - Build a Debug version or Makefiles & Projects. (Release is default)"
  echo "   --debug           - Build with Mocana logging enabled for specific build executable."
  echo "   --fips            - Build with FIPS enabled."
  echo "   --disable-suiteb  - Build with suiteb disabled."
  echo "   --disable-pqc     - Build with PQC disabled."
  echo "   --dual-mode       - Build with dual mode enabled."
  echo "   --nw-red          - Build with nw redundancy enabled."
  echo "   --tls             - Building with TLS"
  echo "   --ipv6            - Build with IPV6 enabled."
  echo "   --eap-s           - Building with EAP supplicant"
  echo "   --eap-a           - Building with EAP authenticator"
  echo "   --export          - Building in export mode"
  echo "   --tap-local       - Building with Tap Local"
  echo "   --tap-remote      - Building with Tap Remote"
  echo "   --x32             - Build 32 bit version"
  echo "   --x64             - Build 64 bit version "
  echo "   --data-protect    - Build with Data Protection"
  echo "   --trustedge       - Build with TrustEdge mode enabled."
  echo "   --library         - Build as Shared Library "
  echo "   --unsecure        - Enable unsecure algorithms"
  echo "   --rfc4806         - Enable RFC 4806 support"
  echo "   --toolchain <rpi32 | rpi64 | bbb | android> - Specify the toolchain to be used"
  echo "                        rpi32     For Raspberry Pi 32-bit"
  echo "                        rpi64     For Raspberry Pi 64-bit"
  echo "                        bbb       For BeagleBone Black"
  echo "                        android   For android"
  echo "   --strongswan      - Build with support for Strongswan 5.6.2"
  echo "   --ref-id-match    - Build with reference identifier match capability."
  echo "   ike               - IKE target"
  echo "   mcpagent          - mcpagent target"
  echo "   kdc               - kdc target"
  echo "   kdc_secondary     - kdc_secondary target"
  echo "   loadconfig        - loadconfig target"
  echo ""
  exit
}

# Place us in the dir of this script
CURR_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
cd $CURR_DIR


######################

unamestr=`uname`

BUILD_OPTIONS=
BUILD_TYPE=Release
BUILD_TGT=
ADD_ARGS=
INV_OPT=0
is_pkcs11_enabled=0
is_tap_enabled=0
is_shared_lib=0
TARGET_PLATFORM=
TLS=0
EAPA=0
EAPS=0
declare -i NO_TARGET=0
BUILD_EXAMPLE=0

source $CURR_DIR/../shared_cmake/get_toolchain.sh

while test $# -gt 0
do
    case "$1" in
        --help)
            INV_OPT=1
            ;;
        --tap-local)
            echo "-- Building with Tap Local enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP_LOCAL=ON";
            ;;
        --tap-remote)
            echo "-- Building with Tap Remote enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP_REMOTE=ON";
            ;;
        --gdb)
            echo "-- Building with Debug symbols enabled...";
            BUILD_TYPE="Debug";
            ;;
        --debug)
            echo "-- Building with Debug logs enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_DEBUG=ON"
            ;;
        --fips)
            echo "-- Building with FIPS enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_FIPS=ON"
            ;;
        --suiteb)
            echo "suiteb is enabled by default (legacy --suiteb flag ignored)...";
            ;;
        --pqc)
            echo "PQC is enabled by default (legacy --pqc flag ignored)...";
            ;;
        --oqs)
            echo "PQC is enabled by default (legacy --oqs flag ignored)...";
            ;;
        --disable-suiteb)
            echo "Building with suiteb disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_SUITEB=ON"
            ;;
        --disable-pqc)
            echo "Building with PQC disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_PQC=ON"
            ;;
        --dual-mode)
            echo "-- Building with dual-mode enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_DUAL_MODE=ON"
            ;;
        --nw-red)
            echo "-- Building with nw redundancy enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_NW_RED=ON"
            ;;
        --ref-id-match)
            echo "-- Build with reference identifier match capability...";
            BUILD_OPTIONS+=" -DCM_ENABLE_MOCANA_IKE_REF_IDENTIFIER_MATCH=ON"
            ;;
        --export)
            echo "-- Building in export mode...";
            BUILD_OPTIONS+=" -DCM_ENABLE_EXPORT=ON"
            ;;
        --eap-s)
            echo "-- Building with EAP server...";
            BUILD_OPTIONS+=" -DCM_ENABLE_EAPS=ON"
            EAPS=1
            ;;
        --eap-a)
            echo "-- Building with EAP authenticator...";
            BUILD_OPTIONS+=" -DCM_ENABLE_EAPA=ON"
            EAPA=1
            ;;
        --tls)
            echo "-- Building with TLS...";
            TLS=1
            ;;
        --ipv6)
            echo "Building with IPV6 enabled ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_IPV6=ON"
            ;;
        --toolchain)
            shift
            TARGET_PLATFORM=$(get_platform "${1}") || INV_OPT=1
            XC_BIN_PATH=$(get_sysroot_bin "${1}") || INV_OPT=1
            export PATH=${XC_BIN_PATH}:$PATH
            ;;
        --data-protect)
            echo "Enabling data protection"
            BUILD_OPTIONS+=" -DCM_ENABLE_DATA_PROTECTION=ON"
            ;;
        --trustedge)
            echo "Enabling TrustEdge mode"
            BUILD_OPTIONS+=" -DCM_ENABLE_TRUSTEDGE=ON"
            ;;
        --library)
            echo "Build Shared Library";
            BUILD_OPTIONS+=" -DCM_BUILD_SHARED_LIBS=ON";
            is_shared_lib=1
            ;;
        --strongswan)
            echo "Build with support for Strongswan 5.6.2";
            BUILD_OPTIONS+=" -DCM_ENABLE_STRONGSWAN=ON";
            ;;
        --unsecure)
            echo "Enable unescure algorithms"
            BUILD_OPTIONS+=" -DCM_ENABLE_UNSECURE=ON";
            ;;
        --rfc4806)
            echo "Enable RFC 4806 support.";
            BUILD_OPTIONS+=" -DCM_ENABLE_RFC4806=ON";
            ;;
        --x32) echo "Build 32 bit option";
            BUILD_OPTIONS+=" -DCM_BUILD_X32=ON"
            ;;
        --x64) echo "Build 64 bit option";
            BUILD_OPTIONS+=" -DCM_BUILD_X64=ON"
            ;;
        ike)
            echo "-- Building ike target..";
            BUILD_OPTIONS+=" -DCM_BUILD_IKE=ON"
            ADD_ARGS+="$1";
            NO_TARGET+=1
            ;;
        ike_sp800_135)
            echo "-- Building ike target for testing SP800-135";
            BUILD_OPTIONS+=" -DCM_BUILD_IKE_SP800_135=ON"
            ADD_ARGS+="$1";
            NO_TARGET+=1
            ;;
        mcpagent)
            echo "-- Building mcpagent target..";
            BUILD_OPTIONS+=" -DCM_BUILD_MCPA=ON"
            ADD_ARGS+="$1";
            NO_TARGET+=1
            ;;
        kdc)
            echo "-- Building kdc target..";
            BUILD_OPTIONS+=" -DCM_BUILD_MCPK=ON"
            ADD_ARGS+="$1";
            NO_TARGET+=1
            ;;
        kdc_secondary)
            echo "-- Building kdc_secondary target..";
            BUILD_OPTIONS+=" -DCM_BUILD_MCPK2=ON"
            ADD_ARGS+="$1";
            NO_TARGET+=1
            ;;
        --*)
            echo "Invalid option: $1";
            INV_OPT=1
            ;;
        *)
            echo "Adding Argument: $1";
            INV_OPT=1
            ;;
    esac
    shift
done

# Check that a valid set of arguments were passed
if [ ${EAPA} -eq 1 -a ${EAPS} -eq 1 ]; then
    echo "Can only build with either --eap-s or -eap-a."
    exit 1
fi

if [ ${NO_TARGET} -eq 0 ]; then
 echo "No target was provided. Max allowed: 1"
 show_usage
fi

if [ ${NO_TARGET} -gt 1 ]; then
 echo "Too many targets were provided. Max allowed: 1"
 show_usage
fi

if [ ${TLS} -eq 0 ]; then
    echo ""
elif [ ${TLS} -eq 1 -a ${EAPA} -eq 1 ]; then
    BUILD_OPTIONS+=" -DCM_ENABLE_TLSA=ON"
elif [ ${TLS} -eq 1 -a ${EAPS} -eq 1 ]; then
    BUILD_OPTIONS+=" -DCM_ENABLE_TLSS=ON"
else
    echo "TLS only works with EAP supplicant or authenticator builds"
    exit
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

######################

echo "Calling: clean.sh..."
. clean.sh

if [ ! -d "build" ]; then
  mkdir build
fi

cd build

echo "Calling: cmake ${TARGET_PLATFORM} \
-DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} CMakeLists.txt ../."

cmake ${TARGET_PLATFORM} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DLIB_TGT=${BUILD_TGT} -DBUILD_TGT=${BUILD_TGT} ${BUILD_OPTIONS} CMakeLists.txt ../.

echo "Calling: make ${BUILD_TGT}"
make ${BUILD_TGT}

LIB_PATH="./libs/lib"
LIB_PATH+="${BUILD_TGT}"
LIB_PATH+=".so"

echo "${LIB_PATH}"

mv ${LIB_PATH} ../../../bin

rm -r *

cmake ${TARGET_PLATFORM} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DLIB_TGT=${BUILD_TGT} -DBUILD_TGT=${BUILD_TGT} ${BUILD_OPTIONS} CMakeLists.txt ../example/.

if [ ${is_shared_lib} -eq 1 ]; then
make ${BUILD_TGT}_example

LIB_PATH="./libs/lib"
LIB_PATH+="${BUILD_TGT}_example"
LIB_PATH+=".so"

echo "${LIB_PATH}"
mv ${LIB_PATH} ../../../bin
else
make ${BUILD_TGT}
fi

if [ ${BUILD_TGT} == "mcpagent" ] ; then
  make mcping
fi
