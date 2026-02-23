#!/usr/bin/env bash

# Usage: ./build.sh [--no-ci] [--operator-path <path>] [--mbedtls] [--mbed-path <path>] [--oqs] [--oqs-path <path>] [--softhsm2] [--cloudhsm] [--dssm] [--pkcs11-path <path>]
# --no-ci     -  Build w/o CryptoInterface enabled
# --speedtest -  Allow the running of speedtests (__ENABLE_DIGICERT_UNITTEST_SPEEDTEST__)
# --mbedtls   -  Build w/ mbed tls enabled
# --mbed-path -  Path to mbed install location, can be absolute or relative

function show_usage
{
    echo "Build Crypto Interface unit tests"
    echo "./build_and_run_all.sh [OPTIONS]"
    echo "OPTIONS:"
    echo "--no-ci               - Build with Crypto Interface disabled."
    echo "--pg                  - Build with call stack tracing."
    echo "--speedtest           - Get execution time for operations."
    echo "--quick               - Reduces the number of tests executed."
    echo "--operator-path       - Path and name of static library with operator implementations"
    echo "--mbedtls             - Adds test with MbedTLS as the crypto."
    echo "--mbed-path           - Argument for path to MbedTLS. Must be followed by the path."
    echo "--oqs                 - Adds oqs tests"
    echo "--oqs-path            - Argument for path to OQS Library. Must be followed by the path."
    echo "--softhsm2            - Build with softhsm2 PKCS11 TAP"
    echo "--cloudhsm            - Build with cloudhsm PKCS11 TAP"
    echo "--pkcs11-tee          - Build with tee PKCS11 TAP"
    echo "--dssm                - Build with Digicert ssm PKCS11 TAP"
    echo "--tpm2                - Build with TPM2 TAP"
    echo "--pkcs11-path         - Argument for path to the softhsm2 or cloudhsm pkcs11 Library. Must be followed by the path."
    echo "--tap-print           - Print supported TAP features"
    echo "--tap-remote          - Build with TAP remote."
    echo "--tap-remote-ip       - TAP remote IP (default 127.0.0.1)."
    echo "--tap-remote-port     - TAP remote port (default 8277)."
    echo "--tap-extern          - TAP extern support."
    echo "--hw-sim              - Build with hardware acceleration simulator"
    echo "--aide                - Build with aide support."
    echo "--vlong-const         - Build with constant time vlong ops."
    echo "--qa-products-path    - Arguent for path to m-qa-products. Optional."
    echo "--toolchain <rpi64|rpi32|qnx-x86> - Specify the toolchain to be used"
    echo "                          rpi64     For Raspberry Pi 64-bit"
    echo "                          rpi32     For Raspberry Pi 32-bit"
    exit
}

set -o errexit
set -o pipefail

# Place us in the dir of this script
SCRIPT_DIR=$(cd `dirname $0` && pwd)
MSS_DIR=$(cd $(pwd)/../.. && pwd)
cd $SCRIPT_DIR

echo "Building CryptoInterface Unit Test project."
. clean.sh
mkdir build

BUILD_OPTIONS=
PG_ARG=
OPERATOR_PATH=
MBED_BUILD=0
MBED_PATH=
OQS_BUILD=0
OQS_PATH=
QA_PROD_PATH=
FULL_EXPORT_ARG=
TPM2_BUILD=0
TAP_ARG=
TAP_EXTERN_ARG=
PKCS11_BUILD=0
PKCS11_PATH=
PKCS11_ARG=
DATA_PROTECT_ARG=
TAP_DATA_PROTECT_ARG=
FIPS_ARG=
REBUILD_LIBS=1
INV_OPT=0
TAP_REMOTE=0
HW_ACCEL_ARG=
AIDE_ARG=
SCRAM_ARG=" --scram"
CVC_ARG=" --cvc"

# Default to x64 unless toolchain is provided
X64=" --x64"
TARGET_PLATFORM=
XC_BIN_PATH=
TOOLCHAIN=
BUILD_FOR_OSI=0

source ../shared_cmake/get_toolchain.sh

while test $# -gt 0
do
    case "$1" in
        --no-ci)
          echo "Building with Crypto Interface disabled...";
          BUILD_OPTIONS+=" -DCM_DISABLE_CI=ON -DCM_DISABLE_PQC=ON"
          CVC_ARG=""
          ;;
        --pg)
          echo "Enabling callstack tracing build..."
          BUILD_OPTIONS+=" -DCM_ENABLE_PG=ON"
          PG_ARG="$1"
          ;;
        --speedtest)
          echo "Building with speedtests enabled...";
          BUILD_OPTIONS+=" -DCM_ENABLE_SPEEDTEST=ON"
          ;;
        --quick)
          echo "Building with quicktest enabled...";
          BUILD_OPTIONS+=" -DCM_ENABLE_QUICKTEST=ON"
          ;;
        --operator-path)
          OPERATOR_PATH=$2; BUILD_OPTIONS+=" -DCM_ENABLE_OPERATORS=ON -DCM_OPERATOR_PATH=$OPERATOR_PATH";
          FULL_EXPORT_ARG+=" --operator-path ${OPERATOR_PATH}"
          shift
          ;;
        --mbedtls)
          echo "-- Building with mbedtls enabled...";
          BUILD_OPTIONS+=" -DCM_ENABLE_MBED=ON -DCM_DISABLE_SCRAM=ON"; MBED_BUILD=1
          SCRAM_ARG=""
          ;;
        --mbed-path)
          MBED_PATH=$2; BUILD_OPTIONS+=" -DCM_MBED_PATH=$MBED_PATH";
          FULL_EXPORT_ARG+=" --export --mbed --mbed-path ${MBED_PATH}"
          shift
          ;;
        --oqs)
          echo "-- Building with oqs enabled...";
          BUILD_OPTIONS+=" -DCM_ENABLE_OQS=ON"; OQS_BUILD=1
          ;;
        --oqs-path)
          OQS_PATH=$2; BUILD_OPTIONS+=" -DCM_OQS_PATH=$OQS_PATH";
          FULL_EXPORT_ARG+=" --oqs --oqs-path ${OQS_PATH}"
          shift
          ;;
        --tpm2)
          echo "-- Building with tpm2 enabled...";
          BUILD_OPTIONS+=" -DCM_ENABLE_TPM2=ON"; TPM2_BUILD=1
          ;;
        --pkcs11-dynamic)
          echo "-- Building with dynamic pkcs11 library loading enabled...";
          BUILD_OPTIONS+=" -DCM_ENABLE_PKCS11=ON"; PKCS11_BUILD=1
          PKCS11_ARG="--pkcs11-dynamic"
          ;;
        --softhsm2)
          echo "-- Building with softhsm2 enabled...";
          BUILD_OPTIONS+=" -DCM_ENABLE_PKCS11=ON -DCM_ENABLE_SOFTHSM=ON"; PKCS11_BUILD=1
          PKCS11_ARG=" --softhsm2"
          ;;
        --cloudhsm)
          echo "-- Building with couldhsm enabled...";
          BUILD_OPTIONS+=" -DCM_ENABLE_PKCS11=ON -DCM_ENABLE_CLOUDHSM=ON"; PKCS11_BUILD=1
          PKCS11_ARG=" --cloudhsm"
          ;;
        --pkcs11-tee)
          echo "-- Building with tee pkcs11 enabled...";
          BUILD_OPTIONS+=" -DCM_ENABLE_PKCS11=ON -DCM_ENABLE_PKCS11_TEE=ON"; PKCS11_BUILD=1
          PKCS11_ARG=" --pkcs11-tee"
          ;;
        --dssm)
          echo "-- Building with Digicert ssm enabled...";
          BUILD_OPTIONS+=" -DCM_ENABLE_PKCS11=ON -DCM_ENABLE_DSSM=ON"; PKCS11_BUILD=1
          PKCS11_ARG=" --dssm"
          ;;
        --pkcs11-path)
          PKCS11_PATH=$2; BUILD_OPTIONS+=" -DCM_PKCS11_PATH=$PKCS11_PATH";
          PKCS11_ARG+=" --pkcs11-path ${PKCS11_PATH}"
          shift
          ;;
        --tap-print)
          echo "Building with printing of TAP features...";
          BUILD_OPTIONS+=" -DCM_ENABLE_TAP_PRINT=ON"
          ;;
        --tap-extern)
          TAP_EXTERN_ARG=" --tap-extern"
          BUILD_OPTIONS+=" -DCM_ENABLE_TAP_EXTERN=ON"
          ;;
        --tap-remote)
          TAP_REMOTE=1
          ;;
        --tap-remote-ip)
          BUILD_OPTIONS+=" -DTAP_SERVER_NAME=\"$2\""
          shift
          ;;
        --tap-remote-port)
          BUILD_OPTIONS+=" -DTAP_SERVER_PORT=$2"
          shift
          ;;
        --data-protect)
          DATA_PROTECT_ARG="$1"
          ;;
        --tap-data-protect)
          TAP_DATA_PROTECT_ARG="$1"
          DATA_PROTECT_ARG='--data-protect'
          ;;
        --qa-products-path)
          QA_PROD_PATH=$2
          BUILD_OPTIONS+=" -DCM_QA_PATH=$QA_PROD_PATH";
          shift
          ;;
        --hw-sim)
          echo "Building with hardware acceleration simulator...";
          BUILD_OPTIONS+=" -DCM_ENABLE_HW_SIM=ON"
          HW_ACCEL_ARG=" --hw-accel"
          CVC_ARG=""
          ;;
        --aide)
          AIDE_ARG=" --aide"
          BUILD_OPTIONS+=" -DCM_ENABLE_AIDE=ON"
          ;;
        --fips)
          echo "Building with FIPS...";
          BUILD_OPTIONS+=" -DCM_ENABLE_FIPS=ON"
          FIPS_ARG="$1"
          ;;
        --vlong-const)
          echo "Building with vlong constant time ops"
          VLONG_ARG="$1"
          ;;
        --toolchain)
          X64=""
          TOOLCHAIN=" --toolchain ${2}"
          BUILD_OPTIONS+=" -DCM_TOOLCHAIN=${2}"
          TARGET_PLATFORM=$(get_platform "${2}") || INV_OPT=1
          XC_BIN_PATH=$(get_sysroot_bin "${2}") || INV_OPT=1
          export PATH=${XC_BIN_PATH}:$PATH
          shift
          ;;
        --no-lib-rebuild)
          REBUILD_LIBS=0
          ;;
        --build-for-osi)
            echo "Enabling BUILD_FOR_OSI...";
            BUILD_OPTIONS+=" -DBUILD_FOR_OSI=ON"
            BUILD_FOR_OSI=1
            ;;
        --help)
          INV_OPT=1
          ;;
        ?|-?)
          INV_OPT=1
          ;;
        --*)
          echo "Invalid option: $1"
          ;;
        *)
          echo "Argument: $1"
          ;;
    esac
    shift
done

# Check if building for OSI
source $SCRIPT_DIR/../../scripts/check_for_osi.sh
if [ ${OSI_BUILD} -eq 1 ]; then
    BUILD_OPTIONS+=" -DBUILD_FOR_OSI=ON"
fi

if [ ${INV_OPT} -eq 1 ]; then
    show_usage
fi

if [ $MBED_BUILD -eq 1 ]; then
    if [ -z $MBED_PATH ]; then
        printf "\n--mbedtls is enabled but no path is provided via --mbed-path. Exiting.\n\n"
        exit 1
    fi
fi

if [ $OQS_BUILD -eq 1 ]; then
    if [ -z $OQS_PATH ]; then
        printf "\n--oqs is enabled but no path is provided via --oqs-path. Exiting.\n\n"
        exit 1
    fi
fi

if [ $OQS_BUILD -eq 0 ] && [ $MBED_BUILD -eq 1 ]; then
    echo "Export Build with no oqs, disabling PQC";
    BUILD_OPTIONS+=" -DCM_DISABLE_PQC=ON"
    FULL_EXPORT_ARG+=" --disable-pqc"
fi

if [ $PKCS11_BUILD -eq 1 ] || [ $TPM2_BUILD -eq 1 ]; then
    if [ $TAP_REMOTE -eq 1 ]; then
        BUILD_OPTIONS+=" -DCM_CLIENT_TAP=REMOTE"
        TAP_ARG=" --tap-remote"
    else
        BUILD_OPTIONS+=" -DCM_CLIENT_TAP=LOCAL"
        TAP_ARG=" --tap-local"
    fi
fi

echo "Building dependent libs"
export WORKSPACE=${MSS_DIR}

if [ $REBUILD_LIBS -eq 1 ]; then
  if [ $PKCS11_BUILD -eq 1 ]; then
    if [ "$TOOLCHAIN" == " --toolchain rpi64" ]; then
      cd ${MSS_DIR}/scripts/ci/tp_shared_libs
      ./ci_shared_libs_pkcs11_rpi64.sh --gdb --debug --des --arc4 ${CVC_ARG} ${SCRAM_ARG} ${TAP_ARG} ${PKCS11_ARG} \
        ${DATA_PROTECT_ARG} ${TAP_DATA_PROTECT_ARG} ${FIPS_ARG} ${FULL_EXPORT_ARG}
    elif [ "$TOOLCHAIN" == " --toolchain rpi32" ]; then
      cd ${MSS_DIR}/scripts/ci/tp_shared_libs
      ./ci_shared_libs_pkcs11_rpi32.sh --gdb --debug --des --arc4 ${CVC_ARG} ${SCRAM_ARG} ${TAP_ARG} ${PKCS11_ARG} \
        ${DATA_PROTECT_ARG} ${TAP_DATA_PROTECT_ARG} ${FIPS_ARG} ${FULL_EXPORT_ARG}
    else
      cd ${MSS_DIR}/scripts/ci/tp_shared_libs
      ./ci_shared_libs_pkcs11_nux64.sh --gdb --debug --des --arc4 ${CVC_ARG} ${SCRAM_ARG} ${TAP_ARG} ${PKCS11_ARG} \
        ${DATA_PROTECT_ARG} ${TAP_DATA_PROTECT_ARG} ${FIPS_ARG} ${FULL_EXPORT_ARG} ${TAP_EXTERN_ARG}
    fi
  else
    cd ${MSS_DIR}/scripts
    ./build_crypto_shared_libs.sh --gdb ${PG_ARG} --debug --cert --des --arc4 ${CVC_ARG} ${SCRAM_ARG} ${HW_ACCEL_ARG} ${TAP_ARG} ${TAP_EXTERN_ARG} \
      ${DATA_PROTECT_ARG} ${TAP_DATA_PROTECT_ARG} ${FIPS_ARG} ${VLONG_ARG} ${FULL_EXPORT_ARG} ${TOOLCHAIN} ${AIDE_ARG}
  fi
  if [ $MBED_BUILD -eq 1 ]; then
    rm -f ${MSS_DIR}/bin/libcryptomw.so
  else
    rm -f ${MSS_DIR}/bin/libnanocrypto.so
  fi
  rm -f ${MSS_DIR}/bin/libcryptointerface.so
  # Build crypto libs again, but with all algs specified
  cd ${MSS_DIR}/projects/crypto
  if [ $PKCS11_BUILD -eq 1 ] && [ "$TOOLCHAIN" == " --toolchain rpi32" ]; then
    ./build.sh --gdb ${PG_ARG} --debug --ci-tests ${TOOLCHAIN} --x32 ${FIPS_ARG} ${VLONG_ARG} ${FULL_EXPORT_ARG} --tap --tpm2
  elif [ $PKCS11_BUILD -eq 1 ] || [ $TPM2_BUILD -eq 1 ]; then
    ./build.sh --gdb ${PG_ARG} --debug --ci-tests ${X64} ${TOOLCHAIN} ${FIPS_ARG} ${VLONG_ARG} ${FULL_EXPORT_ARG} --tap ${TAP_EXTERN_ARG} --tpm2
  else
    ./build.sh --gdb ${PG_ARG} --debug ${HW_ACCEL_ARG} --ci-tests ${X64} ${TOOLCHAIN} ${FIPS_ARG} ${VLONG_ARG} ${FULL_EXPORT_ARG}
  fi
fi

cd ${SCRIPT_DIR}/build

echo "BUILD_OPTIONS=${BUILD_OPTIONS}"
echo "TARGET_PLATFORM=${TARGET_PLATFORM}"

cmake ${TARGET_PLATFORM} -DCMAKE_BUILD_TYPE=Debug CMakeLists.txt ../. ${BUILD_OPTIONS}
# make w/ however many virtual cores the system has.
make -j$(getconf _NPROCESSORS_ONLN)
