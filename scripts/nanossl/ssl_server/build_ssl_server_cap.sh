#!/usr/bin/env bash

######################
function show_usage
{
  echo ""
  echo "./build.sh [Options] "
  echo ""
  echo "   --gdb             - Build Debug version."
  echo "   --pg              - Build with call stack tracing."
  echo "   --debug           - Build with Mocana logging enabled for specific build executable."
  echo "   --mauth           - Build with Mutual Authentication support."
  echo "   --ocsp            - Build with OCSP support."
  echo "   --disable-pqc     - Build without PQC support."
  echo "   --oqs             - Build with OQS support."
  echo "   --oqs-path        - Path to the oqs library."
  echo "   --disable-tls13   - Build with TLS 1.3 disabled."
  echo "   --disable-psk     - Build with TLS 1.3 PSK disabled."
  echo "   --disable-0rtt    - Build with TLS 1.3 0-RTT disabled."
  echo "   --hw-accel        - Build with Hardware Accelerator Support."
  echo "   --enable_ticket_tls12 - Build with session ticket support."
  echo "   --enable_3des     - Enable 3DES cipher support."
  echo "   --enable_ecp192   - Enable EC P-192 curve support."
  echo "   --data-protect    - Build with Data protect support."
  echo "   --ssl_interop_test - Build with support for interop tests."
  echo "   --graceful_shutdown - Build with server example shutdown gracefully."
  echo "   --cvc             - Build with support for Card Verifiable Certificates."
  echo "   --dh_pub_pad      - Pad DH public keys."
  echo ""
  exit -1
}

BUILD_OPTIONS=""
MAUTH_OPTION=""
OCSP_OPTION=""
URI_OPTION=""
TLS13_OPTION=""
ARCH_OPTION=
HW_ACCEL_OPTION=""
INV_OPT=0
PQC_ARG=""
OQS_PATH=""
OQS_PATH_ARG=""
NANOSSL_OPTION=""
DATA_PROTECT_OPTION=""
EXAMPLE_INTEROP_OPTION=""
CVC_OPTION=""
CVC_SSL_OPTION=""
PKCS12_OPTION=""

while test $# -gt 0
do
    case "$1" in
        --gdb)
            echo "Enabling Debug build...";
            BUILD_OPTIONS+=" $1"
            ;;
        --pg)
            echo "Enabling PG call stack tracing...";
            BUILD_OPTIONS+=" $1"
            ;;
        --debug)
            echo "Building with Debug logs enabled...";
            BUILD_OPTIONS+=" $1"
            ;;
        --mauth)
            echo "Building with Mutual Authentication enabled..."
            MAUTH_OPTION=" $1"
            ;;
        --ocsp)
            echo "Building with OCSP enabled..."
            OCSP_OPTION=" $1"
            URI_OPTION=" --uri"
            ;;
        --pqc)
            echo "PQC enabled by default, ignoring legacy flag"
            ;;
        --disable-pqc)
            echo "-- Building without PQC enabled...";
            PQC_ARG=" --disable-pqc"
            ;;
        --oqs)
            echo "-- Building with PQC/OQS enabled...";
            PQC_ARG=" --oqs"
            ;;
        --oqs-path)
            OQS_PATH=$2;
            OQS_PATH_ARG=" --oqs-path ${OQS_PATH}"
            shift
            ;;
        --disable-tls13)
            echo "Building with TLS 1.3 disabled..."
            TLS13_OPTION+=" $1"
            ;;
        --disable-psk)
            echo "Building with TLS 1.3 PSK disabled..."
            TLS13_OPTION+=" $1"
            ;;
        --disable-0rtt)
            echo "Building with TLS 1.3 0-RTT disabled..."
            TLS13_OPTION+=" $1"
            ;;
        --hw-accel)
            echo "Build Hardware Accelerator Support";
            HW_ACCEL_OPTION="$1";
            ;;
        --enable_ticket_tls12)
            echo "Building with session ticket support"
            NANOSSL_OPTION+=" $1"
            ;;
        --enable_3des)
            echo "Building with 3DES enabled..."
            NANOSSL_OPTION+=" $1"
            ;;
        --enable_ecp192)
            echo "Building with EC P-192 curve enabled..."
            NANOSSL_OPTION+=" $1"
            ;;
        --data-protect)
            echo "Building with data protect..."
            DATA_PROTECT_OPTION=" $1"
            ;;
        --ssl_interop_test)
            echo "Building with support for interop tests..."
            EXAMPLE_INTEROP_OPTION=" $1"
            ;;
        --graceful_shutdown)
            echo "Building with server example shutdown gracefully..."
            EXAMPLE_INTEROP_OPTION=" $1"
            ;;
        --pkcs12)
            echo "Building with server example using PKCS12 cert..."
            PKCS12_OPTION=" $1"
            ;;
        --dh_pub_pad)
            echo "Building with DH public padding..."
            NANOSSL_OPTION+=" $1"
            ;;
        --cvc)
            echo "Building with CVC..."
            CVC_OPTION=" --cvc"
            CVC_SSL_OPTION=" --disable-servername-validation"
            ;;
        --x32)
            ARCH_OPTION="--x32"
            ;;
        --x64)
            ARCH_OPTION="--x64"
            ;;
        *)
            echo "Invalid option: $1";
            INV_OPT=1
            ;;
    esac
    shift
done

if [ ${INV_OPT} -eq 1 ]; then
  show_usage
fi

if [ ! -z "${BUILD_OPTIONS}" ]; then
  echo "BUILD_OPTIONS=${BUILD_OPTIONS}"
  echo ""
fi

######################

SCRIPT_DIR=$( cd $(dirname $0) ; pwd -P )

export WORKSPACE="${SCRIPT_DIR}/../../.."

echo "WORKSPACE=${WORKSPACE}"
export MSS_DIR=${WORKSPACE}
export MSS_PROJECTS_DIR=${MSS_DIR}/projects

echo "***************************************************************"
echo "*** Building ssl server TAP (local) version of CAP..."
echo "***************************************************************"
for pass in first second
do
    if [ "$pass" == "first" ]; then
        echo "***************************************************************"
        echo "*** Cleaning binaries and libraries "
        echo "***************************************************************"

        rm ${MSS_DIR}/bin/*.so
        rm ${MSS_DIR}/bin/*.a
        rm ${MSS_DIR}/bin/ssl_server

    fi
    cd ${MSS_PROJECTS_DIR}/common && ./build.sh $BUILD_OPTIONS $URI_OPTION ${ARCH_OPTION} ${DATA_PROTECT_OPTION} &&
    cd ${MSS_PROJECTS_DIR}/platform && ./build.sh $BUILD_OPTIONS ${ARCH_OPTION} &&
    cd ${MSS_PROJECTS_DIR}/asn1 && ./build.sh $BUILD_OPTIONS ${ARCH_OPTION} ${PQC_ARG} ${CVC_OPTION} &&
    cd ${MSS_PROJECTS_DIR}/nanocap && ./build.sh $BUILD_OPTIONS --suiteb ${ARCH_OPTION} &&
    cd ${MSS_PROJECTS_DIR}/crypto && ./build.sh $BUILD_OPTIONS --suiteb --ssl ${ARCH_OPTION} ${PQC_ARG} ${OQS_PATH_ARG} ${HW_ACCEL_OPTION} &&
    cd ${MSS_PROJECTS_DIR}/initialize && ./build.sh $BUILD_OPTIONS ${ARCH_OPTION} ${DATA_PROTECT_OPTION} &&
    cd ${MSS_PROJECTS_DIR}/nanocert && ./build.sh $BUILD_OPTIONS $OCSP_OPTION --suiteb ${PQC_ARG} ${ARCH_OPTION} ${CVC_OPTION} &&

    if [ ! -z "${DATA_PROTECT_OPTION}" ]; then
        cd ${MSS_PROJECTS_DIR}/data_protection && ./clean.sh && ./build.sh $BUILD_OPTIONS
    fi

    cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh --clean $BUILD_OPTIONS $TLS13_OPTION $OCSP_OPTION --suiteb ${PQC_ARG} ${ARCH_OPTION} ${NANOSSL_OPTION} ${CVC_OPTION} ${CVC_SSL_OPTION} ${PKCS12_OPTION} nanossl

    if test "$?" != "0"; then
        echo "*********************************************"
        echo "**** Library build failed on $pass pass  ****"
        echo "*********************************************"
        exit 1
    else
        echo "***********************************************"
        echo "****  $pass pass library build successful  ****"
        echo "***********************************************"
    fi

    if [ "$pass" == "second" ]; then

        cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh $BUILD_OPTIONS $TLS13_OPTION $OCSP_OPTION --suiteb ${PQC_ARG} $MAUTH_OPTION ${ARCH_OPTION} ${DATA_PROTECT_OPTION} ${CVC_OPTION} ${CVC_SSL_OPTION}  ${EXAMPLE_INTEROP_OPTION} ${PKCS12_OPTION} ssl_server
        if test "$?" != "0"; then
            echo "********************************"
            echo "**** Binaries build failed  ****"
            echo "********************************"
            exit 1
        else
            echo "**************************************"
            echo "**** Binaries built successfully  ****"
            echo "**************************************"
        fi
    fi
done
