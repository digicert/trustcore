#!/usr/bin/env bash

######################
function show_usage
{
  echo ""
  echo "./build.sh [Options] "
  echo ""
  echo "   --gdb             - Build Debug version."
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
  echo "   --fips            - Build with FIPS enabled."
  echo "   --data-protect    - Build with Data protect support."
  echo "   --ssl_interop_test - Build with support for interop tests."
  echo "   --ssl_interop_psk_test - Build with support for internal PSK interop tests."
  echo "   --ssl_interop_ex_psk_test - Build with support for external PSK interop tests."
  echo "   --ssl_interop_ticket_test - Build with support for ticket and heartbeat interop tests."
  echo "   --ssl_interop_sessionid_test - Build with support for sessionid interop tests."
  echo "   --graceful_shutdown - Build with client example shutdown gracefully."
  echo "   --disable-cbc     - Build with CBC ciphers disabled."
  echo "   --dh_pub_pad      - Pad DH public keys."
  echo "   --cvc             - Build with support for Card Verifiable Certificates."
  echo "   --client-cert-cb  - Build with client certificate callback."
  echo "   --keylog          - Building with key logging enabled."
  echo ""
  exit -1
}

BUILD_OPTIONS=""
MAUTH_OPTION=""
OCSP_OPTION=""
URI_OPTION=""
TLS13_OPTION=""
INV_OPT=0
PQC_ARG=""
OQS_PATH=""
OQS_PATH_ARG=""
SESSION_TICKET_OPTION=""
FIPS_OPTION=""
DATA_PROTECT_OPTION=""
SP800_135_OPTION=""
CBC_OPTION=""
CVC_OPTION=""
CVC_SSL_OPTION=""
CLIENT_CERT_CB_OPTION=""
SSL_CLIENT_TARGET="ssl_client"
EXAMPLE_INTEROP_OPTION=""
DH_PUB_PAD_OPTION=""
KEYLOG_OPTION=""

while test $# -gt 0
do
    case "$1" in
        --gdb)
            echo "Enabling Debug build...";
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
            SESSION_TICKET_OPTION="$1"
            ;;
        --data-protect)
            echo "Building with data protect..."
            DATA_PROTECT_OPTION=" $1"
            ;;
        --ssl_interop_test)
            echo "Building with support for interop tests..."
            EXAMPLE_INTEROP_OPTION=" $1"
            ;;
        --ssl_interop_psk_test)
            echo "Building with support for internal PSK interop tests..."
            EXAMPLE_INTEROP_OPTION=" $1"
            ;;
        --ssl_interop_ex_psk_test)
            echo "Building with support for external PSK interop tests..."
            EXAMPLE_INTEROP_OPTION=" $1"
            ;;
        --ssl_interop_ticket_test)
            echo "Building with support for ticket and heartbeat interop tests..."
            EXAMPLE_INTEROP_OPTION=" $1"
            ;;
        --ssl_interop_sessionid_test)
            echo "Building with support for sesison id interop tests..."
            EXAMPLE_INTEROP_OPTION=" $1"
            ;;
        --graceful_shutdown)
            echo "Building with client example shutdown gracefully..."
            EXAMPLE_INTEROP_OPTION=" $1"
            ;;
        --disable-cbc)
            echo "Building with CBC ciphers disabled..."
            CBC_OPTION=" $1"
            ;;
        --dh_pub_pad)
            echo "Building with DH public padding...";
            DH_PUB_PAD_OPTION+=" $1"
            ;;
        --cvc)
            echo "Building with CVC..."
            CVC_OPTION=" --cvc"
            CVC_SSL_OPTION=" --disable-servername-validation"
            ;;
        --client-cert-cb)
            echo "Building with client certificate callback..."
            CLIENT_CERT_CB_OPTION=" --client-cert-cb"
            ;;
        --sp800-135)
            echo "Building for testing SP800-135..."
            SP800_135_OPTION=" --sp800-135"
            SSL_CLIENT_TARGET="ssl_client_sp800_135"
            ;;
        --x32)
            BUILD_OPTIONS+=" $1"
            ;;
        --x64)
            BUILD_OPTIONS+=" $1"
            ;;
        --fips)
            echo "Building with FIPS enabled..."
            FIPS_OPTION=" $1"
            ;;
        --keylog)
            echo "Building with key logging enabled..."
            KEYLOG_OPTION=" $1"
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
echo "*** Building ssl client TAP (local) version of CAP..."
echo "***************************************************************"
for pass in first second
do
    if [ "$pass" == "first" ]; then
        echo "***************************************************************"
        echo "*** Cleaning binaries and libraries "
        echo "***************************************************************"

        for libs in ${MSS_DIR}/bin/*.so; do
            if [[ ! "$libs" == *libmss.so ]] || [[ -z "$FIPS_OPTION" ]]; then
                rm -f $libs
            fi
        done
        rm ${MSS_DIR}/bin/*.a
        rm ${MSS_DIR}/bin/ssl_client

    fi
    cd ${MSS_PROJECTS_DIR}/platform && ./build.sh $BUILD_OPTIONS $FIPS_OPTION &&
    cd ${MSS_PROJECTS_DIR}/common && ./build.sh $BUILD_OPTIONS $URI_OPTION $FIPS_OPTION ${DATA_PROTECT_OPTION} &&
    cd ${MSS_PROJECTS_DIR}/asn1 && ./build.sh $BUILD_OPTIONS ${PQC_ARG} ${CVC_OPTION} &&
    cd ${MSS_PROJECTS_DIR}/initialize && ./build.sh $BUILD_OPTIONS ${DATA_PROTECT_OPTION} &&
    cd ${MSS_PROJECTS_DIR}/nanocap && ./build.sh $BUILD_OPTIONS --suiteb &&
    cd ${MSS_PROJECTS_DIR}/crypto && ./build.sh $BUILD_OPTIONS --suiteb --ssl ${PQC_ARG} ${OQS_PATH_ARG} ${HW_ACCEL_OPTION} $FIPS_OPTION &&
    cd ${MSS_PROJECTS_DIR}/nanocert && ./build.sh $BUILD_OPTIONS $OCSP_OPTION --suiteb ${PQC_ARG} ${CVC_OPTION} $FIPS_OPTION &&

    if [ ! -z "${DATA_PROTECT_OPTION}" ]; then
        cd ${MSS_PROJECTS_DIR}/data_protection && ./clean.sh && ./build.sh $BUILD_OPTIONS
    fi

    cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh --clean $BUILD_OPTIONS $KEYLOG_OPTION $TLS13_OPTION $OCSP_OPTION --suiteb ${PQC_ARG} ${SESSION_TICKET_OPTION} ${SP800_135_OPTION} ${CVC_OPTION} ${CVC_SSL_OPTION} $FIPS_OPTION ${CBC_OPTION} ${DH_PUB_PAD_OPTION} nanossl

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

        cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh --clean $BUILD_OPTIONS $KEYLOG_OPTION $TLS13_OPTION $OCSP_OPTION $FIPS_OPTION  --suiteb ${PQC_ARG} ${SESSION_TICKET_OPTION} $MAUTH_OPTION ${CVC_OPTION} ${CVC_SSL_OPTION} ${CLIENT_CERT_CB_OPTION} ${DATA_PROTECT_OPTION} ${EXAMPLE_INTEROP_OPTION} ${SSL_CLIENT_TARGET}
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
