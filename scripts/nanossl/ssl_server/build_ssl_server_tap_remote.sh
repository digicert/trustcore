#!/usr/bin/env bash

######################
function show_usage
{
  echo ""
  echo "./build.sh [Options]"
  echo ""
  echo "   --gdb              - Build Debug version."
  echo "   --debug            - Build with Mocana logging enabled for specific build executable."
  echo "   --mauth            - Build with Mutual Authentication support."
  echo "   --tap-remote-tcp   - Build NanoTAP Remote mode with TCP connection."
  echo "   --oqs              - Build with OQS support."
  echo "   --oqs-path         - Path to the oqs library."
  echo "   --disable-tls13    - Build with TLS 1.3 disabled."
  echo "   --disable-psk      - Build with TLS 1.3 PSK disabled."
  echo "   --disable-0rtt     - Build with TLS 1.3 0-RTT disabled."
  echo "   --pss-auto-recover - Allow NanoSSL to recover the salt length for PSS signatures."
  echo "   --tap-hybrid-sign  - Build with hybrid signing scheme using for SW and HW."
  echo "   --data-protect     - Build with Data protect support."
  echo "   --tap-data-protect - Build with TAP Data protect support."
  echo "   --cvc              - Build with support for Card Verifiable Certificates."
  echo ""
  exit -1
}

BUILD_OPTIONS=""
MAUTH_OPTION=""
TAP_REMOTE_OPTION="--tap-remote"
TLS13_OPTION=""
PSS_VAR_SALT_OPTION=""
PSS_AUTO_RECOVER_OPTION=""
TAP_HYBRID_SIGN_OPTION=""
SSL_SERVER_GW=0
INV_OPT=0
OQS_ARG=""
OQS_PATH=""
OQS_PATH_ARG=""
DATA_PROTECT_OPTION=""
TAP_DATA_PROTECT_OPTION=""
CVC_OPTION=""
CVC_SSL_OPTION=""

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
        --oqs)
            echo "-- Building with oqs enabled...";
            OQS_ARG=" --oqs"
            ;;
        --oqs-path)
            OQS_PATH=$2;
            OQS_PATH_ARG=" --oqs-path ${OQS_PATH}"
            shift
            ;;
        --pss-auto-recover)
            echo "Building with PSS auto recover...";
            PSS_AUTO_RECOVER_OPTION=" $1"
            PSS_VAR_SALT_OPTION=" --pss-var-salt"
            ;;
        --tap-remote-tcp)
            TAP_REMOTE_OPTION="--tap-remote-tcp"
            ;;
        --ssl-server-gw)
            SSL_SERVER_GW=1
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
        --tap-hybrid-sign)
            echo "Building with TAP hybrid sign...";
            TAP_HYBRID_SIGN_OPTION=" $1"
            ;;
        --data-protect)
            echo "Building with data protect..."
            DATA_PROTECT_OPTION=" $1"
            ;;
        --tap-data-protect)
            echo "Building with TAP data protect..."
            TAP_DATA_PROTECT_OPTION=" $1"
            ;;
        --cvc)
            echo "Building with CVC..."
            CVC_OPTION=" --cvc"
            CVC_SSL_OPTION=" --disable-servername-validation"
            ;;
        --x32)
            BUILD_OPTIONS+=" $1"
            ;;
        --x64)
            BUILD_OPTIONS+=" $1"
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

echo "BUILD_OPTIONS=$BUILD_OPTIONS"
echo "MAUTH_OPTION=$MAUTH_OPTION"
echo "TAP_REMOTE_OPTION=$TAP_REMOTE_OPTION"

######################

SCRIPT_DIR=$( cd $(dirname $0) ; pwd -P )

export WORKSPACE="${SCRIPT_DIR}/../../.."

echo "WORKSPACE=${WORKSPACE}"
export MSS_DIR=${WORKSPACE}
export MSS_PROJECTS_DIR=${MSS_DIR}/projects

echo "***************************************************************"
echo "*** Building ssl server client TAP (remote) version of CAP..."
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

    cd ${MSS_PROJECTS_DIR}/common && ./build.sh $BUILD_OPTIONS $DATA_PROTECT_OPTION &&
    cd ${MSS_PROJECTS_DIR}/platform && ./build.sh $BUILD_OPTIONS &&
    cd ${MSS_PROJECTS_DIR}/asn1 && ./build.sh $BUILD_OPTIONS ${OQS_ARG} ${CVC_OPTION} &&
    cd ${MSS_PROJECTS_DIR}/nanocap && ./build.sh $BUILD_OPTIONS --suiteb &&
    cd ${MSS_PROJECTS_DIR}/nanotap2_common && ./build.sh $BUILD_OPTIONS --tap-remote &&
    cd ${MSS_PROJECTS_DIR}/nanotap2_configparser && ./build.sh $BUILD_OPTIONS &&
    cd ${MSS_PROJECTS_DIR}/nanotap2 && ./build.sh $BUILD_OPTIONS --tap-remote clientcomm &&
    cd ${MSS_PROJECTS_DIR}/nanotap2 && ./build.sh $BUILD_OPTIONS --tap-remote $DATA_PROTECT_OPTION nanotap2 &&
    cd ${MSS_PROJECTS_DIR}/crypto && ./build.sh $BUILD_OPTIONS $PSS_VAR_SALT_OPTION $TAP_HYBRID_SIGN_OPTION --suiteb --tap --ssl ${OQS_ARG} ${OQS_PATH_ARG} &&
    cd ${MSS_PROJECTS_DIR}/initialize && ./build.sh $BUILD_OPTIONS $DATA_PROTECT_OPTION $TAP_DATA_PROTECT_OPTION &&
    cd ${MSS_PROJECTS_DIR}/nanocert && ./build.sh $BUILD_OPTIONS --suiteb --tap ${OQS_ARG} ${CVC_OPTION} &&

if [ ! -z "${DATA_PROTECT_OPTION}" ]; then
    cd ${MSS_PROJECTS_DIR}/data_protection && ./clean.sh && ./build.sh $BUILD_OPTIONS
fi

    cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh --clean $BUILD_OPTIONS $TLS13_OPTION $PSS_AUTO_RECOVER_OPTION --suiteb --tap ${OQS_ARG} ${CVC_OPTION} ${CVC_SSL_OPTION} nanossl
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

        if [ ${SSL_SERVER_GW} -eq 1 ]; then
            cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh --clean $BUILD_OPTIONS $TLS13_OPTION --suiteb $TAP_REMOTE_OPTION $MAUTH_OPTION ${OQS_ARG} ssl_server_gw
        else
            cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh --clean $BUILD_OPTIONS $TLS13_OPTION --suiteb $TAP_REMOTE_OPTION $MAUTH_OPTION ${OQS_ARG} $DATA_PROTECT_OPTION ${CVC_OPTION} ${CVC_SSL_OPTION} ssl_server
        fi

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
