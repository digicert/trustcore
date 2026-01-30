#!/usr/bin/env bash

set -e

######################
function show_usage
{
  echo ""
  echo "./build.sh [Options] "
  echo ""
  echo "   --gdb              - Build Debug version."
  echo "   --debug            - Build with Mocana logging enabled for specific build executable."
  echo "   --mauth            - Build with Mutual Authentication support."
  echo "   --disable-tls13    - Build with TLS 1.3 disabled."
  echo "   --disable-psk      - Build with TLS 1.3 PSK disabled."
  echo "   --disable-0rtt     - Build with TLS 1.3 0-RTT disabled."
  echo "   --oqs              - Build with OQS support."
  echo "   --oqs-path         - Path to the oqs library."
  echo "   --pss-auto-recover - Allow NanoSSL to recover the salt length for PSS signatures."
  echo "   --tap-deferred-unload - Build NanoSSL enabling deferrred TAP Key Unload."
  echo "   --tap-hybrid-sign - Build with hybrid signing scheme using for SW and HW."
  echo ""
  exit -1
}

BUILD_OPTIONS=""
MAUTH_OPTION=""
TLS13_OPTION=""
PSS_VAR_SALT_OPTION=""
PSS_AUTO_RECOVER_OPTION=""
TAP_HYBRID_SIGN_OPTION=""
ARCH_OPTION=
INV_OPT=0
OQS_ARG=""
OQS_PATH=""
OQS_PATH_ARG=""
DEFER_UNLOAD_OPTION=""
CERT_OPTION=""

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
        --x32)
            ARCH_OPTION="--x32"
            ;;
        --x64)
            ARCH_OPTION="--x64"
            ;;
        --tap-deferred-unload)
            echo "-- Building with tap deferred unload enabled..."
            DEFER_UNLOAD_OPTION+=" $1"
            CERT_OPTION=" --cert"
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

export WORKSPACE="${SCRIPT_DIR}/../.."

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

        rm -f ${MSS_DIR}/bin/*.so
        rm -f ${MSS_DIR}/bin/*.a

    fi
    cd ${MSS_PROJECTS_DIR}/common && ./build.sh $BUILD_OPTIONS ${ARCH_OPTION} --uri
    cd ${MSS_PROJECTS_DIR}/platform && ./build.sh $BUILD_OPTIONS ${ARCH_OPTION}
    cd ${MSS_PROJECTS_DIR}/asn1 && ./build.sh $BUILD_OPTIONS ${ARCH_OPTION}
    cd ${MSS_PROJECTS_DIR}/nanocap && ./build.sh $BUILD_OPTIONS --suiteb ${ARCH_OPTION}
    cd ${MSS_PROJECTS_DIR}/nanotap2_common && ./build.sh $BUILD_OPTIONS --tap-local --tpm2 ${ARCH_OPTION}
    cd ${MSS_PROJECTS_DIR}/nanotap2_configparser && ./build.sh $BUILD_OPTIONS ${ARCH_OPTION}
    cd ${MSS_PROJECTS_DIR}/nanotap2 && ./build.sh $BUILD_OPTIONS --tap-local --tpm2 ${ARCH_OPTION} nanotap2
    cd ${MSS_PROJECTS_DIR}/crypto && ./build.sh $BUILD_OPTIONS $PSS_VAR_SALT_OPTION $TAP_HYBRID_SIGN_OPTION --suiteb --tap --tpm2 --ssl ${ARCH_OPTION} ${OQS_ARG} ${OQS_PATH_ARG} --nil-cipher
    cd ${MSS_PROJECTS_DIR}/tpm2 && ./build.sh $BUILD_OPTIONS --suiteb ${ARCH_OPTION}
    cd ${MSS_PROJECTS_DIR}/smp_tpm2 && ./build.sh $BUILD_OPTIONS --suiteb ${ARCH_OPTION}
    cd ${MSS_PROJECTS_DIR}/initialize && ./build.sh $BUILD_OPTIONS ${ARCH_OPTION}
    cd ${MSS_PROJECTS_DIR}/nanocert && ./build.sh $BUILD_OPTIONS --suiteb --tap ${ARCH_OPTION} ${OQS_ARG} ${CERT_OPTION} --ocsp
    cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh --clean $BUILD_OPTIONS $TLS13_OPTION $PSS_AUTO_RECOVER_OPTION --disable-servername-validation --disable-client-commonname-validation --suiteb --tap --nil-cipher --anon-support ${ARCH_OPTION} ${OQS_ARG} --enable_ticket_tls12 --rehandshake --srp --psk --ocsp nanossl
done
