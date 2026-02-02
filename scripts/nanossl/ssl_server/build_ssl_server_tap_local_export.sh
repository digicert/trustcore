#!/usr/bin/env bash

function show_usage
{
  echo ""
  echo "./build.sh  --mbed_path <path_to_libraries> [Options] "
  echo ""
  echo "   --mbed-path        - Path to mbed install location, can be absolute or relative."
  echo "   --gdb              - Build Debug version."
  echo "   --debug            - Build with Mocana logging enabled for specific build executable." echo "   --mauth           - Build with Mutual Authentication support."
  echo "   --skip-cap         - Do not build libnanocap library."
  echo "   --disable-tls13    - Build with TLS 1.3 disabled."
  echo "   --disable-psk      - Build with TLS 1.3 PSK disabled."
  echo "   --disable-0rtt     - Build with TLS 1.3 0-RTT disabled."
  echo "   --pss-auto-recover - Allow NanoSSL to recover the salt length for PSS signatures."
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
MBED_PATH=""
SKIP_CAP=0
INV_OPT=0

while test $# -gt 0
do
    case "$1" in
        --mbed-path)
            MBED_PATH="$2"; shift
            ;;
        --gdb)
            echo "Enabling Debug build...";
            BUILD_OPTIONS+=" $1"
            ;;
        --debug)
            echo "Building with Debug logs enabled...";
            BUILD_OPTIONS+=" $1"
            ;;
        --mauth)
            echo "Building with Mutual Authentication enabled...";
            MAUTH_OPTION=" $1"
            ;;
        --pss-auto-recover)
            echo "Building with PSS auto recover...";
            PSS_AUTO_RECOVER_OPTION=" $1"
            PSS_VAR_SALT_OPTION=" --pss-var-salt"
            ;;
        --skip-cap)
            echo "Skip building libnanocap library...";
            SKIP_CAP=1
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

# Caller must provide the --mbed-path argument to this bash script which is a valid
# path to the top level directory of a mbedtls source. If a path is not provided
# then an error will occur.
if [ -z "$MBED_PATH" ]
then
    echo "No path provided to mbedtls source..."
    echo "Exiting build"
    exit 1
fi

if [ ! -z "${BUILD_OPTIONS}" ]; then
    echo "BUILD_OPTIONS=${BUILD_OPTIONS}"
    echo ""
fi

#echo "MBED_PATH=$MBED_PATH"
#echo "BUILD_OPTIONS=$BUILD_OPTIONS"
#echo "MAUTH_OPTION=$MAUTH_OPTION"
#echo "SKIP_CAP=$SKIP_CAP"

######################

SCRIPT_DIR=$( cd $(dirname $0) ; pwd -P )

export WORKSPACE="${SCRIPT_DIR}/../../.."

echo "WORKSPACE=${WORKSPACE}"
export MSS_DIR=${WORKSPACE}
export MSS_PROJECTS_DIR=${MSS_DIR}/projects

if [ ${SKIP_CAP} -eq 1 ] && [ ! -e "${MSS_DIR}/bin/libnanocap.so" ]; then
    echo "libnanocap.so does not exist in the bin/ directory..."
    echo "Exiting build"
    exit 1
fi

echo "***************************************************************"
echo "*** Building ssl server TAP (local) version of CAP..."
echo "***************************************************************"
for pass in first second
do
    if [ "$pass" == "first" ]; then
        echo "***************************************************************"
        echo "*** Cleaning binaries and libraries "
        echo "***************************************************************"

        if [ ${SKIP_CAP} -eq 1 ]; then
            mv ${MSS_DIR}/bin/libnanocap.so ${MSS_DIR}/bin/libnanocap.so.backup
        fi

        rm ${MSS_DIR}/bin/*.so
        rm ${MSS_DIR}/bin/*.a
        rm ${MSS_DIR}/bin/ssl_server

        if [ ${SKIP_CAP} -eq 1 ]; then
            mv ${MSS_DIR}/bin/libnanocap.so.backup ${MSS_DIR}/bin/libnanocap.so
        fi

    fi
    cd ${MSS_PROJECTS_DIR}/common && ./build.sh $BUILD_OPTIONS &&
    cd ${MSS_PROJECTS_DIR}/platform && ./build.sh $BUILD_OPTIONS &&
    cd ${MSS_PROJECTS_DIR}/asn1 && ./build.sh $BUILD_OPTIONS --disable-pqc &&

    if [ ${SKIP_CAP} -eq 0 ]; then
        cd ${MSS_PROJECTS_DIR}/nanocap && ./build.sh $BUILD_OPTIONS
    fi

    cd ${MSS_PROJECTS_DIR}/nanotap2_common && ./build.sh $BUILD_OPTIONS --tap-local --tpm2 &&
    cd ${MSS_PROJECTS_DIR}/nanotap2_configparser && ./build.sh $BUILD_OPTIONS &&
    cd ${MSS_PROJECTS_DIR}/nanotap2 && ./build.sh $BUILD_OPTIONS --tap-local --tpm2 nanotap2 &&
    cd ${MSS_PROJECTS_DIR}/crypto && ./clean.sh && ./build.sh $BUILD_OPTIONS $PSS_VAR_SALT_OPTION $TAP_HYBRID_SIGN_OPTION --disable-pqc --ssl --export --tap --tpm2 --mbed --mbed-path "${MBED_PATH}" &&
    cd ${MSS_PROJECTS_DIR}/tpm2 && ./build.sh $BUILD_OPTIONS &&
    cd ${MSS_PROJECTS_DIR}/smp_tpm2 && ./build.sh $BUILD_OPTIONS &&
    cd ${MSS_PROJECTS_DIR}/initialize && ./build.sh $BUILD_OPTIONS &&
    cd ${MSS_PROJECTS_DIR}/nanocert && ./build.sh $BUILD_OPTIONS --disable-pqc --export --tap &&
    cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh --clean $BUILD_OPTIONS $TLS13_OPTION $PSS_AUTO_RECOVER_OPTION --disable-pqc --tap --export nanossl
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

        cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh $BUILD_OPTIONS $TLS13_OPTION --disable-pqc --tap-local --export $MAUTH_OPTION ssl_server
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
