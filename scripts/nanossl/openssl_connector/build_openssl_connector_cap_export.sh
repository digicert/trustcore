#!/usr/bin/env bash

set -e

######################
function show_usage
{
  echo ""
  echo "./build.sh  --mbed_path <path_to_libraries> [Options] "
  echo ""
  echo "   --mbed-path       - Path to mbed install location, can be absolute or relative."
  echo "   --gdb             - Build Debug version."
  echo "   --debug           - Build with Mocana logging enabled for specific build executable."
  echo "   --redefine        - Redefine the PEM_read_bio_PrivateKey function."
  echo "   --dtls            - Build with DTLS support."
  echo "   --skip-cap        - Do not build libnanocap library."
  echo "   --disable-tls13   - Disable with TLS 1.3."
  echo "   --disable-psk     - Build with TLS 1.3 PSK disabled."
  echo "   --disable-0rtt    - Build with TLS 1.3 0-RTT disabled."
  echo "   --openssl_1_0_2j  - (OBSOLETE) Build with openssl 1.0.2j."
  echo "   --openssl_1_0_2n  - (OBSOLETE) Build with openssl 1.0.2n."
  echo "   --openssl_1_0_2p  - (OBSOLETE) Build with openssl 1.0.2p."
  echo "   --openssl_1_0_2t  - (OBSOLETE) Build with openssl 1.0.2t."
  echo "   --openssl_1_0_2u  - (OBSOLETE) Build with openssl 1.0.2u."
  echo "   --openssl_1_1_x   - (OBSOLETE) Build with openssl 1.1.0x."
  echo "   --openssl_1_1_1   - (OBSOLETE) Build with openssl 1.1.1."
  echo "   --openssl_1_1_1f  - (OBSOLETE) Build with openssl 1.1.1f."
  echo "   --openssl_1_1_1i  - Build with openssl 1.1.1i."
  echo "   --openssl_1_1_1k  - Build with openssl 1.1.1k."
  echo "   --openssl_3_0_7   - Build with openssl 3.0.7."
  echo "   --openssl_3_0_12  - Build with openssl 3.0.12."
  echo "   --enable_extended_master_secret - Build with support for Extended Master Secret"
  echo "   --rsa1024         - Build with RSA 1024 support."
  echo "   --rsa_8k          - Build with RSA 8K support."
  echo "   --sha1            - Build with support for SHA1."
  echo "   --enable_ecp192   - Build with support for EC P-192."
  echo "   --ocsp            - Build with OCSP support."
  echo ""
  exit -1
}

BUILD_OPTIONS=""
DEBUG_OPTIONS=""
DTLS_OPTION=""
MBED_PATH=""
REDEFINE_OPTION=""
REDEFINE_LIB_OPTION=""
SKIP_CAP=0
INV_OPT=0
TLS13_OPTION=""
# Default to openssl-3.0.12 version
OPENSSL_OPTION="--openssl_3_0_12"
OPENSSL_VER="3.0.12"
OPENSSL_LIB_OPTION="openssl-3.0.12"
SAMPLE_CRYPTOINTERFACE_OPTION="cryptointerface=true"
OSSL_VER="3"
OPENSSL_GDB_OPTIONS=""
OPENSSL_ENGINE_TYPE=""
DYN_ENG=0
RSA1024_OPTION=""
RSA8K_OPTION=""
SHA1_OPTION=""
OCSP_OPTION=""
URI_OPTION=""
SAMPLE_GDB_OPTION=""
NANOSSL_OSSL_OPTIONS=""
BUILD_FOR_OSI=0

while test $# -gt 0
do
    case "$1" in
        --mbed-path)
            MBED_PATH="$2"; shift
            ;;
        --gdb)
            echo "Enabling Debug build...";
            BUILD_OPTIONS+=" $1"
            OPENSSL_GDB_OPTIONS+="-d"
            SAMPLE_GDB_OPTION="gdb=true"
            ;;
        --debug)
            echo "Building with Debug logs enabled...";
            BUILD_OPTIONS+=" $1";
            DEBUG_OPTIONS="debug=true"
            ;;
        --dtls)
            echo "Building with DTLS enabled...";
            DTLS_OPTION=" $1"
            ;;
        --redefine)
            echo "Redefine the PEM_read_bio_PrivateKey function...";
            REDEFINE_OPTION=" $1";
            REDEFINE_LIB_OPTION="redefine=true"
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
        --openssl_1_1_x)
            echo "(OBSOLETE) Build with openssl 1.1.0x...";
            INV_OPT=1
            ;;
        --openssl_1_1_1)
            echo "(OBSOLETE) Build with openssl 1.1.1c...";
            INV_OPT=1
            ;;
        --openssl_1_1_1f)
            echo "(OBSOLETE) Build with openssl 1.1.1f...";
            INV_OPT=1
            ;;
        --openssl_1_1_1i)
            echo "Build with openssl 1.1.1i...";
            OPENSSL_OPTION=" $1"
            OPENSSL_LIB_OPTION="openssl-1.1.1i"
            OPENSSL_ENGINE_TYPE="enable-static-engine"
            OPENSSL_VER="1.1.1"
            SAMPLE_CRYPTOINTERFACE_OPTION=""
            OSSL_VER=""
            ;;
        --openssl_1_1_1k)
            echo "Build with openssl 1.1.1k...";
            OPENSSL_OPTION=" $1"
            OPENSSL_LIB_OPTION="openssl-1.1.1k"
            OPENSSL_ENGINE_TYPE="enable-static-engine"
            OPENSSL_VER="1.1.1"
            SAMPLE_CRYPTOINTERFACE_OPTION=""
            OSSL_VER=""
            ;;
        --openssl_1_0_2u)
            echo "(OBSOLETE) Build with openssl 1.0.2u...";
            INV_OPT=1
            ;;
        --openssl_1_0_2t)
            echo "(OBSOLETE) Build with openssl 1.0.2t...";
            INV_OPT=1
            ;;
        --openssl_1_0_2n)
            echo "(OBSOLETE) Build with openssl 1.0.2n...";
            INV_OPT=1
            ;;
        --openssl_1_0_2j)
            echo "(OBSOLETE) Build with openssl 1.0.2j...";
            INV_OPT=1
            ;;
        --openssl_1_0_2p)
            echo "(OBSOLETE) Build with openssl 1.0.2p...";
            INV_OPT=1
            ;;
        --openssl_3_0_7)
            echo "Build with openssl 3.0.7...";
            OPENSSL_OPTION=" $1"
            OPENSSL_LIB_OPTION="openssl-3.0.7"
            OPENSSL_ENGINE_TYPE=
            OPENSSL_VER="3.0.7"
            SAMPLE_CRYPTOINTERFACE_OPTION="cryptointerface=true"
            OSSL_VER="3"
            ;;
        --openssl_3_0_12)
	    echo "Build with openssl 3.0.12..."
	    OPENSSL_OPTION=" $1"
            OPENSSL_LIB_OPTION="openssl-3.0.12"
            OPENSSL_ENGINE_TYPE=
            OPENSSL_VER="3.0.12"
            SAMPLE_CRYPTOINTERFACE_OPTION="cryptointerface=true"
            OSSL_VER="3"
            ;;
        --enable_extended_master_secret)
            echo "Build with support for Extended Master Secret";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --rsa1024)
            echo "Build with support for RSA 1024";
            RSA1024_OPTION=" $1"
            ;;
        --rsa_8k)
            echo "Build with support for RSA 8K";
            RSA8K_OPTION=" $1"
            ;;
        --sha1)
            echo "Build with support for SHA1";
            SHA1_OPTION=" $1"
            ;;
        --enable_ecp192)
            echo "Build with support for EC P-192";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --ocsp)
            echo "Build with OCSP support..";
            OCSP_OPTION=" $1"
            URI_OPTION=" --uri"
            ;;
        --build-for-osi)
            echo "Enabling BUILD_FOR_OSI...";
            BUILD_OPTIONS+=" --build-for-osi"
            BUILD_FOR_OSI=1
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

if [ ${DYN_ENG} -eq 1 ]; then
  OPENSSL_ENGINE_TYPE=""
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

#echo "BUILD_OPTIONS=$BUILD_OPTIONS"
#echo "DEBUG_OPTIONS=$DEBUG_OPTIONS"
#echo "DTLS_OPTION=$DTLS_OPTION"
#echo "MBED_PATH=$MBED_PATH"
#echo "SKIP_CAP=$SKIP_CAP"

######################

SCRIPT_DIR=$( cd $(dirname $0) ; pwd -P )

export WORKSPACE="${SCRIPT_DIR}/../../.."

echo "WORKSPACE=${WORKSPACE}"
export MSS_DIR=${WORKSPACE}
export MSS_PROJECTS_DIR=${MSS_DIR}/projects

# Check if building for OSI
source ${MSS_DIR}/scripts/check_for_osi.sh
if [ ${OSI_BUILD} -eq 1 ] || [ ${BUILD_FOR_OSI} -eq 1 ]; then
    BIN_DIR="lib"
else
    BIN_DIR="bin"
fi

if [ ${SKIP_CAP} -eq 1 ] && [ ! -e "${MSS_DIR}/${BIN_DIR}/libnanocap.so" ]; then
    echo "libnanocap.so does not exist in the ${BIN_DIR}/ directory..."
    echo "Exiting build"
    exit 1
fi

echo "***************************************************************"
echo "*** Cleaning binaries and libraries "
echo "***************************************************************"

if [ ${SKIP_CAP} -eq 1 ]; then
    mv ${MSS_DIR}/${BIN_DIR}/libnanocap.so ${MSS_DIR}/${BIN_DIR}/libnanocap.so.backup
fi

rm -f ${MSS_DIR}/${BIN_DIR}/*.so
rm -f ${MSS_DIR}/${BIN_DIR}/*.a
rm -f ${MSS_DIR}/thirdparty/${OPENSSL_LIB_OPTION}/sample/openssl_client_local
export LD_LIBRARY_PATH=

if [ ${SKIP_CAP} -eq 1 ]; then
    mv ${MSS_DIR}/${BIN_DIR}/libnanocap.so.backup ${MSS_DIR}/${BIN_DIR}/libnanocap.so
fi

echo "*********************************************************************"
echo "*** Building openssl connector with CAP and Mbed Operators Enabled..."
echo "*********************************************************************"
for pass in first second
do
    cd ${MSS_PROJECTS_DIR}/platform && ./clean.sh && ./build.sh $BUILD_OPTIONS
    cd ${MSS_PROJECTS_DIR}/common && ./clean.sh && ./build.sh $BUILD_OPTIONS $URI_OPTION
    cd ${MSS_PROJECTS_DIR}/asn1 && ./clean.sh && ./build.sh --disable-pqc $BUILD_OPTIONS
    cd ${MSS_PROJECTS_DIR}/initialize && ./build.sh $BUILD_OPTIONS

    if [ ${SKIP_CAP} -eq 0 ]; then
        cd ${MSS_PROJECTS_DIR}/nanocap && ./clean.sh &&  ./build.sh $BUILD_OPTIONS
    fi

    cd ${MSS_PROJECTS_DIR}/crypto && ./clean.sh && ./build.sh $BUILD_OPTIONS --ssl --openssl${OSSL_VER} --export --disable-pqc --mbed --mbed-path "${MBED_PATH}" $RSA8K_OPTION
    cd ${MSS_PROJECTS_DIR}/nanocert && ./build.sh $BUILD_OPTIONS --openssl --export --disable-pqc $OCSP_OPTION $RSA8K_OPTION
    cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh --clean $BUILD_OPTIONS --openssl_shim --export --disable-pqc $DTLS_OPTION $TLS13_OPTION $OPENSSL_OPTION $RSA1024_OPTION $SHA1_OPTION $OCSP_OPTION $RSA8K_OPTION $NANOSSL_OSSL_OPTIONS nanossl

    if [ "$pass" == "second" ]; then
        cd ${MSS_DIR}/thirdparty/${OPENSSL_LIB_OPTION}
        if [[ "$OPENSSL_VER" == "3.0.7" ]] || [[ "$OPENSSL_VER" == "3.0.12" ]]; then
            ./Configure enable-rc5 enable-mocana-cryptointerface enable-mocana-export ${OPENSSL_GDB_OPTIONS} -D__ENABLE_DIGICERT_OSSL_V3_TEST__ enable-moc-ossl-v3-test
        else
            ./config $OPENSSL_GDB_OPTIONS $OPENSSL_ENGINE_TYPE
        fi
        make clean
        if [[ "$OPENSSL_VER" == "3.0.7" ]] || [[ "$OPENSSL_VER" == "3.0.12" ]]
        then
            make
            cp ${MSS_DIR}/thirdparty/${OPENSSL_LIB_OPTION}/libcrypto.so* ${MSS_DIR}/${BIN_DIR}
        elif [[ "$OPENSSL_VER" == "1.1.1" ]]
        then
            make $DEBUG_OPTIONS $REDEFINE_LIB_OPTION export=true cryptointerface=true build_libs
            cp ${MSS_DIR}/thirdparty/${OPENSSL_LIB_OPTION}/libcrypto.so* ${MSS_DIR}/${BIN_DIR}
        else
            echo "Unsupported OpenSSL version"
            exit 1
        fi

        cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh --clean $BUILD_OPTIONS $REDEFINE_OPTION --disable-pqc --openssl_shim --export $DTLS_OPTION $OPENSSL_OPTION $OCSP_OPTION $NANOSSL_OSSL_OPTIONS openssl_shim_lib
    fi

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
done

if [[ "$OPENSSL_VER" == "3.0.7" ]] || [[ "$OPENSSL_VER" == "3.0.12" ]]
then
    cd ${MSS_DIR}/${BIN_DIR} && ln -sf libopenssl_shim.so libssl.so
    cd ${MSS_DIR}/${BIN_DIR} && ln -sf libopenssl_shim.so libssl.so.3
elif [[ "$OPENSSL_VER" == "1.1.1" ]]
then
    cd ${MSS_DIR}/${BIN_DIR} && ln -sf libopenssl_shim.so libssl.so
    cd ${MSS_DIR}/${BIN_DIR} && ln -sf libopenssl_shim.so libssl.so.1.1
else
    echo "Unsupported OpenSSL version"
    exit 1
fi

export LD_LIBRARY_PATH=${MSS_DIR}/${BIN_DIR} &&
# Build binaries
cd ${MSS_DIR}/thirdparty/${OPENSSL_LIB_OPTION}/sample &&
make -f Makefile suiteb=true mauth=true export=true $SAMPLE_CRYPTOINTERFACE_OPTION $SAMPLE_GDB_OPTION clean openssl_client_local

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
