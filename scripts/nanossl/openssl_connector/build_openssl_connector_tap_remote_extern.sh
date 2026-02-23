#!/usr/bin/env bash

set -e

######################
function show_usage
{
  echo ""
  echo "./build.sh [Options] "
  echo ""
  echo "   --gdb             - Build Debug version."
  echo "   --debug           - Build with Mocana logging enabled for specific build executable."
  echo "   --fips            - Build with FIPS enabled."
  echo "   --disable-pqc     - Build without PQC support."
  echo "   --custom-entropy  - Build with custom entropy."
  echo "   --dtls            - Build with DTLS support."
  echo "   --tap-hybrid-sign - Build with TAP hybrid signing."
  echo "   --redefine        - Redefine the PEM_read_bio_PrivateKey function."
  echo "   --disable-tls13   - Disable with TLS 1.3."
  echo "   --disable-psk     - Build with TLS 1.3 PSK disabled."
  echo "   --disable-0rtt    - Build with TLS 1.3 0-RTT disabled."
  echo "   --tap-remote-tcp  - Build NanoTAP Remote mode with TCP connection."
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
  echo "   --ocsp            - Build with OCSP support."
  echo ""
  exit -1
}

BUILD_OPTIONS=""
DEBUG_OPTIONS=""
FIPS_OPTION=""
FIPS_MAKE_OPTION=""
FIPS_MAKE30_OPTION=""
CUSTOM_ENTROPY_OPTION=""
DTLS_OPTION=""
REDEFINE_OPTION=""
REDEFINE_LIB_OPTION=""
TAP_REMOTE_OPTION="--tap-remote"
INV_OPT=0
TLS13_OPTION=""
TAP_HYBRID_SIGN_OPTION=""
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
NANOSSL_OSSL_OPTIONS=""
SAMPLE_GDB_OPTION=""
STRICT_DH_OPTION=""
STRICT_DH_OPTION_OSSL=""
STRICT_DH_OPTION_OSSL3=""
DISABLE_PQC_OPT=""
OSSL_PQC_OPTION=" enable-mocana-pqc"
BUILD_FOR_OSI=0

while test $# -gt 0
do
    case "$1" in
        --gdb)
            echo "Enabling Debug build...";
            BUILD_OPTIONS+=" $1"
            OPENSSL_GDB_OPTIONS+="-d"
            SAMPLE_GDB_OPTION="gdb=true"
            ;;
        --debug)
            echo "Building with Debug logs enabled...";
            BUILD_OPTIONS+=" $1"
            DEBUG_OPTIONS="debug=true"
            ;;
        --fips)
            echo "Building with FIPS enabled..."
            FIPS_OPTION=" $1"
            FIPS_MAKE_OPTION=" fips=true"
            FIPS_MAKE30_OPTION="enable-mocana-fips"
            ;;
        --disable-pqc)
            echo "Building without PQC support"
            DISABLE_PQC_OPT=" --disable-pqc"
            OSSL_PQC_OPTION=""
            ;;
        --custom-entropy)
            echo "Build with custom entropy";
            CUSTOM_ENTROPY_OPTION=" $1"
            ;;
        --dtls)
            echo "Building with DTLS enabled..."
            DTLS_OPTION=" $1"
            ;;
        --tap-hybrid-sign)
            echo "Building with TAP hybrid signing enabled..."
            TAP_HYBRID_SIGN_OPTION=" $1"
            ;;
        --redefine)
            echo "Redefine the PEM_read_bio_PrivateKey function...";
            REDEFINE_OPTION=" $1"
            REDEFINE_LIB_OPTION="redefine=true"
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
        --tap-remote-tcp)
            TAP_REMOTE_OPTION="--tap-remote-tcp"
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
            NANOSSL_OSSL_OPTIONS=" $1"
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
        --strict_dh)
            echo "Building with strict DH...";
            STRICT_DH_OPTION+=" $1"
            STRICT_DH_OPTION_OSSL=" strict_dh=true"
            STRICT_DH_OPTION_OSSL3="enable-mocana-strict-dh"
            ;;
        --ocsp)
            echo "Build with OCSP support..";
            OCSP_OPTION=" $1"
            URI_OPTION=" --uri"
            ;;
        --build-for-osi)
            echo "Building for OSI platform..."
            BUILD_OPTIONS+=" $1"
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

if [ ! -z "${BUILD_OPTIONS}" ]; then
  echo "BUILD_OPTIONS=${BUILD_OPTIONS}"
  echo ""
fi

#echo "BUILD_OPTIONS=$BUILD_OPTIONS"
#echo "DEBUG_OPTIONS=$DEBUG_OPTIONS"
#echo "DTLS_OPTION=$DTLS_OPTION"
#echo "TAP_REMOTE_OPTION=$TAP_REMOTE_OPTION"

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

echo "***************************************************************"
echo "*** Cleaning binaries and libraries "
echo "***************************************************************"

for libs in ${MSS_DIR}/${BIN_DIR}/*.so; do
    if [[ ! "$libs" == *libmss.so ]] || [[ -z "$FIPS_OPTION" ]]; then
        rm -f $libs
    fi
done
rm -f ${MSS_DIR}/${BIN_DIR}/*.a
rm -f ${MSS_DIR}/thirdparty/${OPENSSL_LIB_OPTION}/sample/openssl_client_tap
export LD_LIBRARY_PATH=

echo "***************************************************************"
echo "*** Building TAP remote openssl connector with TAP Extern..."
echo "***************************************************************"
for pass in first second
do
    cd ${MSS_PROJECTS_DIR}/platform && ./build.sh $BUILD_OPTIONS $FIPS_OPTION
    cd ${MSS_PROJECTS_DIR}/common && ./build.sh $BUILD_OPTIONS $FIPS_OPTION $URI_OPTION
    cd ${MSS_PROJECTS_DIR}/asn1 && ./build.sh $BUILD_OPTIONS $DISABLE_PQC_OPT
    cd ${MSS_PROJECTS_DIR}/initialize && ./build.sh $BUILD_OPTIONS $CUSTOM_ENTROPY_OPTION
    cd ${MSS_PROJECTS_DIR}/nanocap && ./build.sh $BUILD_OPTIONS
    cd ${MSS_PROJECTS_DIR}/crypto && ./build.sh $BUILD_OPTIONS $TAP_HYBRID_SIGN_OPTION $FIPS_OPTION $DISABLE_PQC_OPT --ssl --openssl${OSSL_VER} --tap --tap-extern $RSA8K_OPTION
    cd ${MSS_PROJECTS_DIR}/nanocert && ./build.sh $BUILD_OPTIONS $FIPS_OPTION $DISABLE_PQC_OPT --tap --openssl $OCSP_OPTION $RSA8K_OPTION
    cd ${MSS_PROJECTS_DIR}/nanotap2_common && ./build.sh $BUILD_OPTIONS --tap-remote
    cd ${MSS_PROJECTS_DIR}/nanotap2_configparser && ./build.sh $BUILD_OPTIONS
    cd ${MSS_PROJECTS_DIR}/nanotap2 && ./build.sh $BUILD_OPTIONS --tap-remote nanotap2
    cd ${MSS_PROJECTS_DIR}/nanotap2 && ./build.sh $BUILD_OPTIONS --tap-remote tap_extern
    cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh --clean $BUILD_OPTIONS $FIPS_OPTION $DISABLE_PQC_OPT --tap-remote --openssl_shim $DTLS_OPTION  $OPENSSL_OPTION $RSA1024_OPTION $SHA1_OPTION $TLS13_OPTION $OCSP_OPTION $RSA8K_OPTION $NANOSSL_OSSL_OPTIONS $STRICT_DH_OPTION nanossl
    cd ${MSS_PROJECTS_DIR}/nanotap2 && ./build.sh $BUILD_OPTIONS --tap-remote --tap-extern --openssl clientcomm

    if [ "$pass" == "second" ]; then
        cd ${MSS_DIR}/thirdparty/${OPENSSL_LIB_OPTION}
        if [[ "$OPENSSL_VER" == "3.0.7" ]] || [[ "$OPENSSL_VER" == "3.0.12" ]]; then
            ./Configure enable-rc5 $STRICT_DH_OPTION_OSSL3 enable-mocana-cryptointerface enable-mocana-tap ${FIPS_MAKE30_OPTION} ${OPENSSL_GDB_OPTIONS} ${OSSL_PQC_OPTION}
        else
            ./config $OPENSSL_GDB_OPTIONS $OPENSSL_ENGINE_TYPE
        fi
        make clean
        if [[ "$OPENSSL_VER" == "3.0.7" ]] || [[ "$OPENSSL_VER" == "3.0.12" ]]
        then
            make build_libs
            cp ${MSS_DIR}/thirdparty/${OPENSSL_LIB_OPTION}/libcrypto.so* ${MSS_DIR}/${BIN_DIR}
        elif [[ "$OPENSSL_VER" == "1.1.1" ]]
        then
            make $DEBUG_OPTIONS $FIPS_MAKE_OPTION $REDEFINE_LIB_OPTION $STRICT_DH_OPTION_OSSL cryptointerface=true tap=true build_libs
            cp ${MSS_DIR}/thirdparty/${OPENSSL_LIB_OPTION}/libcrypto.so* ${MSS_DIR}/${BIN_DIR}
        else
            echo "Unsupported OpenSSL version"
            exit 1
        fi

        cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh --clean $BUILD_OPTIONS $FIPS_OPTION $DISABLE_PQC_OPT $REDEFINE_OPTION $TAP_REMOTE_OPTION --tap-extern --openssl_shim $DTLS_OPTION $OPENSSL_OPTION $OCSP_OPTION $NANOSSL_OSSL_OPTIONS openssl_shim_lib
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

export LD_LIBRARY_PATH=${MSS_DIR}/${BIN_DIR}
cd ${MSS_DIR}/thirdparty/${OPENSSL_LIB_OPTION}/sample
# Build binaries only on the second pass
make -f Makefile $FIPS_MAKE_OPTION $SAMPLE_CRYPTOINTERFACE_OPTION $SAMPLE_GDB_OPTION tap=true tap_remote=true suiteb=true tap_extern=true mauth=true clean openssl_client_tap

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
