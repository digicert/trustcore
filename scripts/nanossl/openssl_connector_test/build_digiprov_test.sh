#!/usr/bin/env bash

# Place us in the dir of this script
CURR_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
MSS_PROJECTS_DIR=$CURR_DIR/../../../projects
MSS_DIR=$CURR_DIR/../../..

OSSL_DEBUG=""

set -e

function show_usage
{
  echo ""
  echo "./build.sh [Options] "
  echo ""
  echo "   --gdb              - Build Debug version."
  echo "   --debug            - Build with Mocana logging enabled for specific build executable."
  echo "   --nlr              - Don't rebuild ANY suporting libraries."
  echo "   --openssl_3_0_7   - Build with openssl 3.0.7."
  echo "   --openssl_3_0_12   - Build with openssl 3.0.12."  
  echo "   --orp              - Don't rebuild mss supporting libraries, only rebuild the provider and test(s)."
  echo "   --ossl-digi-test   - Build the openssl test suite for digiprov."
  echo "   --tap-local        - Build TAP local with TPM2"
  echo "   --tap-remote       - Build TAP remote with TPM2"
  echo "   --tap-extern       - Build with TAP extern"
  echo "   --pkcs11-dynamic   - Build with dynamic loading for pkcs11 libraries"
  echo "   --fips             - Build with FIPS enabled."
  echo "   --force-entropy-example - Build with force entropy example."
  echo "   --x32              - Build for 32-bit platforms."
  echo "   --x64              - Build for 64-bit platforms."
  echo "   --toolchain <rpi32 | rpi64 | bbb | android> - Specify the toolchain to be used"
  echo "                        rpi32     For Raspberry Pi 32-bit"
  echo "                        rpi64     For Raspberry Pi 64-bit"
  echo "                        bbb       For BeagleBone Black"
  echo "                        android   For android"
  echo ""
  exit 1
}

BUILD_OPTIONS=""
MAUTH_OPTION=""
INV_OPT=0
ALL=1
NO_REBUILD=0
ONLY_REBUILD_PROVIDER=0
OPENSSL_OPTION=""
OPENSSL_VER="3.0.12"
OPENSSL_LIB_OPTION="openssl-3.0.12"
OSSL_EXTRA_OPTS+=""
OSSL_VER=""
FIPS_OPTION=""
FIPS_MAKE_OPTION=""
FORCE_ENTROPY_EXAMPLE_OPTION=""
TAP_ARG=
TAP_LOCAL_ARG=
TAP_EXTERN_ARG=
TAP_EXTERN_TARGET=
TPM2_ARG=
OSSL_TAP=
PKCS11_DYN_ARG=
COMMON_ARG=
PKCS11_ARG=
BUILD_FOR_OSI=0

while test $# -gt 0
do
    case "$1" in
        --gdb)
            echo "Enabling Debug build...";
            BUILD_OPTIONS+=" $1"
            OSSL_DEBUG="-d"
            ;;
        --debug)
            echo "Building with Debug logs enabled...";
            BUILD_OPTIONS+=" $1"
            ;;
        --nlr)
            echo "NOT building supporting libraries.";
            NO_REBUILD=1
            ;;
        --orp)
            echo "Only rebuilding the provider library.";
            ONLY_REBUILD_PROVIDER=1
            ;;
        --toolchain)
            echo "Cross-compiling for $2"
            BUILD_OPTIONS+=" $1 $2"
            shift
            ;;
        --x32)
            BUILD_OPTIONS+=" $1"
            echo "Building for x32 machine...";
            ;;
        --x64)
            BUILD_OPTIONS+=" $1"
            echo "Building for x64 machine...";
            ;;
        --fips)
            echo "Building with FIPS enabled..."
            FIPS_OPTION=" $1"
            FIPS_MAKE_OPTION="enable-mocana-fips"
            ;;
        --force-entropy-example)
            echo "Build with force entropy example";
            FORCE_ENTROPY_EXAMPLE_OPTION=" --force-entropy"
            ;;
        --tap-local)
            echo "Build with TAP local"
            TAP_ARG="--tap"
            TAP_LOCAL_ARG="--tap-local"
            TPM2_ARG="--tpm2"
            OSSL_TAP="enable-mocana-tap"
            ;;
        --tap-remote)
            echo "Build with TAP remote"
            TAP_ARG="--tap"
            TAP_LOCAL_ARG="--tap-remote"
            TPM2_ARG="--tpm2"
            OSSL_TAP="enable-mocana-tap"
            ;;
        --tap-extern)
            echo "Build with TAP extern"
            TAP_EXTERN_ARG="--tap-extern"
            TAP_EXTERN_TARGET="tap_extern"
            ;;
        --pkcs11-dynamic)
            PKCS11_DYN_ARG=" --pkcs11-dynamic"
            COMMON_ARG=" --dynamic-load"
            PKCS11_ARG=" --pkcs11"
            ;;
	--openssl_3_0_7)
            echo "Build with openssl 3.0.7...";
	    OPENSSL_OPTION=" $1"
            OPENSSL_LIB_OPTION="openssl-3.0.7"
            OPENSSL_ENGINE_TYPE=
            OPENSSL_VER="3.0.7"
            SAMPLE_CRYPTOINTERFACE_OPTION="cryptointerface=true"
            OSSL_VER="3"
            OSSL_EXTRA_OPTS+=" -D__ENABLE_DIGICERT_OSSL_V3_TEST__"
            OSSL_EXTRA_OPTS+=" enable-moc-ossl-v3-test"
            ;;
	--openssl_3_0_12)
	    echo "Build with openssl 3.0.12..."
	    OPENSSL_OPTION=" $1"
            OPENSSL_LIB_OPTION="openssl-3.0.12"
            OPENSSL_ENGINE_TYPE=
            OPENSSL_VER="3.0.12"
            SAMPLE_CRYPTOINTERFACE_OPTION="cryptointerface=true"
            OSSL_VER="3"
            OSSL_EXTRA_OPTS+=" -D__ENABLE_DIGICERT_OSSL_V3_TEST__"
            OSSL_EXTRA_OPTS+=" enable-moc-ossl-v3-test"
            ;;
        --ossl-digi-test)
            OSSL_EXTRA_OPTS+=" -D__ENABLE_DIGICERT_OSSL_V3_TEST__"
            OSSL_EXTRA_OPTS+=" enable-moc-ossl-v3-test"
            echo "Building with evp_fetch modification for testing digi provider ...";
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

# Check if building for OSI
source ${MSS_DIR}/scripts/check_for_osi.sh
if [ ${OSI_BUILD} -eq 1 ] || [ ${BUILD_FOR_OSI} -eq 1 ]; then
    BIN_DIR="lib"
else
    BIN_DIR="bin"
fi

if [ ${INV_OPT} -eq 1 ]; then
    show_usage
fi

if [ ${NO_REBUILD} -eq 0 ] && [ ${ONLY_REBUILD_PROVIDER} -eq 0 ]; then
    for libs in ${MSS_DIR}/${BIN_DIR}/*.so; do
        if [[ ! "$libs" == *libmss.so ]] || [[ -z "$FIPS_OPTION" ]]; then
            rm -f $libs
        fi
    done
fi

cd $CURR_DIR

echo "***************************************************************"
echo "*** Building Digiprov tests..."
echo "***************************************************************"
for pass in first second
do
    if [ ${NO_REBUILD} -eq 0 ] && [ ${ONLY_REBUILD_PROVIDER} -eq 0 ]; then
        cd ${MSS_PROJECTS_DIR}/platform && ./clean.sh && ./build.sh $FIPS_OPTION $BUILD_OPTIONS
        if [ "${TAP_LOCAL_ARG}" == "--tap-remote" ]; then
          cd ${MSS_PROJECTS_DIR}/common && ./clean.sh && ./build.sh $BUILD_OPTIONS $FIPS_OPTION --uri ${COMMON_ARG} --cmake-opt "-DCM_TAP_TYPE=REMOTE"
        else
          cd ${MSS_PROJECTS_DIR}/common && ./clean.sh && ./build.sh $BUILD_OPTIONS $FIPS_OPTION --uri ${COMMON_ARG}
        fi
        cd ${MSS_PROJECTS_DIR}/asn1 && ./clean.sh && ./build.sh $BUILD_OPTIONS
        cd ${MSS_PROJECTS_DIR}/nanocap && ./clean.sh && ./build.sh $BUILD_OPTIONS
        if [ ! -z "${TAP_ARG}" ]; then
          cd ${MSS_PROJECTS_DIR}/nanotap2_common && ./build.sh $BUILD_OPTIONS --suiteb ${TAP_LOCAL_ARG} ${TPM2_ARG} ${PKCS11_ARG}
          cd ${MSS_PROJECTS_DIR}/nanotap2_configparser && ./build.sh $BUILD_OPTIONS
          if [ "${TAP_LOCAL_ARG}" == "--tap-remote" ]; then
            cd ${MSS_PROJECTS_DIR}/nanotap2 && ./build.sh $BUILD_OPTIONS ${TAP_LOCAL_ARG} ${TPM2_ARG} ${TAP_EXTERN_ARG} clientcomm
          fi
          cd ${MSS_PROJECTS_DIR}/nanotap2 && ./build.sh $BUILD_OPTIONS ${TAP_LOCAL_ARG} ${TPM2_ARG} ${PKCS11_ARG} ${TAP_EXTERN_TARGET} nanotap2
          cd ${MSS_PROJECTS_DIR}/tpm2 && ./build.sh $BUILD_OPTIONS --suiteb ${PKCS11_ARG}
          cd ${MSS_PROJECTS_DIR}/smp_tpm2 && ./build.sh $BUILD_OPTIONS --suiteb
          if [ "${PKCS11_ARG}" == " --pkcs11" ]; then
            cd ${MSS_PROJECTS_DIR}/smp_pkcs11 && ./build.sh --suiteb ${DEBUG_ARG} ${GDB_ARG} ${PKCS11_DYN_ARG} --x64
          fi
        fi
        cd ${MSS_PROJECTS_DIR}/crypto && ./clean.sh && ./build.sh $BUILD_OPTIONS $FIPS_OPTION --openssl3 ${TAP_ARG} ${TAP_EXTERN_ARG} ${TPM2_ARG}
        cd ${MSS_PROJECTS_DIR}/initialize && ./clean.sh && ./build.sh $BUILD_OPTIONS $FORCE_ENTROPY_EXAMPLE_OPTION
        cd ${MSS_PROJECTS_DIR}/nanocert && ./clean.sh && ./build.sh $BUILD_OPTIONS $FIPS_OPTION ${TAP_ARG}
        # may need tap-remote nanossl here, which also affects nanossl build below
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
    fi

    if [ "$pass" == "second" ]; then
        if [ ${NO_REBUILD} -eq 0 ]; then

            # build libcrypto.so with DigiCert provider built in
            pushd ${MSS_DIR}/thirdparty/${OPENSSL_LIB_OPTION} 
            ./Configure enable-rc5 enable-mocana-cryptointerface enable-mocana-pqc ${FIPS_MAKE_OPTION} ${OSSL_TAP} ${OSSL_DEBUG} ${OSSL_EXTRA_OPTS}
            make -j8

            if [ ! -f ${MSS_DIR}/thirdparty/${OPENSSL_LIB_OPTION}/libcrypto.so.3 ]; then
                echo "******************************************"
                echo "**** OpenSSL library failed to build  ****"
                echo "******************************************"
                exit 1
            fi
            cp ${MSS_DIR}/thirdparty/${OPENSSL_LIB_OPTION}/libcrypto.so.3 ${MSS_DIR}/${BIN_DIR}
            pushd ${MSS_DIR}/${BIN_DIR}
            [ -f libcrypto.so ] && rm libcrypto.so
            ln -s libcrypto.so.3 libcrypto.so
            popd

        fi
        cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh --clean $BUILD_OPTIONS $FIPS_OPTION --openssl_shim $DTLS_OPTION $DTLS_SRTP_OPTION ${OPENSSL_OPTION} $RSA1024_OPTION $SHA1_OPTION $TLS13_OPTION $OCSP_OPTION $SESSION_TICKET_OPTION $STATIC_OPTION $NANOSSL_OSSL_OPTIONS $STRICT_DH_OPTION $RSA8K_OPTION nanossl
        cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh --clean $BUILD_OPTIONS $FIPS_OPTION $REDEFINE_OPTION --openssl_shim $DTLS_OPTION ${OPENSSL_OPTION} $OCSP_OPTION $SESSION_TICKET_OPTION $STATIC_OPTION $NANOSSL_OSSL_OPTIONS openssl_shim_lib

        cd ${MSS_PROJECTS_DIR}/digiprov_test && ./clean.sh && ./build.sh $BUILD_OPTIONS ${FIPS_OPTION} ${TAP_ARG} ${PKCS11_ARG} ${OPENSSL_OPTION}

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
