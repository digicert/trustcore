#!/usr/bin/env bash

set -e

# Set script directory
SCRIPT_DIR=$( cd $(dirname $0) ; pwd -P )

source ${SCRIPT_DIR}/configuration.sh

# Set paths
MSS_DIR=${SCRIPT_DIR}/../../..
MSS_PROJECTS_DIR=${MSS_DIR}/projects

# Default global build options
BUILD_OPTIONS=

# Check if building for OSI
source ${MSS_DIR}/scripts/check_for_osi.sh
if [ ${OSI_BUILD} -eq 1 ]; then
    BIN_DIR="${MSS_DIR}/lib"
    BUILD_OPTIONS+=" --build-for-osi"
else
    BIN_DIR="${MSS_DIR}/bin"
fi

# Library specific build options
COMMON_BUILD_OPTIONS="--libtype static --debug --build-info --arg-parser --msg-logger --uri --common-utils --protobuf --mime-parser"
PLATFORM_BUILD_OPTIONS="--process --term --signal --libtype static"
ASN1_BUILD_OPTIONS="--libtype static --cms"
INITIALIZE_BUILD_OPTIONS="--libtype static"
NANOCAP_BUILD_OPTIONS="--libtype static --suiteb"
CERT_ENROLL_BUILD_OPTIONS="--libtype static"
CRYPTO_BUILD_OPTIONS="--libtype static --debug --suiteb --ssl --keygen"
NANOCERT_BUILD_OPTIONS="--libtype static --suiteb --cert --json-verify --cmc --est --debug --status-log"
NANOSSL_BUILD_OPTIONS="--libtype static --clean --suiteb --keylog --keylog_env_var"
NANOMQTT_BUILD_OPTIONS="--libtype static --ssl --library --streaming"
TRUSTEDGE_BUILD_OPTIONS="--debug"

UNITTEST_ARG=0
PACKAGE=0
MONOLITHIC=0

NO_REBUILD=0
TAP_ARG=
PKCS11_ARG=
PKCS11_PATH=
SMP_ARG=
SMP_PKCS11_ARG=" --pkcs11"
SMP_TPM2_ARG=
TAP_MODE=
NANOROOT_TAP_BUILD_OPTIONS=
TAP_COMMON_ARG=
COMMON_ARG=
CVC_ARG=
PQC_ARG=" --disable-pqc"
PQC_COMPOSITE_ARG=
OQS_ARG=
OQS_PATH=
EXPORT_ARG=
MBED_ARG=
OCSP_ARG=
VERSION_STRING=""
DIGICERT_SCEP=
PROXY_ARG=
PC_ARG=
MEM_PROFILE_ARG=
GCM_OPT=" --aes-gcm-256b"

# Show usage
function show_usage
{
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  --help                 - Show help options"
    echo "  --gdb                  - Build with debug symbols"
    echo "  --aes-gcm-4k           - Build with AES-GCM 4k table (rather than 256b default)"
    echo "  --aes-gcm-64k          - Build with AES-GCM 64k table (rather than 256b default)"
    echo "  --pkcs11-dynamic       - Build with dynamic loading for multiple pkcs11 libraries"
    echo "  --softhsm2             - Build with softhsm2 pkcs11 support."
    echo "  --cloudhsm             - Build with cloudhsm pkcs11 support."
    echo "  --dssm                 - Build with Digicert SSM PKCS11 library"
    echo "  --pkcs11-tee           - Build with tee pkcs11 support."
    echo "  --tee                  - Build with tee support."
    echo "  --tpm2                 - Build with tpm2 support."
    echo "  --nanoroot             - Build with NanoROOT support."
    echo "  --pkcs11-path          - Path to pkcs11 library. Must be followed by the path."
    echo "  --tee-path             - Path to tee library (libteec.so)."
    echo "  --tap-remote           - Build with TAP remote support."
    echo "  --no-lib-rebuild       - Don't rebuild the suporting libraries."
    echo "  --cvc                  - Build with CV Certificate support."
    echo "  --enable-pc            - Enable Certificate/CSR printing."
    echo "  --pqc                  - Build with PQC support."
    echo "  --pqc-composite        - Build with PQC composite support."
    echo "  --oqs                  - Build with PQC/OQS support."
    echo "  --oqs-path             - Path to oqs install location, can be absolute or relative."
    echo "  --mbed                 - Build with mbedtls support"
    echo "  --mbed-path            - Path to mbed install location, can be absolute or relative."
    echo "  --digicert             - Add support for Digicert SCEP."
    echo "  --unittest             - Build with unittesting"
    echo "  --debug-internals      - Internal debug logging"
    echo "  --monolithic           - Build monolithic binary"
    echo "  --library              - Build as library (disables REST API, enables monolithic)"
    echo "  --libtype <shared | static> - Specify library type"
    echo "  --minimal              - Build with minimal code footprint"
    echo "  --package              - Package artifacts"
    echo "  --pre-release          - Specify pre-release string"
    echo "  --msg-timestamp        - Enable timestamps in log messages."
    echo "  --persist-artifact     - Enable persisting artifact payload."
    echo "  --proxy                - Build with proxy support enabled."
    echo "  --x32                  - Build for 32-bit platforms."
    echo "  --x64                  - Build for 64-bit platforms."
    echo "  --service-certificate  - Build with service certificate mode support."
    echo "  --valgrind-tool <tool> - Enable valgrind with selected tool."
    echo "                              memcheck"
    echo "                              massif"
    echo "  --mem-profile          - Build with memory profiling."
    echo "  --version-string       - Version information for release."
    echo "  --enable-coverage      - Build with gcov code coverage support."
    echo "  --enable-token-fallback - Enable fallback when authorization token missing."
    echo "  --toolchain <rpi32 | rpi64 | bbb | android> - Specify the toolchain to be used"
    echo "                        rpi32     For Raspberry Pi 32-bit"
    echo "                        rpi64     For Raspberry Pi 64-bit"
    echo "                        bbb       For BeagleBone Black"
    echo "                        android   For android"
    echo "  --esp32                - Cross compile for ESP32"
    echo "  --esp32-version        - ESP IDF version. Must be followed by the version."
    echo "  --esp32-idf-path       - Path to ESP IDF install location. Must be followed by the path."
    echo "  --esp32-sdkconfig-path - Path to ESP32 sdkconfig file. Must be followed by the path."
    echo ""
    if [ -n "$1" ]; then
        echo "$1"
        echo ""
        exit 1
    else
        exit 0
    fi
}

# Parse command line arguments
while test $# -gt 0
do
    case "$1" in
        --help)
            show_usage
            ;;
        --gdb)
            BUILD_OPTIONS+=" --gdb"
            ;;
        --no-lib-rebuild)
            echo "NOT building supporting libraries.";
            NO_REBUILD=1
            ;;
        --aes-gcm-4k)
            echo "Building with AES-GCM 4k table.";
            GCM_OPT=" --aes-gcm-4k"
            ;;
        --aes-gcm-64k)
            echo "Building with AES-GCM 64k table.";
            GCM_OPT=""
            ;;
        --pkcs11-dynamic)
            echo "-- Building with pkcs11 dynamic load enabled...";
            TAP_ARG=" --tap"
            TAP_MODE=" --tap-local"
            SMP_TPM2_ARG=" --tpm2"
            PKCS11_ARG=" --pkcs11-dynamic"
            SMP_ARG=" --pkcs11"
            COMMON_ARG=" --dynamic-load"
            OCSP_ARG=" --ocsp"
            ;;
        --softhsm2)
            echo "-- Building with pkcs11 softhsm2 enabled...";
            TAP_ARG=" --tap"
            TAP_MODE=" --tap-local"
            SMP_TPM2_ARG=" --tpm2"
            PKCS11_ARG=" --softhsm2"
            SMP_ARG=" --pkcs11"
            OCSP_ARG=" --ocsp"
            ;;
        --cloudhsm)
            echo "-- Building with pkcs11 cloudhsm enabled...";
            TAP_ARG=" --tap"
            TAP_MODE=" --tap-local"
            SMP_TPM2_ARG=" --tpm2"
            PKCS11_ARG=" --cloudhsm"
            SMP_ARG=" --pkcs11"
            OCSP_ARG=" --ocsp"
            ;;
        --dssm)
            echo "-- Building with pkcs11 dssm enabled...";
            TAP_ARG=" --tap"
            TAP_MODE=" --tap-local"
            SMP_TPM2_ARG=" --tpm2"
            PKCS11_ARG=" --dssm"
            SMP_ARG=" --pkcs11"
            OCSP_ARG=" --ocsp"
            ;;
        --pkcs11-tee)
            echo "-- Building with pkcs11 tee enabled...";
            TAP_ARG=" --tap"
            TAP_MODE=" --tap-local"
            SMP_TPM2_ARG=" --tpm2"
            PKCS11_ARG=" --pkcs11-tee"
            SMP_ARG=" --pkcs11"
            OCSP_ARG=" --ocsp"
            ;;
        --tee)
            echo "-- Building with tee enabled...";
            TAP_ARG=" --tap"
            TAP_MODE=" --tap-local"
            SMP_ARG=" --tee"
            SMP_PKCS11_ARG=""
            OCSP_ARG=" --ocsp"
            CRYPTO_BUILD_OPTIONS+=" --tee"
            ;;
        --tpm2)
            echo "-- Building with tpm2 enabled...";
            TAP_ARG=" --tap"
            TAP_MODE=" --tap-local"
            SMP_TPM2_ARG=" --tpm2"
            SMP_ARG=" --tpm2"
            SMP_PKCS11_ARG=""
            OCSP_ARG=" --ocsp"
            CRYPTO_BUILD_OPTIONS+=" --tap-hybrid-sign"
            ;;
        --nanoroot)
            echo "-- Building with NanoROOT enabled...";
            TAP_ARG=" --tap"
            TAP_MODE=" --tap-local"
            SMP_TPM2_ARG=""
            SMP_ARG=" --nanoroot"
            SMP_PKCS11_ARG=""
            NANOROOT_TAP_BUILD_OPTIONS=" --cmake-opt -DCM_ENABLE_TPM2=OFF"
            CRYPTO_BUILD_OPTIONS+=" --tap-hybrid-sign --nanoroot"
            CERT_ENROLL_BUILD_OPTIONS+=" --tap"
            OCSP_ARG=" --ocsp"
            PQC_ARG=" --pqc"
            echo "Building with PQC support...";
            ;;
        --pkcs11-path)
            PKCS11_PATH=$2;
            shift
            ;;
        --tee-path)
            PKCS11_PATH=$2;
            shift
            ;;
        --tap-remote)
            echo "-- Building with TAP remote enabled...";
            TAP_ARG=" --tap"
            TAP_MODE=" --tap-remote"
            OCSP_ARG=" --ocsp"
            ;;
        --cvc)
            CVC_ARG=" --cvc"
            echo "Building with cvc cert support...";
            ;;
        --enable-pc)
            PC_ARG=" --enable-pc"
            echo "Building with cert/csr printing support...";
            ;;
        --pqc)
            PQC_ARG=" --pqc"
            echo "Building with PQC support...";
            ;;
        --pqc-composite)
            PQC_COMPOSITE_ARG=" --pqc-composite"
            echo "Building with PQC composite support...";
            ;;
        --oqs)
            PQC_ARG=" --pqc"
            OQS_ARG=" --oqs"
            echo "Building with PQC/OQS support...";
            ;;
        --oqs-path)
            OQS_PATH=" --oqs-path $2";
            shift
            ;;
        --mbed)
            EXPORT_ARG=" --export"
            echo "Building with export support...";
            ;;
        --mbed-path)
            MBED_ARG=" --mbed --mbed-path $2";
            shift
            ;;
        --digicert)
            DIGICERT_SCEP=" --digicert"
            ;;
        --unittest)
            UNITTEST_ARG=1
            ;;
        --debug-internals)
            TRUSTEDGE_BUILD_OPTIONS+=" $1"
            ;;
        --monolithic)
            TRUSTEDGE_BUILD_OPTIONS+=" $1"
            MONOLITHIC=1
            ;;
        --library)
            TRUSTEDGE_BUILD_OPTIONS+=" --disable-rest-api --monolithic $1"
            MONOLITHIC=1
            ;;
        --libtype)
            TRUSTEDGE_BUILD_OPTIONS+=" --libtype $2"
            shift
            ;;
        --msg-timestamp)
            COMMON_BUILD_OPTIONS+=" $1"
            ;;
        --persist-artifact)
            TRUSTEDGE_BUILD_OPTIONS+=" $1"
            ;;
        --proxy)
            PROXY_ARG=" --proxy"
            ;;
        --minimal)
            echo "Building with minimal ciphers";
            export CM_ENV_STRIP_FUNC=1
            COMMON_BUILD_OPTIONS+=" --disable-error-code-lookup"
            CRYPTO_BUILD_OPTIONS+=" --disable-aes-ccm --disable-aes-cmac --disable-aes-eax --disable-aes-mmo --disable-aes-xcbc-mac-96 --disable-aes-xts --disable-rc4 --disable-chacha20 --disable-poly1305 --disable-des --disable-dsa --disable-fips186-rng --disable-rc5 --disable-ec-elgamal --disable-ec-mqv --small-footprint"
            NANOCERT_BUILD_OPTIONS+=" --disable-dsa"
            NANOSSL_BUILD_OPTIONS+=" --disable-weak-ciphers --disable-aes-ccm --disable_chacha20poly1305 --disable-psk --disable-0rtt --disable-dual-mode-api --disable-client-async --disable-server-async --disable-server --disable-ciphersuite-select --disable-key-expansion"
            TRUSTEDGE_BUILD_OPTIONS+=" --disable-rest-api"
            ;;
        --package)
            PACKAGE=1
            TRUSTEDGE_BUILD_OPTIONS+=" package"
            ;;
        --pre-release)
            if [ -z "$2" ]; then
                show_usage "Missing pre-release string"
            fi
            TRUSTEDGE_BUILD_OPTIONS+=" $1 $2"
            shift
            ;;
        --toolchain)
            echo "Cross-compiling for $2"
            BUILD_OPTIONS+=" $1 $2"
            shift
            ;;
        --esp32)
            echo "Cross compiling for ESP32"
            BUILD_OPTIONS+=" --toolchain esp32"
            ;;
        --esp32-version)
            echo "ESP IDF version"
            BUILD_OPTIONS+=" --cmake-opt -DESP32_VERSION=$2"
            shift
            ;;
        --esp32-idf-path)
            BUILD_OPTIONS+=" --cmake-opt -DESP32_IDF_PATH=$2"
            shift
            ;;
        --esp32-sdkconfig-path)
            BUILD_OPTIONS+=" --cmake-opt -DESP32_SDKCONFIG_PATH=$2"
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
        --service-certificate)
            TRUSTEDGE_BUILD_OPTIONS+=" $1"
            echo "Building with service certificate mode conf...";
            ;;
        --valgrind-tool)
            TRUSTEDGE_BUILD_OPTIONS+=" $1 $2"
            echo "Enabling valgrind tool $2...";
            shift
            ;;
        --mem-profile)
            MEM_PROFILE_ARG=" --mem-profile"
            echo "Enabling memory profiling.";
            ;;
        --version-string)
            echo "Version string: $2"
            VERSION_STRING="--version-string $2"
            shift
            ;;
        --enable-coverage)
            TRUSTEDGE_BUILD_OPTIONS+=" $1"
            ;;
        --enable-token-fallback)
            TRUSTEDGE_BUILD_OPTIONS+=" $1"
            ;;
        --enable-posix)
            echo "Building with posix support enabled...";
            COMMON_BUILD_OPTIONS+=" $1"
            ;;
        *)
            show_usage "Invalid option: $1"
            ;;
    esac
    shift
done

# Cleanup previous build
if [ ${OSI_BUILD} -eq 0 ]; then
    if [ ${NO_REBUILD} -eq 0 ]; then
        rm -f ${MSS_DIR}/bin/*.so*
        rm -f ${MSS_DIR}/bin_static/*.a
    fi
    rm -f ${MSS_DIR}/bin/trustedge
    rm -f ${MSS_DIR}/bin_static/trustedge
else
    if [ ${NO_REBUILD} -eq 0 ]; then
        rm -f ${MSS_DIR}/lib/*.so*
        rm -f ${MSS_DIR}/lib/*.a
    fi
    rm -f ${MSS_DIR}/bin/trustedge
fi

#TODO cloudhssm and dssm may need to copy to bin or be built to be static TBD
if [ "$SMP_ARG" == " --pkcs11" ]; then
    echo "Copying PKCS11 library(s) from ${PKCS11_PATH}"
    if [ "${PKCS11_ARG}" == " --pkcs11-tee" ]; then
      cp "${PKCS11_PATH}/libckteec.so" ${BIN_DIR}
      cp "${PKCS11_PATH}/libteec.so" ${BIN_DIR}
      rm -f ${BIN_DIR}/libckteec.so.0
      ln -s ${BIN_DIR}/libckteec.so ${BIN_DIR}/libckteec.so.0
      rm -f ${BIN_DIR}/libteec.so.1
      ln -s ${BIN_DIR}/libteec.so ${BIN_DIR}/libteec.so.1
    elif [ "${PKCS11_ARG}" != " --pkcs11-dynamic" ]; then
      cp ${PKCS11_PATH} ${BIN_DIR}
    fi
fi

if [ "$SMP_ARG" == " --tee" ]; then
    echo "Copying TEE library(s) from ${PKCS11_PATH}"
    cp "${PKCS11_PATH}/libteec.so" ${BIN_DIR}
    rm -f ${BIN_DIR}/libteec.so.1
    ln -s ${BIN_DIR}/libteec.so ${BIN_DIR}/libteec.so.1
fi

if ! [ -z "${TAP_MODE}" ]; then
   if [ "${TAP_MODE}" == " --tap-local" ]; then
       TAP_COMMON_ARG="--cmake-opt -DCM_TAP_TYPE=LOCAL"
   else
       TAP_COMMON_ARG="--cmake-opt -DCM_TAP_TYPE=REMOTE"
   fi
fi

if ! [ -z "${EXPORT_ARG}" ]; then
    if [ -z "${OQS_ARG}" ]; then
        echo "Export Build with no oqs, disabling PQC";
        PQC_ARG=" --disable-pqc"
    fi
fi

# Build libraries
if [ ${NO_REBUILD} -eq 0 ]; then
    cd ${MSS_PROJECTS_DIR}/common && ./clean.sh && ./build.sh ${MEM_PROFILE_ARG} ${TAP_COMMON_ARG} ${COMMON_ARG} $BUILD_OPTIONS $COMMON_BUILD_OPTIONS ${VERSION_STRING}
    cd ${MSS_PROJECTS_DIR}/platform && ./clean.sh && ./build.sh $BUILD_OPTIONS $PLATFORM_BUILD_OPTIONS
    cd ${MSS_PROJECTS_DIR}/asn1 && ./clean.sh && ./build.sh ${CVC_ARG}  ${PQC_ARG} $BUILD_OPTIONS $ASN1_BUILD_OPTIONS
    cd ${MSS_PROJECTS_DIR}/initialize && ./clean.sh && ./build.sh ${MEM_PROFILE_ARG} $BUILD_OPTIONS $INITIALIZE_BUILD_OPTIONS
    cd ${MSS_PROJECTS_DIR}/nanocap && ./clean.sh && ./build.sh $BUILD_OPTIONS $NANOCAP_BUILD_OPTIONS
    cd ${MSS_PROJECTS_DIR}/crypto && ./clean.sh && ./build.sh ${CVC_ARG}  ${TAP_ARG} ${TAP_MODE} ${PC_ARG} ${SMP_TPM2_ARG} ${PQC_ARG} ${OQS_ARG} ${OQS_PATH} ${EXPORT_ARG} ${MBED_ARG} ${CRYPTO_BUILD_OPTIONS} ${GCM_OPT} $BUILD_OPTIONS
    cd ${MSS_PROJECTS_DIR}/nanocert && ./clean.sh && ./build.sh ${TAP_ARG} ${OCSP_ARG} ${PC_ARG} ${PQC_ARG} ${CVC_ARG} ${EXPORT_ARG} $BUILD_OPTIONS ${NANOCERT_BUILD_OPTIONS} ${PROXY_ARG}
    cd ${MSS_PROJECTS_DIR}/cert_enroll && ./clean.sh && ./build.sh ${TAP_ARG} $BUILD_OPTIONS $CERT_ENROLL_BUILD_OPTIONS

    #TAP builds, leave pkcs11 in for now, support can be validated later
    if ! [ -z "${TAP_MODE}" ]; then
        cd ${MSS_PROJECTS_DIR}/nanotap2_common && ./clean.sh && ./build.sh --libtype static $BUILD_OPTIONS --suiteb ${SMP_ARG} ${TAP_MODE} ${NANOROOT_TAP_BUILD_OPTIONS} &&
        cd ${MSS_PROJECTS_DIR}/nanotap2 && ./clean.sh && ./build.sh --libtype static $BUILD_OPTIONS ${SMP_ARG} ${TAP_MODE} ${NANOROOT_TAP_BUILD_OPTIONS} nanotap2 &&
        cd ${MSS_PROJECTS_DIR}/nanotap2_configparser && ./clean.sh && ./build.sh --libtype static $BUILD_OPTIONS

        if [ "${TAP_MODE}" == " --tap-remote" ]; then
            cd ${MSS_PROJECTS_DIR}/nanotap2 && ./clean.sh && ./build.sh --libtype static --tap-remote $BUILD_OPTIONS clientcomm
        else
            if [ "$SMP_ARG" == " --tpm2" ]; then
                cd ${MSS_PROJECTS_DIR}/tpm2 && ./clean.sh && ./build.sh --libtype static $BUILD_OPTIONS --suiteb ${SMP_PKCS11_ARG} &&
                cd ${MSS_PROJECTS_DIR}/smp_tpm2 && ./clean.sh && ./build.sh --libtype static $BUILD_OPTIONS --suiteb --x64
            fi
            if [ "$SMP_ARG" == " --pkcs11" ]; then
                cd ${MSS_PROJECTS_DIR}/tpm2 && ./clean.sh && ./build.sh --libtype static $BUILD_OPTIONS --suiteb ${SMP_PKCS11_ARG} &&
                cd ${MSS_PROJECTS_DIR}/smp_pkcs11 && ./clean.sh && ./build.sh --libtype static $BUILD_OPTIONS --suiteb ${PKCS11_ARG}
            fi
            if [ "$SMP_ARG" == " --tee" ]; then
                cd ${MSS_PROJECTS_DIR}/smp_tee && ./clean.sh && ./build.sh --libtype static $BUILD_OPTIONS --tee
            fi
            if [ "$SMP_ARG" == " --nanoroot" ]; then
                cd ${MSS_PROJECTS_DIR}/smp_nanoroot && ./clean.sh && ./build.sh --libtype static $BUILD_OPTIONS --suiteb
            fi
        fi
        cd ${MSS_PROJECTS_DIR}/nanossl && ./clean.sh && ./build.sh $BUILD_OPTIONS ${EXPORT_ARG} $NANOSSL_BUILD_OPTIONS ${GCM_OPT} --ocsp nanossl --mauth ${PQC_ARG} ${PQC_COMPOSITE_ARG} ${OQS_ARG} ${PROXY_ARG}
    else
        cd ${MSS_PROJECTS_DIR}/nanossl && ./clean.sh && ./build.sh $BUILD_OPTIONS ${EXPORT_ARG} $NANOSSL_BUILD_OPTIONS ${GCM_OPT} nanossl ${PQC_ARG} ${PQC_COMPOSITE_ARG} ${OQS_ARG} ${PROXY_ARG}
    fi

    cd ${MSS_PROJECTS_DIR}/mqtt_client && ./clean.sh && ./build.sh $BUILD_OPTIONS $NANOMQTT_BUILD_OPTIONS ${PQC_ARG} nanomqtt
    cd ${MSS_PROJECTS_DIR}/mqtt_client && ./clean.sh && ./build.sh $BUILD_OPTIONS $NANOMQTT_BUILD_OPTIONS ${PQC_ARG} mqtt_client_sample ${PROXY_ARG}
fi

# Build trustedge binary
if [ ${PACKAGE} -eq 1 ]; then
    TRUSTEDGE_PROJ_DIR=${MSS_PROJECTS_DIR}/trustedge
    cd $MSS_DIR
    rm -rf dist
    mkdir -p dist
    # cp $TRUSTEDGE_PROJ_DIR/build/*.deb .
    # cp $TRUSTEDGE_PROJ_DIR/build/*.tar.gz .
fi

# Array of artifacts to generate
ARTIFACTS=("DEB" "RPM" "TGZ")

# Loop through the array
for GENERATOR in "${ARTIFACTS[@]}"; do
    echo "cd ${MSS_PROJECTS_DIR}/trustedge && ./clean.sh && ./build.sh ${VERSION_STRING} ${SMP_ARG} ${TAP_MODE} ${PKCS11_ARG} ${CVC_ARG} ${PC_ARG} ${OQS_ARG} ${PQC_ARG} ${EXPORT_ARG} ${DIGICERT_SCEP} $BUILD_OPTIONS $TRUSTEDGE_BUILD_OPTIONS --generator ${GENERATOR} ${PROXY_ARG}"
    cd ${MSS_PROJECTS_DIR}/trustedge && ./clean.sh && ./build.sh ${VERSION_STRING} ${SMP_ARG} ${TAP_MODE} ${PKCS11_ARG} ${CVC_ARG} ${PC_ARG} ${OQS_ARG} ${PQC_ARG} ${EXPORT_ARG} ${DIGICERT_SCEP} $BUILD_OPTIONS $TRUSTEDGE_BUILD_OPTIONS --generator ${GENERATOR} ${PROXY_ARG}

    if [ ${PACKAGE} -eq 1 ]; then
        if [ "${GENERATOR}" == "DEB" ]; then
            cp $TRUSTEDGE_PROJ_DIR/build/*.deb $MSS_DIR/dist/
        elif [ "${GENERATOR}" == "RPM" ]; then
            cp $TRUSTEDGE_PROJ_DIR/build/*.rpm $MSS_DIR/dist/
        elif [ "${GENERATOR}" == "TGZ" ]; then
            cp $TRUSTEDGE_PROJ_DIR/build/*.tar.gz $MSS_DIR/dist/
        fi
    fi

done

if [ ${UNITTEST_ARG} -eq 1 ]; then
    echo "cd ${MSS_PROJECTS_DIR}/trustedge && ./clean.sh && ./build.sh ${SMP_ARG} ${TAP_MODE} ${PKCS11_ARG} ${CVC_ARG} ${OQS_ARG} ${PQC_ARG} ${EXPORT_ARG} $BUILD_OPTIONS $TRUSTEDGE_BUILD_OPTIONS --unittest --library"
    cd ${MSS_PROJECTS_DIR}/trustedge && ./clean.sh && ./build.sh ${SMP_ARG} ${TAP_MODE} ${PKCS11_ARG} ${CVC_ARG} ${OQS_ARG} ${PQC_ARG} ${EXPORT_ARG} $BUILD_OPTIONS $TRUSTEDGE_BUILD_OPTIONS --unittest --library
fi
