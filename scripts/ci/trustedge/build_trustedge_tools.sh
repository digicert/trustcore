#!/usr/bin/env bash

set -e

export CM_ENV_STRIP_FUNC=1

# Set script directory
SCRIPT_DIR=$( cd $(dirname $0) ; pwd -P )

# Set paths
MSS_DIR=${SCRIPT_DIR}/../../..
MSS_PROJECTS_DIR=${MSS_DIR}/projects
BIN_DIR=${MSS_DIR}/bin

# Assume x86_64 by default
TOOLS_ZIP_NAME=tpm2_tools-x86_64.zip

BUILD_OPTIONS="$@"
COMMON_BUILD_OPTIONS="--libtype static --debug --json --uri --x64 --cmake-opt -DCM_TAP_TYPE=LOCAL --common-utils"
PLATFORM_BUILD_OPTIONS="--libtype static --x64"
ASN1_BUILD_OPTIONS="--libtype static --cms --x64"
NANOCAP_BUILD_OPTIONS="--libtype static --suiteb --x64"
NANOTAP2_COMMON_BUILD_OPTIONS="--libtype static --tap-local --tpm2 --suiteb --x64"
NANOTAP2_CONFIGPARSER_BUILD_OPTIONS="--libtype static --x64"
NANOTAP2_BUILD_OPTIONS="--libtype static --tap-local --tpm2 nanotap2 --x64"
CRYPTO_BUILD_OPTIONS="--libtype static --suiteb --tap --tpm2 --ssl --tap-hybrid-sign --x64"
TPM2_BUILD_OPTIONS="--libtype static --suiteb --x64"
SMP_TPM2_BUILD_OPTIONS="--libtype static --suiteb --x64"
INITIALIZE_BUILD_OPTIONS="--libtype static --x64"
NANOCERT_BUILD_OPTIONS="--libtype static --suiteb --ocsp --tap --cms --cmc --json-verify --x64 --cert --status-log"
NANOSSL_BUILD_OPTIONS="--libtype static --clean --suiteb --tap --ocsp nanossl --x64 --mauth"
MOCTPM2_TOOLS_BUILD_OPTIONS="--libtype static --tap-local --x64 all --strip"

while test $# -gt 0
do
    case "$1" in
        --toolchain)
            if [ "${2}" == "rpi64" ]; then
                TOOLS_ZIP_NAME=tpm2_tools-aarch64.zip
            else
                TOOLS_ZIP_NAME=tpm2_tools.zip
            fi
            shift
            ;;
        --gdb)
            BUILD_OPTIONS="${BUILD_OPTIONS} --gdb"
            ;;
        --debug)
            BUILD_OPTIONS="${BUILD_OPTIONS} --debug"
            ;;
        *)
            echo "Unknown option $1"
            exit 1
            ;;
    esac
    shift
done

cd ${MSS_DIR}
. ./scripts/ci/devenv.sh
DIST_DIR=${WORKSPACE}/dist

echo "*** Cleaning up ***"
rm -rf ${DIST_DIR}
mkdir -p ${DIST_DIR}

echo "*** Building libraries ***"
cd ${MSS_PROJECTS_DIR}/common && ./clean.sh && ./build.sh $BUILD_OPTIONS $COMMON_BUILD_OPTIONS
cd ${MSS_PROJECTS_DIR}/platform && ./clean.sh && ./build.sh $BUILD_OPTIONS $PLATFORM_BUILD_OPTIONS
cd ${MSS_PROJECTS_DIR}/asn1 && ./clean.sh && ./build.sh $BUILD_OPTIONS $ASN1_BUILD_OPTIONS
cd ${MSS_PROJECTS_DIR}/nanocap && ./clean.sh && ./build.sh $BUILD_OPTIONS $NANOCAP_BUILD_OPTIONS
cd ${MSS_PROJECTS_DIR}/nanotap2_common && ./clean.sh && ./build.sh $BUILD_OPTIONS $NANOTAP2_COMMON_BUILD_OPTIONS
cd ${MSS_PROJECTS_DIR}/nanotap2_configparser && ./clean.sh && ./build.sh $BUILD_OPTIONS $NANOTAP2_CONFIGPARSER_BUILD_OPTIONS
cd ${MSS_PROJECTS_DIR}/nanotap2 && ./clean.sh && ./build.sh $BUILD_OPTIONS $NANOTAP2_BUILD_OPTIONS
cd ${MSS_PROJECTS_DIR}/crypto && ./clean.sh && ./build.sh $BUILD_OPTIONS $CRYPTO_BUILD_OPTIONS
cd ${MSS_PROJECTS_DIR}/tpm2 && ./clean.sh && ./build.sh $BUILD_OPTIONS $TPM2_BUILD_OPTIONS
cd ${MSS_PROJECTS_DIR}/smp_tpm2 && ./clean.sh && ./build.sh $BUILD_OPTIONS $SMP_TPM2_BUILD_OPTIONS
cd ${MSS_PROJECTS_DIR}/initialize && ./clean.sh && ./build.sh $BUILD_OPTIONS $INITIALIZE_BUILD_OPTIONS
cd ${MSS_PROJECTS_DIR}/nanocert && ./clean.sh && ./build.sh $BUILD_OPTIONS $NANOCERT_BUILD_OPTIONS
cd ${MSS_PROJECTS_DIR}/nanossl && ./clean.sh && ./build.sh $BUILD_OPTIONS $NANOSSL_BUILD_OPTIONS

echo "*** Building tools ***"
echo "cd ${MSS_PROJECTS_DIR}/moctpm2_tools && ./clean.sh && ./build.sh $BUILD_OPTIONS $MOCTPM2_TOOLS_BUILD_OPTIONS"
cd ${MSS_PROJECTS_DIR}/moctpm2_tools && ./clean.sh && ./build.sh $BUILD_OPTIONS $MOCTPM2_TOOLS_BUILD_OPTIONS

mkdir -p ${DIST_DIR}/bin
cp ${BIN_DIR}/digicert_tpm2_* ${DIST_DIR}/bin/
cp ${BIN_DIR}/smp_tpm2_getidstr_bin ${DIST_DIR}/bin/

mkdir -p ${DIST_DIR}/conf/tap/tpm2
cp ${MSS_PROJECTS_DIR}/moctpm2_tools/provision/tpm2_prov.conf ${DIST_DIR}/conf/tap/tpm2/
cp ${MSS_PROJECTS_DIR}/moctpm2_tools/provision/tpm2_prov.conf.tmpl ${DIST_DIR}/conf/tap/tpm2/

mkdir -p ${DIST_DIR}/scripts/tap/tpm2
cp ${MSS_PROJECTS_DIR}/moctpm2_tools/provision/tpm2_provision_linux.sh ${DIST_DIR}/scripts/tap/tpm2/
cp ${MSS_PROJECTS_DIR}/moctpm2_tools/provision/tpm2_reset_linux.sh ${DIST_DIR}/scripts/tap/tpm2/

cp ${MSS_DIR}/scripts/ci/trustedge/provision_tpm2.sh ${DIST_DIR}/
cp ${MSS_DIR}/scripts/ci/trustedge/reset_tpm2.sh ${DIST_DIR}/

cd ${DIST_DIR}
zip -r $TOOLS_ZIP_NAME bin/ conf/ scripts/ provision_tpm2.sh reset_tpm2.sh
