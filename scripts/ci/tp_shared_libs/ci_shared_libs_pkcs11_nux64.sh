#!/usr/bin/env bash

set -e

########################################################################
# This script creates shared TAP libraries for TPEC and TPUC for pkcs11
# for a linux 64-bit platform.
#
# Variables $WORKSPACE, $BUILD_NUMBER and $GIT_COMMIT are set by Jenkins.
########################################################################

PROJ_FNAME=TPLibs
PLATFORM=$( uname -s )
CPU_ARCH=x86_64

function quit {
  [[ -z $1 ]] || echo "*** $1"
  exit
}

DIST_DIR=${WORKSPACE}/dist
PROD_DIR=${DIST_DIR}/shared_libs

## What to build
BUILD_TAP_REMOTE=0
BUILD_TAP_LOCAL=0
BUILD_TAP_OFF=0
BUILD_EXPORT_MBED=0
WITH_GDB=0
WITH_DEBUG=0
WITH_SUITEB=1
WITH_DP=0
GDB_ARG=
DEBUG_ARG=
MSG_LOGGER_ARG=
SUITEB_ARG=
PQC_ARG=
MBED_PATH=
MBED_ARG=
EXPORT_ARG=
DATA_PROTECT_ARG=
TAP_DATA_PROTECT_ARG=
MBED_PATH_ARG=
PKCS11_PATH=
PKCS11_ARG=
DES_ARG=
RC4_ARG=
PROXY_ARG=
TAP_EXTERN_ARG=
TAP_EXTERN_TARGET=
COMMON_ARG=
CVC_ARG=
TEE_ARG=
TEE_PATH=
SCRAM_ARG=

## Create a package?
SKIP_ZIP=0

# Where to build
export MSS_DIR=${WORKSPACE}
export MSS_PROJECTS_DIR=${MSS_DIR}/projects
export OUTPUT_DIR=${PROD_DIR}
export LIBS_OUTPUT_DIR=${OUTPUT_DIR}/libs

[[ -z ${WORKSPACE} ]] && quit "Error: Build environment is not set-up"
[[ -d "${OUTPUT_DIR}" ]] && rm -rf ${OUTPUT_DIR}/* || mkdir -p "${OUTPUT_DIR}"

function clean_projects {
  echo "Cleaning up built project artifacts..."
  rm -rf ${MSS_PROJECTS_DIR}/common/build
  rm -rf ${MSS_PROJECTS_DIR}/platform/build
  rm -rf ${MSS_PROJECTS_DIR}/asn1/build
  rm -rf ${MSS_PROJECTS_DIR}/nanocap/build
  rm -rf ${MSS_PROJECTS_DIR}/nanotap2_common/build
  rm -rf ${MSS_PROJECTS_DIR}/nanotap2_configparser/build
  rm -rf ${MSS_PROJECTS_DIR}/nanotap2/build
  rm -rf ${MSS_PROJECTS_DIR}/nanotap2/build
  rm -rf ${MSS_PROJECTS_DIR}/crypto/build
  rm -rf ${MSS_PROJECTS_DIR}/tpm2/build
  rm -rf ${MSS_PROJECTS_DIR}/smp_pkcs11/build
  rm -rf ${MSS_PROJECTS_DIR}/initialize/build
  rm -rf ${MSS_PROJECTS_DIR}/nanocert/build
  rm -rf ${MSS_PROJECTS_DIR}/nanossl/build
  rm -rf ${MSS_PROJECTS_DIR}/data_protection/build
}

function clean_built_libs {
  echo "Removing built libraries..."
  rm -rf ${LIBS_OUTPUT_DIR}
  mkdir -p ${LIBS_OUTPUT_DIR}

  rm -f ${WORKSPACE}/bin/*.so
  rm -f ${WORKSPACE}/bin/*.a
}

function package_libs {
  [[ -z $1 ]] && quit "Error: Missing library type for packaging" || LIBS_TYPE=$1

  if [ ${SKIP_ZIP} -eq 0 ]; then
    cp ${WORKSPACE}/bin/*.so ${LIBS_OUTPUT_DIR}
    if [[ ! -z "${MBED_ARG}" ]]; then
      cp ${WORKSPACE}/bin/*.so.* ${LIBS_OUTPUT_DIR}
    fi

    TAR_NAME=${PROJ_FNAME}_${LIBS_TYPE}_${PLATFORM}_${CPU_ARCH}
    [[ ${WITH_SUITEB} -eq 1 ]] && TAR_NAME=${TAR_NAME}_suiteb
    [[ ${WITH_DP} -eq 1 ]] && TAR_NAME=${TAR_NAME}_dp
    [[ ${WITH_DEBUG} -eq 1 ]] && TAR_NAME=${TAR_NAME}_debug
    [[ ${WITH_GDB} -eq 1 ]] && TAR_NAME=${TAR_NAME}_gdb
    TAR_NAME=${TAR_NAME}_${BUILD_NUMBER}_${GIT_COMMIT}.tgz

    echo "Archiving libraries to ${TAR_NAME}..."
    cd ${OUTPUT_DIR}
    rm -rf ${OUTPUT_DIR}/${TAR_NAME}
    tar -czvf ${TAR_NAME} -C ${LIBS_OUTPUT_DIR} .
  else
    echo "*** Skipping packaging"
  fi
}

function get_pkcs11_lib {
    echo "Copying PKCS11 library(s) from ${PKCS11_PATH}"
    if [ "${PKCS11_ARG}" == "--pkcs11-tee" ]; then
      cp "${PKCS11_PATH}/libckteec.so" ${WORKSPACE}/bin/
      cp "${PKCS11_PATH}/libteec.so" ${WORKSPACE}/bin/
      rm -f ${WORKSPACE}/bin/libckteec.so.0
      ln -s ${WORKSPACE}/bin/libckteec.so ${WORKSPACE}/bin/libckteec.so.0
      rm -f ${WORKSPACE}/bin/libteec.so.1
      ln -s ${WORKSPACE}/bin/libteec.so ${WORKSPACE}/bin/libteec.so.1
    else
      cp ${PKCS11_PATH} ${WORKSPACE}/bin/
    fi
}

function get_tee_lib {
    echo "Copying TEE library(s) from ${TEE_PATH}"
      cp "${TEE_PATH}/libteec.so" ${WORKSPACE}/bin/
      rm -f ${WORKSPACE}/bin/libteec.so.1
      ln -s ${WORKSPACE}/bin/libteec.so ${WORKSPACE}/bin/libteec.so.1
}

function build_tap_off {
  echo "***************************************"
  echo "*** Building libraries with TAP Off ..."
  echo "***************************************"

  clean_projects
  clean_built_libs

  for pass in first second
  do
    cd ${MSS_PROJECTS_DIR}/common && ./build.sh ${GDB_ARG} ${DATA_PROTECT_ARG} ${MSG_LOGGER_ARG} --debug --json --uri --x64 ${COMMON_ARG}
    cd ${MSS_PROJECTS_DIR}/platform && ./build.sh ${GDB_ARG} ${DEBUG_ARG} --x64
    cd ${MSS_PROJECTS_DIR}/asn1 && ./build.sh ${GDB_ARG} ${DEBUG_ARG} ${PQC_ARG} ${CVC_ARG} --cms --x64
    cd ${MSS_PROJECTS_DIR}/nanocap && ./build.sh ${GDB_ARG} ${DEBUG_ARG} --x64
    cd ${MSS_PROJECTS_DIR}/crypto && ./build.sh ${GDB_ARG} ${DEBUG_ARG} ${PQC_ARG} ${SUITEB_ARG} ${DES_ARG} ${EXPORT_ARG} ${MBED_ARG} ${MBED_PATH_ARG} "${MBED_PATH}" --ssl --x64
    cd ${MSS_PROJECTS_DIR}/initialize && ./build.sh ${DEBUG_ARG} ${GDB_ARG} ${DATA_PROTECT_ARG} --x64
    cd ${MSS_PROJECTS_DIR}/nanocert && ./build.sh ${GDB_ARG} ${PQC_ARG} ${SUITEB_ARG} ${DEBUG_ARG} ${DATA_PROTECT_ARG} ${DES_ARG} ${RC4_ARG} ${CVC_ARG} --ocsp --cmc --cms --json-verify ${DES_ARG} ${EXPORT_ARG} --x64 ${PROXY_ARG} --cert --status-log ${SCRAM_ARG}
    cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh --clean ${PQC_ARG} ${SUITEB_ARG} ${DEBUG_ARG} ${GDB_ARG} ${EXPORT_ARG} --ocsp nanossl --x64 --mauth ${PROXY_ARG}
    if [ ! -z "${DATA_PROTECT_ARG}" ]; then
        cd ${MSS_PROJECTS_DIR}/data_protection && ./build.sh ${DEBUG_ARG} ${GDB_ARG} ${EXPORT_ARG} --x64
    fi
  done

  package_libs TAPOff

}

function build_tap_local {
  echo "*************************************************"
  echo "*** Building libraries with TAP in LOCAL mode ..."
  echo "*************************************************"

  clean_projects
  clean_built_libs
  if [ ! -z "${PKCS11_PATH}" ]; then
    get_pkcs11_lib
  fi
  if [ ! -z "${TEE_ARG}" ]; then
    get_tee_lib
  fi

  for pass in first second
  do
    cd ${MSS_PROJECTS_DIR}/common && ./build.sh ${GDB_ARG} ${DATA_PROTECT_ARG} ${MSG_LOGGER_ARG} --debug --json --uri --x64 ${COMMON_ARG} --cmake-opt "-DCM_TAP_TYPE=LOCAL"
    cd ${MSS_PROJECTS_DIR}/platform && ./build.sh ${GDB_ARG} ${DEBUG_ARG} --x64
    cd ${MSS_PROJECTS_DIR}/asn1 && ./build.sh ${GDB_ARG} ${PQC_ARG} ${DEBUG_ARG} ${CVC_ARG} --cms --x64
    cd ${MSS_PROJECTS_DIR}/nanocap && ./build.sh ${GDB_ARG} ${DEBUG_ARG} --x64
    cd ${MSS_PROJECTS_DIR}/nanotap2_common && ./build.sh --pkcs11 --tap-local --tpm2 ${TEE_ARG} ${DEBUG_ARG} ${GDB_ARG} ${SUITEB_ARG} ${DATA_PROTECT_ARG} --x64
    cd ${MSS_PROJECTS_DIR}/nanotap2_configparser && ./build.sh ${DEBUG_ARG} ${GDB_ARG} --x64
    cd ${MSS_PROJECTS_DIR}/nanotap2 && ./build.sh --pkcs11 --tap-local ${TEE_ARG} ${DEBUG_ARG} ${GDB_ARG} --tpm2 ${TAP_EXTERN_TARGET} nanotap2 ${DATA_PROTECT_ARG} --x64
    cd ${MSS_PROJECTS_DIR}/crypto && ./build.sh ${GDB_ARG} ${DEBUG_ARG} ${PQC_ARG} ${SUITEB_ARG} ${TAP_EXTERN_ARG} --tap --tpm2 --ssl ${EXPORT_ARG} ${MBED_ARG} ${MBED_PATH_ARG} "${MBED_PATH}" --x64
    if [ ! -z "${DATA_PROTECT_ARG}" ]; then
        cd ${MSS_PROJECTS_DIR}/data_protection && ./build.sh ${DEBUG_ARG} ${GDB_ARG} ${EXPORT_ARG} --x64
    fi
    if [ ! -z "${TEE_ARG}" ]; then
        cd ${MSS_PROJECTS_DIR}/smp_tee && ./build.sh ${DEBUG_ARG} ${GDB_ARG} --tee --x64
    fi
    cd ${MSS_PROJECTS_DIR}/tpm2 && ./build.sh --pkcs11 ${SUITEB_ARG} ${DEBUG_ARG} ${GDB_ARG} --x64
    cd ${MSS_PROJECTS_DIR}/smp_pkcs11 && ./build.sh ${SUITEB_ARG} ${DEBUG_ARG} ${GDB_ARG} ${PKCS11_ARG} --pkcs11-tools --x64
    cd ${MSS_PROJECTS_DIR}/initialize && ./build.sh ${DEBUG_ARG} ${GDB_ARG} ${DATA_PROTECT_ARG} ${TAP_DATA_PROTECT_ARG} --x64
    cd ${MSS_PROJECTS_DIR}/nanocert && ./build.sh ${GDB_ARG}  ${PQC_ARG} ${SUITEB_ARG} ${DEBUG_ARG} ${DATA_PROTECT_ARG} ${DES_ARG} ${RC4_ARG} ${CVC_ARG} --ocsp --tap --cms --cmc --json-verify ${DES_ARG} ${EXPORT_ARG} --x64 ${PROXY_ARG} --cert --status-log ${SCRAM_ARG}
    cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh --clean ${PQC_ARG} ${SUITEB_ARG} ${DEBUG_ARG} ${GDB_ARG} ${EXPORT_ARG} --tap --ocsp nanossl --x64 --mauth ${PROXY_ARG}
  done

  package_libs TAPLocal

}

function build_tap_remote {
  echo "**************************************************"
  echo "*** Building libraries with TAP in REMOTE mode ..."
  echo "**************************************************"

  clean_projects
  clean_built_libs
  if [ ! -z "${PKCS11_PATH}" ]; then
    get_pkcs11_lib
  fi

  for pass in first second
  do
    cd ${MSS_PROJECTS_DIR}/common && ./build.sh ${GDB_ARG} ${DATA_PROTECT_ARG} ${MSG_LOGGER_ARG} --debug --json --uri --x64 ${COMMON_ARG} --cmake-opt "-DCM_TAP_TYPE=REMOTE"
    cd ${MSS_PROJECTS_DIR}/platform && ./build.sh ${GDB_ARG} ${DEBUG_ARG} --x64
    cd ${MSS_PROJECTS_DIR}/asn1 && ./build.sh ${GDB_ARG} ${DEBUG_ARG} ${PQC_ARG} ${CVC_ARG} --cms --x64
    cd ${MSS_PROJECTS_DIR}/nanocap && ./build.sh ${GDB_ARG} ${DEBUG_ARG} --x64
    cd ${MSS_PROJECTS_DIR}/nanotap2_common && ./build.sh --pkcs11 ${DEBUG_ARG} ${GDB_ARG} ${SUITEB_ARG} --tap-remote ${DATA_PROTECT_ARG} --x64
    cd ${MSS_PROJECTS_DIR}/nanotap2_configparser && ./build.sh ${GDB_ARG} ${DEBUG_ARG} --x64
    cd ${MSS_PROJECTS_DIR}/nanotap2 && ./build.sh --pkcs11 --tap-remote ${DEBUG_ARG} ${GDB_ARG} ${TAP_EXTERN_ARG} --tpm2 --tcp-close-msg clientcomm --x64
    cd ${MSS_PROJECTS_DIR}/nanotap2 && ./build.sh --tap-remote  ${DEBUG_ARG} ${GDB_ARG} ${TAP_EXTERN_TARGET} nanotap2 ${DATA_PROTECT_ARG} --x64
    cd ${MSS_PROJECTS_DIR}/crypto && ./build.sh ${GDB_ARG} ${DEBUG_ARG} ${PQC_ARG} ${SUITEB_ARG} ${TAP_EXTERN_ARG} --tap --tpm2 --ssl ${EXPORT_ARG} ${MBED_ARG} ${MBED_PATH_ARG} "${MBED_PATH}" --x64
    if [ ! -z "${DATA_PROTECT_ARG}" ]; then
        cd ${MSS_PROJECTS_DIR}/data_protection && ./build.sh ${DEBUG_ARG} ${GDB_ARG} ${EXPORT_ARG} --x64
    fi
    cd ${MSS_PROJECTS_DIR}/tpm2 && ./build.sh --pkcs11 ${SUITEB_ARG} ${DEBUG_ARG} ${GDB_ARG} --x64
    cd ${MSS_PROJECTS_DIR}/smp_pkcs11 && ./build.sh ${SUITEB_ARG} ${DEBUG_ARG} ${GDB_ARG} ${PKCS11_ARG} --pkcs11-tools --x64
    cd ${MSS_PROJECTS_DIR}/initialize && ./build.sh ${DEBUG_ARG} ${GDB_ARG} ${DATA_PROTECT_ARG} ${TAP_DATA_PROTECT_ARG} --x64
    cd ${MSS_PROJECTS_DIR}/nanocert && ./build.sh ${GDB_ARG} ${PQC_ARG} ${SUITEB_ARG} ${DEBUG_ARG} ${DATA_PROTECT_ARG} ${DES_ARG} ${RC4_ARG} ${CVC_ARG} ${TAP_EXTERN_ARG} --ocsp --tap --cms --cmc --json-verify ${DES_ARG} ${EXPORT_ARG} --x64 ${PROXY_ARG} --cert --status-log ${SCRAM_ARG}
    cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh --clean ${GDB_ARG} ${PQC_ARG} ${SUITEB_ARG} ${DEBUG_ARG} --tap --tap-remote ${EXPORT_ARG} ${TAP_EXTERN_ARG} --ocsp nanossl --x64 --mauth ${PROXY_ARG}
  done

  package_libs TAPRemote

}

function show_usage
{
  echo ""
  echo "Usage: $0 [--tap-off] [--tap-local] [--tap-remote] [--softhsm2] [--cloudhsm] [--dssm] [--pkcs11-path] [--no-zip] [--debug] [--gdb] [--des]"
  echo ""
  echo " Provide at least one of the following arguments:"
  echo "   --tap-off       Build libraries without TAP"
  echo "   --tap-local     Build libraries with TAP in local mode"
  echo "   --tap-remote    Build libraries with TAP in remote mode"
  echo ""
  echo " Provide at least one of the following arguments:"
  echo "   --pkcs11-dynamic Enable dynamic loading for multiple pkcs11 libraries"
  echo "   --softhsm2       Build libraries using the SoftHSM2 PKCS11 library"
  echo "   --cloudhsm       Build libraries using the Amazon CloudHSM PKCS11 library"
  echo "   --dssm           Build libraries using the Digicert ssm PKCS11 library"
  echo "   --pkcs11-tee     Build libraries using TEE PKCS11 library"
  echo ""
  echo " Additional options:"
  echo "   --disable-suiteb    Disable Suite-B algos"
  echo "   --data-protect      Enable Data Protection"
  echo "   --tap-data-protect  Enable data protection and TAP default handlers"
  echo "   --tee               Build with TEE support"
  echo "   --tee-path          Path to TEE supporting libraries"
  echo "   --debug             Build with DEBUG output"
  echo "   --gdb               Include GDB Debugger symbols"
  echo "   --no-zip            Do not create ZIP/TAR files"
  echo "   --export            Build the Export Edition"
  echo "   --mbed              Export with MBedTLS"
  echo "   --mbed-path         MbedTLS Path"
  echo "   --pkcs11-path       Optional explicit path to PKCS11 library. If not specified the default search paths will be used."
  echo "   --cvc               Build with CV certs"
  echo "   --des               Build with single DES"
  echo "   --arc4              Add RC4 support"
  echo "   --proxy             Build with http proxy support"
  echo "   --tap-extern        Build with TAP extern"
  echo ""
  exit 255
}

############################

INV_OPT=0

while test $# -gt 0
do
    case "$1" in
        --gdb)
            echo "Enabling GDB"
            WITH_GDB=1
            GDB_ARG='--gdb'
            ;;
        --debug)
            echo "Enabling Debug"
            WITH_DEBUG=1
            DEBUG_ARG='--debug'
            MSG_LOGGER_ARG='--msg-logger'
            ;;
        --no-zip)
            SKIP_ZIP=1
            ;;
        --suiteb)
            echo "Suiteb enabled by default"
            ;;
        --disable-suiteb)
            echo "Disabling SuiteB algos"
            WITH_SUITEB=0
            SUITEB_ARG=' --disable-suiteb'
            ;;
        --tap-local)
            BUILD_TAP_LOCAL=1
            ;;
        --tap-off)
            BUILD_TAP_OFF=1
            ;;
        --tap-remote)
            BUILD_TAP_REMOTE=1
            ;;
        --pkcs11-dynamic)
            PKCS11_ARG="--pkcs11-dynamic"
            COMMON_ARG="--dynamic-load"
            ;;
        --softhsm2)
            PKCS11_ARG="--softhsm2"
            ;;
        --cloudhsm)
            PKCS11_ARG="--cloudhsm"
            ;;
        --dssm)
            PKCS11_ARG="--dssm"
            ;;
        --pkcs11-tee)
            PKCS11_ARG="--pkcs11-tee"
            ;;
        --pkcs11-path)
            PKCS11_PATH="$2"
            ;;
        --disable-pqc)
            echo "Disabling PQC algos"
            PQC_ARG=' --disable-pqc'
            ;;
        --tee)
            echo "Enabling TEE"
            TEE_ARG=" --tee"
            ;;
        --tee-path)
            TEE_PATH="$2"
            ;;
        --export)
            echo "Enabling export"
            EXPORT_ARG="--export"
            ;;
        --des)
            echo "Enabling DES"
            DES_ARG="--des"
            ;;
        --arc4)
            echo "Enabling RC4"
            RC4_ARG="--arc4"
            ;;
        --cvc)
            echo "Enabling CV Certs"
            CVC_ARG="--cvc"
            ;;
        --data-protect)
            echo "Enabling data protection"
            DATA_PROTECT_ARG="--data-protect"
            WITH_DP=1
            ;;
        --tap-data-protect)
            echo "Enabling data protection with TAP default handlers"
            TAP_DATA_PROTECT_ARG='--tap-data-protect'
            DATA_PROTECT_ARG='--data-protect'
            WITH_DP=1
            ;;
        --mbed)
            MBED_ARG="--mbed"
            BUILD_EXPORT_MBED=1
            ;;
        --mbed-path)
            MBED_PATH_ARG="--mbed-path"
            MBED_PATH="$2"
            ;;
        --des)
            echo "Build with DES"
            DES_ARG="--des"
            ;;
        --x64)
            ;;
        --proxy)
            echo "Building with proxy support"
            PROXY_ARG=" --proxy"
            ;;
        --tap-extern)
            echo "Build with TAP extern"
            TAP_EXTERN_ARG="--tap-extern"
            TAP_EXTERN_TARGET="tap_extern"
            ;;
        --scram)
            echo "Building with scram support"
            SCRAM_ARG=" --scram"
            ;;
        --*)
            echo "Invalid option: $1"; INV_OPT=1
            ;;
    esac
    shift
done

if [ ${INV_OPT} -eq 1 ]; then
  show_usage
fi

if [ -z ${PKCS11_ARG} ]; then
  show_usage
fi

if [[ ${BUILD_TAP_OFF} -eq 0 && ${BUILD_TAP_LOCAL} -eq 0 && ${BUILD_TAP_REMOTE} -eq 0 ]]; then
  echo "There's nothing to do. Specify which library flavors to build."
  show_usage
fi

[[ ${BUILD_TAP_OFF} -eq 1 ]] && build_tap_off
[[ ${BUILD_TAP_LOCAL} -eq 1 ]] && build_tap_local
[[ ${BUILD_TAP_REMOTE} -eq 1 ]] && build_tap_remote

echo "Done"
