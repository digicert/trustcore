#!/usr/bin/env bash

set -e

########################################################################
# This script creates shared crypto related libraries on 64bit machines
#
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
BUILD_EXPORT_MBED=0
WITH_GDB=0
WITH_DEBUG=0
WITH_DP=0
GDB_ARG=
PG_ARG=
DEBUG_ARG=
OPERATOR_PATH=
MBED_PATH=
MBED_ARG=
OQS_PATH=
OQS_ARG=
PQC_ARG=
EXPORT_ARG=
DATA_PROTECT_ARG=
TAP_DATA_PROTECT_ARG=
MBED_PATH_ARG=
OQS_PATH_ARG=
CERT_SUPPORT=""
CERT_BLOB_EXTRACT_SUPPORT=""
FIPS_ARG=
FIPS_700_COMPAT_OPTION=""
TAP_ARG=
TAP_LOCAL_ARG=
TAP_EXTERN_ARG=
TAP_EXTERN_TARGET=
TPM2_ARG=
DES_ARG=
RC4_ARG=
HW_ACCEL_ARG=
AIDE_ARG=
BLAKE2_ARG=
TOOLCHAIN=
X64=" --x64"
CVC_ARG=
SCRAM_ARG=
VLONG_ARG=
PSS_ARG=

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
  rm -rf ${MSS_PROJECTS_DIR}/crypto/build
  rm -rf ${MSS_PROJECTS_DIR}/initialize/build
  rm -rf ${MSS_PROJECTS_DIR}/nanocert/build
  rm -rf ${MSS_PROJECTS_DIR}/data_protection/build
}

function clean_built_libs {
  echo "Removing built libraries..."
  rm -rf ${LIBS_OUTPUT_DIR}
  mkdir -p ${LIBS_OUTPUT_DIR}

  for libs in ${WORKSPACE}/bin/*.so; do
    if [[ ! "$libs" == *libmss.so ]] || [[ -z $FIPS_ARG ]]; then
        rm -f $libs
    fi
  done
  rm -f ${WORKSPACE}/bin/*.a
}

function build_libs {
  echo "***************************************"
  echo "*** Building libraries ...          ***"
  echo "***************************************"

  clean_projects
  clean_built_libs

  for pass in first second
  do
    cd ${MSS_PROJECTS_DIR}/platform && ./build.sh ${PG_ARG} ${GDB_ARG} ${DEBUG_ARG} ${FIPS_ARG} ${X64} ${TOOLCHAIN} 
    if [ "${TAP_LOCAL_ARG}" == "--tap-remote" ]; then
      cd ${MSS_PROJECTS_DIR}/common && ./build.sh ${PG_ARG} ${GDB_ARG} ${DATA_PROTECT_ARG} --msg-logger --debug --json --uri ${VLONG_ARG} ${X64} ${TOOLCHAIN} --cmake-opt "-DCM_TAP_TYPE=REMOTE"
    else
      cd ${MSS_PROJECTS_DIR}/common && ./build.sh ${PG_ARG} ${GDB_ARG} ${DATA_PROTECT_ARG} ${FIPS_ARG} --msg-logger --debug --json --uri ${VLONG_ARG} ${X64} ${TOOLCHAIN} 
    fi

    cd ${MSS_PROJECTS_DIR}/asn1 && ./build.sh ${PG_ARG} ${GDB_ARG} ${DEBUG_ARG} --cms ${PQC_ARG} ${CVC_ARG} ${X64} ${TOOLCHAIN} 
    cd ${MSS_PROJECTS_DIR}/nanocap && ./build.sh ${PG_ARG} ${GDB_ARG} ${DEBUG_ARG} ${X64} ${TOOLCHAIN} 
    if [ ! -z "${TAP_ARG}" ]; then
      cd ${MSS_PROJECTS_DIR}/nanotap2_common && ./build.sh ${PG_ARG} ${GDB_ARG} ${DEBUG_ARG} ${TAP_LOCAL_ARG} ${TPM2_ARG} ${X64} ${TOOLCHAIN} 
      cd ${MSS_PROJECTS_DIR}/nanotap2_configparser && ./build.sh ${PG_ARG} ${GDB_ARG} ${DEBUG_ARG} ${X64} ${TOOLCHAIN} 
      if [ "${TAP_LOCAL_ARG}" == "--tap-remote" ]; then
        cd ${MSS_PROJECTS_DIR}/nanotap2 && ./build.sh ${DEBUG_ARG} ${PG_ARG} ${GDB_ARG} ${TAP_LOCAL_ARG} ${TPM2_ARG} ${TAP_EXTERN_ARG} ${X64} ${TOOLCHAIN} clientcomm
      fi
      cd ${MSS_PROJECTS_DIR}/nanotap2 && ./build.sh ${PG_ARG} ${GDB_ARG} ${DEBUG_ARG} ${TAP_LOCAL_ARG} ${TPM2_ARG} ${TAP_EXTERN_TARGET} ${X64} ${TOOLCHAIN} nanotap2
      cd ${MSS_PROJECTS_DIR}/tpm2 && ./build.sh ${PG_ARG} ${GDB_ARG} ${DEBUG_ARG} ${X64} ${TOOLCHAIN} 
      cd ${MSS_PROJECTS_DIR}/smp_tpm2 && ./build.sh ${PG_ARG} ${GDB_ARG} ${DEBUG_ARG} ${X64} ${TOOLCHAIN} 
    fi
    cd ${MSS_PROJECTS_DIR}/crypto && ./build.sh ${PG_ARG} ${GDB_ARG} ${DEBUG_ARG} ${PQC_ARG} ${BLAKE2_ARG} ${HW_ACCEL_ARG} ${VLONG_ARG} ${OPERATOR_PATH} ${PSS_ARG} ${TAP_ARG} ${TAP_EXTERN_ARG} ${TPM2_ARG} ${FIPS_ARG} ${FIPS_700_COMPAT_OPTION} ${EXPORT_ARG} ${MBED_ARG} ${MBED_PATH_ARG} "${MBED_PATH}" ${OQS_ARG} ${OQS_PATH_ARG} "${OQS_PATH}" --ssl ${X64} ${TOOLCHAIN}
    cd ${MSS_PROJECTS_DIR}/initialize && ./build.sh ${DEBUG_ARG} ${PG_ARG} ${GDB_ARG} ${DATA_PROTECT_ARG} ${X64} ${TOOLCHAIN} --custom-entropy
    cd ${MSS_PROJECTS_DIR}/nanocert && ./build.sh ${PG_ARG} ${GDB_ARG} ${DEBUG_ARG} ${PQC_ARG} ${TAP_ARG} ${FIPS_ARG} ${DATA_PROTECT_ARG} ${CVC_ARG} --ocsp --cmc --cms --json-verify ${TAP_EXTERN_ARG} ${EXPORT_ARG} ${X64} ${TOOLCHAIN} ${CERT_SUPPORT} ${CERT_BLOB_EXTRACT_SUPPORT} ${DES_ARG} ${RC4_ARG} ${SCRAM_ARG} ${AIDE_ARG}
    if [ ! -z "${DATA_PROTECT_ARG}" ]; then
      cd ${MSS_PROJECTS_DIR}/data_protection && ./build.sh ${DEBUG_ARG} ${PG_ARG} ${GDB_ARG} ${EXPORT_ARG} ${BLAKE2_ARG} ${X64} ${TOOLCHAIN} 
    fi
    if [ "${TAP_LOCAL_ARG}" == "--tap-remote" ]; then
      cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh --clean ${PG_ARG} ${GDB_ARG} ${DEBUG_ARG} ${PQC_ARG} --tap --tap-remote ${TAP_EXTERN_ARG} ${EXPORT_ARG} --ocsp nanossl ${X64} ${TOOLCHAIN} --mauth
    fi
  done
}

function show_usage
{
  echo ""
  echo "Usage: $0 [--debug] [--gdb] [--hw-accel] [--operator-path <path>] [--mbed] [--mbed-path <path>] [--oqs] [--oqs-path <path>] [--cert] [--fips] [--fips-700-compat] [--tap-local] [--tap-remote] [--tap-extern] [--des] [--blake2]"
  echo ""
  echo " Additional options:"
  echo "   --data-protect      Enable Data Protection"
  echo "   --tap-data-protect  Enable data protection and TAP default handlers"
  echo "   --debug             Build with DEBUG output"
  echo "   --gdb               Include GDB Debugger symbols"
  echo "   --pg                Include call stack tracing"
  echo "   --no-zip            Do not create ZIP/TAR files"
  echo "   --operator-path     Path and name of static library with operator implementations"
  echo "   --export            Build the Export Edition"
  echo "   --mbed              Export with MBedTLS"
  echo "   --mbed-path         MbedTLS Path"
  echo "   --oqs               Build oqs operators"
  echo "   --oqs-path          OQS Path"
  echo "   --cert              Add certificate search support"
  echo "   --fips              Build with FIPS"
  echo "   --fips-700-compat   Build with backward compatibility with FIPS REL_700_U1 binary."
  echo "   --tap-local         Build TAP local with TPM2"
  echo "   --tap-remote        Build TAP remote with TPM2"
  echo "   --tap-extern        Build with TAP extern"
  echo "   --pss-var-salt      Auto recover PSS salt length during inline PSS verify during PSS sign operation for TAP."
  echo "   --des               Build with single DES"
  echo "   --arc4              Build with ARC4"
  echo "   --blake2            Build with Blake2"
  echo "   --hw-accel          Build with hardware acceleration"
  echo "   --aide              Build with aide"
  echo "   --cvc               Build with CV Certificate support"
  echo "   --scram             Build with scram support"
  echo "   --vlong-const       Build with constant time vlong ops."
  echo "   --toolchain <rpi64|rpi32|qnx-x86> - Specify the toolchain to be used"
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
        --pg)
            echo "Enabling PG call stack tracing"
            PG_ARG=' --pg'
            ;;
        --debug)
            echo "Enabling Debug"
            WITH_DEBUG=1
            DEBUG_ARG='--debug'
            ;;
        --suiteb)
            echo "suiteb is always enabled";
            ;;
        --pqc)
            echo "pqc is always enabled";
            ;;
        --disable-pqc)
            PQC_ARG=' --disable-pqc'
            ;;
        --blake2)
            echo "Building with Blake2 enabled";
            BLAKE2_ARG='--blake2'
            ;;
        --export)
            echo "Enabling export"
            EXPORT_ARG="--export"
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
        --operator-path)
            OPERATOR_PATH=" --operator-path $2"
            shift
            ;;
        --mbed)
            MBED_ARG="--mbed"
            BUILD_EXPORT_MBED=1
            ;;
        --mbed-path)
            MBED_PATH_ARG="--mbed-path"
            MBED_PATH="$2"
            shift
            ;;
        --oqs)
            OQS_ARG="--oqs"
            ;;
        --oqs-path)
            OQS_PATH_ARG="--oqs-path"
            OQS_PATH="$2"
            shift
            ;;
        --cert)
            echo "Build NanoCert with certificate search support"
            CERT_SUPPORT="$1"
            ;;
        --cert-blob-extract)
            echo "Build NanoCert with certificate blob extract support"
            CERT_BLOB_EXTRACT_SUPPORT="$1"
            ;;
        --fips)
            echo "Build with FIPS"
            FIPS_ARG="--fips"
            ;;
        --fips-700-compat)
            echo "Build with backward compatibility with FIPS REL_700_U1 binary."
            FIPS_700_COMPAT_OPTION=" $1"
            ;;
        --tap-local)
            echo "Build with TAP local"
            TAP_ARG="--tap"
            TAP_LOCAL_ARG="--tap-local"
            TPM2_ARG="--tpm2"
            ;;
        --tap-remote)
            echo "Build with TAP remote"
            TAP_ARG="--tap"
            TAP_LOCAL_ARG="--tap-remote"
            TPM2_ARG="--tpm2"
            ;;
        --tap-extern)
            echo "Build with TAP extern"
            TAP_EXTERN_ARG="--tap-extern"
            TAP_EXTERN_TARGET="tap_extern"
            ;;
        --pss-var-salt)
            echo "Building with variable salt length for TAP...";
            PSS_ARG=" --pss-var-salt"
            ;;
        --des)
            echo "Build with DES"
            DES_ARG="--des"
            ;;
        --arc4)
            echo "Build with ARC4"
            RC4_ARG="--arc4"
            ;;
        --hw-accel)
            echo "Build with hw acceleration"
            HW_ACCEL_ARG=" --hw-accel"
            ;;
        --aide)
            echo "Build with aide"
            AIDE_ARG=" --aide"
            ;;
        --cvc)
            echo "Enabling CV Certificates"
            CVC_ARG=" --cvc"
            ;;
        --scram)
            echo "Building with scram support"
            SCRAM_ARG=" --scram"
            ;;
        --vlong-const)
            echo "Building with constant time vlong operations enabled"
            VLONG_ARG=" --vlong-const"
            ;;
        --toolchain)
            X64=""
            TOOLCHAIN=" --toolchain ${2}"
            shift
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

build_libs

echo "Done"
