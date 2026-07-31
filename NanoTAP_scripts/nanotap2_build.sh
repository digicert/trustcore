#!/usr/bin/env bash

set -e

######################
function show_usage
{
  echo ""
  echo "./build.sh [Options] "
  echo ""
  echo "   --gdb              - Build Debug version."
  echo "   --debug            - Build with Digicert logging enabled for specific build executable."
  echo "   --useloopbackaddr  - Build TAP server to listen only on loopback address."
  echo "   --data-protect     - Build TAP server with data protection for configuration files."
  echo "   --tap-data-protect - Build with data protection and TAP default handlers."
  echo "   --pkcs11-dynamic   - Build with dynamic loading for multiple pkcs11 libraries"
  echo "   --softhsm2         - Build with softhsm2."
  echo "   --cloudhsm         - Build with cloudhsm."
  echo "   --dssm             - Build with ssm."
  echo "   --pkcs11-tee       - Build with TEE PKCS11"
  echo "   --pkcs11-path      - Path (directory and filename) of pkcs11 library."
  echo "   --tee              - Build with TEE smp"
  echo "   --tee-path         - Path (directory) of teec library"
  echo "   --help             - Show Usage"
  echo "   --x32              - Creates build for 32Bit machine. By default creates build for 64Bit machine."
  echo "   --x64              - Creates build for 64Bit machine. By default creates build for 64Bit machine."
  echo "   --toolchain <toolchain> - Cross compile build using the specified toolchain. This toolchain"
  echo "                             must have the appropriate handling in MocPlatform.cmake"
  echo ""
  exit -1
}

BUILD_OPTIONS=""
TAP_SERVER_OPTIONS=""
IS_32_BIT_BUILD=false
IS_64_BIT_BUILD=false
TARGET_ARCH_PARAM=--x64
TOOLCHAIN=""
INV_OPT=0
DATA_PROTECT=""
TAP_DATA_PROTECT=""
# Additional flag needed for building nanotap2 with --data-protect and --tpm2 for --tap-data-protect case
DATA_PROTECT_FLAG=""
is_dp=0
is_tap_dp=0
SMP_ARG=""
PKCS11_TYPE=""
PKCS11_PATH=""
COMMON_ARG=""
TEE_ARG=""
TEE_PATH=""
TPM2_ARG=" --tpm2"

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
        --useloopbackaddr)
            echo "Building TAP server to listen only on loopback address...";
            TAP_SERVER_OPTIONS+=" $1"
            ;;
        --data-protect)
            echo "Building TAP server with data protection...";
            DATA_PROTECT=" $1"
            is_dp=1
            ;;
        --tap-data-protect)
            echo "Building TAP server with data protection and TAP handlers...";
            TAP_DATA_PROTECT=" $1"
            DATA_PROTECT_FLAG=" --data-protect --tpm2"
            is_tap_dp=1
            ;;
        --pkcs11-dynamic)
            SMP_ARG=" --pkcs11"
            PKCS11_TYPE=" --pkcs11-dynamic"
            COMMON_ARG=" --dynamic-load"
            ;;
        --softhsm2)
            SMP_ARG=" --pkcs11"
            PKCS11_TYPE=" --softhsm2"
            ;;
        --cloudhsm)
            SMP_ARG=" --pkcs11"
            PKCS11_TYPE=" --cloudhsm"
            ;;
        --dssm)
            SMP_ARG=" --pkcs11"
            PKCS11_TYPE=" --dssm"
            ;;
        --pkcs11-tee)
            SMP_ARG=" --pkcs11"
            PKCS11_TYPE=" --pkcs11-tee"
            ;;
        --pkcs11-path)
            PKCS11_PATH="$2"
            shift
            ;;
        --tee)
            TEE_ARG=" --tee"
            TPM2_ARG=""
            ;;
        --tee-path)
            TEE_PATH="$2"
            shift
            ;;
        --help)
            echo "Show Usage";
            INV_OPT=1
            ;;
        --x32)
            echo "Building for x32 machine...";
            IS_32_BIT_BUILD=true
            TARGET_ARCH_PARAM="--x32"
            ;;
        --x64)
            echo "Building for x64 machine...";
            IS_64_BIT_BUILD=true
            TARGET_ARCH_PARAM="--x64"
            ;;
        --toolchain)
            echo "Building with toolchain: $2"
            TOOLCHAIN="$2"
            BUILD_OPTIONS+=" --toolchain ${TOOLCHAIN}"
            shift
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

if [[ "$IS_32_BIT_BUILD" = "true" && "$IS_64_BIT_BUILD" = "true" ]] ; then
    echo "Build for either 32-bit or 64-bit"
    show_usage
    exit 1
fi

if [[ "$IS_32_BIT_BUILD" = "false" && "$IS_64_BIT_BUILD" = "false" ]] ; then
    echo "Building for x64 machine...";
    IS_64_BIT_BUILD=true
    TARGET_ARCH_PARAM=--x64
fi

if [ ! -z "${BUILD_OPTIONS}" ]; then
  echo "BUILD_OPTIONS=${BUILD_OPTIONS}"
  echo ""
fi

if [ ${is_tap_dp} -eq 1 ] && [ ${is_dp} -eq 0 ]; then
  echo "Error: Cannot enable --tap-data-protect without also enabling --data-protect"
  exit 1
fi

######################

SCRIPT_DIR=$( cd $(dirname $0) ; pwd -P )
export WORKSPACE="${SCRIPT_DIR}/.."
echo "WORKSPACE=${WORKSPACE}"
export MSS_DIR=${WORKSPACE}
export MSS_PROJECTS_DIR=${MSS_DIR}/projects

# Check if building for OSI
source ${MSS_DIR}/scripts/check_for_osi.sh
if [ ${OSI_BUILD} -eq 1 ]; then
    LIB_DIR="${MSS_DIR}/lib"
else
    LIB_DIR="${MSS_DIR}/bin"
fi

function get_pkcs11_lib {
    echo "Copying PKCS11 library(s) from ${PKCS11_PATH}"
    if [ "${PKCS11_TYPE}" == " --pkcs11-tee" ]; then
      cp "${PKCS11_PATH}/libckteec.so" ${LIB_DIR}
      cp "${PKCS11_PATH}/libteec.so" ${LIB_DIR}
      rm -f ${LIB_DIR}/libteec.so.1
      rm -f ${LIB_DIR}/libckteec.so.0
      ln -s ${LIB_DIR}/libteec.so ${LIB_DIR}/libteec.so.1
      ln -s ${LIB_DIR}/libckteec.so ${LIB_DIR}/libckteec.so.0
    else
      cp ${PKCS11_PATH} ${LIB_DIR}
    fi
}

function get_tee_lib {
    echo "Copying TEEC library from ${TEE_PATH}"
    cp ${TEE_PATH}/libteec.so ${LIB_DIR}
    rm -f ${LIB_DIR}/libteec.so.1
    ln -s ${LIB_DIR}/libteec.so ${LIB_DIR}/libteec.so.1
}

echo "***************************************************************"
echo "*** Building remote version of moctpm2 tools..."
echo "***************************************************************"

for pass in first second
do
    if [ "$pass" == "first" ]; then
        echo "***************************************************************"
        echo "*** Cleaning binaries and libraries " 
        echo "***************************************************************"

        rm -f ${LIB_DIR}/*.so
        rm -f ${LIB_DIR}/*.a
        rm -f bin/digicert_tpm2_*
        rm -f bin/nanotap_server_bin
        rm -f bin/tap_api_example
        rm -f bin/smp_tpm2_getidstr_bin

        if [ ! -z "${PKCS11_PATH}" ]; then
            get_pkcs11_lib
        fi
        if [ ! -z "${TEE_PATH}" ]; then
            get_tee_lib
        fi
    fi

    cd ${MSS_PROJECTS_DIR}/platform && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM
    cd ${MSS_PROJECTS_DIR}/common && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM $COMMON_ARG $DATA_PROTECT
    cd ${MSS_PROJECTS_DIR}/asn1 && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM
    cd ${MSS_PROJECTS_DIR}/nanocap && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM --suiteb
    cd ${MSS_PROJECTS_DIR}/nanotap2_common && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM $DATA_PROTECT $SMP_ARG $TEE_ARG --suiteb --tap-remote
    cd ${MSS_PROJECTS_DIR}/nanotap2_configparser && ./clean.sh &&./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM
    cd ${MSS_PROJECTS_DIR}/nanotap2 && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM $SMP_ARG $TEE_ARG --tap-remote clientcomm
    cd ${MSS_PROJECTS_DIR}/nanotap2 && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM $DATA_PROTECT_FLAG $SMP_ARG $TEE_ARG --tap-remote nanotap2
    cd ${MSS_PROJECTS_DIR}/crypto && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM --suiteb --tap --ssl $TPM2_ARG

    if [ "$DATA_PROTECT" == " --data-protect" ]; then
       cd ${MSS_PROJECTS_DIR}/data_protection && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM
    fi

    if [ "$SMP_ARG" == " --pkcs11" ] || [ "$TPM2_ARG" == " --tpm2" ]; then
       cd ${MSS_PROJECTS_DIR}/tpm2 && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM --suiteb
       cd ${MSS_PROJECTS_DIR}/smp_tpm2 && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM --suiteb
    fi

    if [ "$SMP_ARG" == " --pkcs11" ]; then
       cd ${MSS_PROJECTS_DIR}/smp_pkcs11 && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM $PKCS11_TYPE --pkcs11-tools --suiteb
    fi

    if [ "$TEE_ARG" == " --tee" ]; then
       cd ${MSS_PROJECTS_DIR}/smp_tee && ./clean.sh && ./build.sh --debug --gdb $BUILD_OPTIONS $TARGET_ARCH_PARAM --tee
    fi
    
    cd ${MSS_PROJECTS_DIR}/initialize && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM $DATA_PROTECT $TAP_DATA_PROTECT
    cd ${MSS_PROJECTS_DIR}/nanocert && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM --suiteb --tap
    cd ${MSS_PROJECTS_DIR}/nanossl && ./clean.sh && ./build.sh --clean $BUILD_OPTIONS $TARGET_ARCH_PARAM --suiteb --tap nanossl

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
        # Build binaries only on the second pass
        if [ "$TEE_ARG" == " --tee" ] && [ "$SMP_ARG" != " --pkcs11" ]; then
           cd ${MSS_PROJECTS_DIR}/moctee_tools && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM --tap-remote
        else
           cd ${MSS_PROJECTS_DIR}/moctpm2_tools && ./clean.sh && ./build.sh --clean $BUILD_OPTIONS $TARGET_ARCH_PARAM --tap-remote all
           if [ "$SMP_ARG" == " --pkcs11" ]; then
              cd ${MSS_PROJECTS_DIR}/mocpkcs11_tools && ./clean.sh && ./build.sh --clean $BUILD_OPTIONS $TARGET_ARCH_PARAM $PKCS11_TYPE --tap-remote all
           else
              cd ${MSS_PROJECTS_DIR}/tap_api_example && ./clean.sh && ./build.sh --clean $BUILD_OPTIONS $TARGET_ARCH_PARAM --tap-remote --tpm2 all
           fi
        fi
        cd ${MSS_PROJECTS_DIR}/nanotap_server && ./clean.sh && ./build.sh --clean $BUILD_OPTIONS $TARGET_ARCH_PARAM $TAP_SERVER_OPTIONS $DATA_PROTECT --tap-remote $TPM2_ARG $SMP_ARG $TEE_ARG


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

