#!/usr/bin/env bash

function show_usage
{
  echo ""
  echo "./nanotap2_moctap_build.sh --debug [--tpm2 | --tpm12] [--useloopbackaddr] [--x64 | --x32]"
  echo ""
  echo "   --help            - Build options information"
  echo "   --debug           - Build debug version with Digicert logging enabled."
  echo "   --tpm2            - Build with support for TPM 2 SMP."
  echo "   --useloopbackaddr - Build TAP server to listen only on loopback address"
  echo "   --tpm12           - Build with support for TPM 1.2 SMP."
  echo "   --x32             - Creates build for 32Bit machine. By default creates build for 64Bit machine."
  echo "   --x64             - Creates build for 64Bit machine. By default creates build for 64Bit machine."
  echo ""
  exit -1
}

SCRIPT_DIR=$( cd $(dirname $0) ; pwd -P )
export WORKSPACE="${SCRIPT_DIR}/.."
echo "WORKSPACE=${WORKSPACE}"
export MSS_DIR=${WORKSPACE}
export MSS_PROJECTS_DIR=${MSS_DIR}/projects

# Variables
DO_BUILD_TPM12=false
DO_BUILD_TPM2=false
SMP_DEP_FLAG=
IS_32_BIT_BUILD=false
IS_64_BIT_BUILD=false
TARGET_ARCH_PARAM=--x64
DEBUG_OPTION=
INV_OPT=0
loopbackflag=""

# Check if building for OSI
source ${MSS_DIR}/scripts/check_for_osi.sh
if [ ${OSI_BUILD} -eq 1 ]; then
    LIB_DIR="${MSS_DIR}/lib"
else
    LIB_DIR="${MSS_DIR}/bin"
fi

#############################################################################
#parse arguments
while test $# -gt 0
do
    case "$1" in
        --help)
            INV_OPT=1
            ;;
        --debug)
            echo "Enabling Debug build...";
            DEBUG_OPTION+=" --gdb --debug"
            ;;
        --tpm2)
            echo "Building with tpm2...";
            DO_BUILD_TPM2=true
            SMP_DEP_FLAG+=" --tpm2"
            ;;
        --tpm12)
            echo "Building with tpm12...";
            DO_BUILD_TPM12=true
            SMP_DEP_FLAG+=" --tpm12"
            ;;
        --useloopbackaddr)
            echo "Building TAP server to listen only on loopback address"
            loopbackflag="--useloopbackaddr"
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
        --*)
            echo "Invalid option: $1";
            INV_OPT=1
            ;;
         *)
            echo "Adding Argument: $1";
            ADD_ARGS+=" $1"
            ;;
    esac
    shift
done

if [ ${INV_OPT} -eq 1 ]; then
  show_usage
fi

#Validate arguments
if [[ "$DO_BUILD_TPM12" == "true" && "$DO_BUILD_TPM2" == "true" ]] ||
   [[ "$DO_BUILD_TPM12" = "false" && "$DO_BUILD_TPM2" = "false" ]] ; then
    echo "Build with support for either TPM12 or TPM2"
    show_usage
    exit 1
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


##############################################################################
#Build steps
echo "***************************************************************"
echo "*** Building remote version of moctap tools ..."
echo "***************************************************************"

for pass in first second
do
    if [ "$pass" == "first" ]; then
        echo "***************************************************************"
        echo "*** Cleaning binaries and libraries "
        echo "***************************************************************"

        rm ${LIB_DIR}/*.so
        rm ${LIB_DIR}/*.a
        rm bin/moctap_*
        rm bin/nanotap_server_*
        rm bin/tap_api_example*
        if [ "$DO_BUILD_TPM2" == "true" ]; then
           rm bin/digicert_tpm2_*
           rm bin/smp_tpm2_*
        fi
        if [ "$DO_BUILD_TPM12" == "true" ]; then
           rm bin/moctpm_*
           rm bin/smp_tpm12_*
        fi
    fi

    cd ${MSS_PROJECTS_DIR}/common && ./clean.sh && ./build.sh $DEBUG_OPTION $TARGET_ARCH_PARAM &&
    cd ${MSS_PROJECTS_DIR}/platform && ./clean.sh && ./build.sh $DEBUG_OPTION $TARGET_ARCH_PARAM &&
    cd ${MSS_PROJECTS_DIR}/asn1 && ./clean.sh && ./build.sh --cms $DEBUG_OPTION $TARGET_ARCH_PARAM &&
    cd ${MSS_PROJECTS_DIR}/nanocap && ./clean.sh && ./build.sh $DEBUG_OPTION --suiteb $TARGET_ARCH_PARAM &&
    cd ${MSS_PROJECTS_DIR}/nanotap2_common && ./clean.sh && ./build.sh $DEBUG_OPTION $SMP_DEP_FLAG --suiteb --tap-remote $TARGET_ARCH_PARAM &&
    cd ${MSS_PROJECTS_DIR}/nanotap2_configparser && ./clean.sh &&./build.sh $DEBUG_OPTION $TARGET_ARCH_PARAM &&
    cd ${MSS_PROJECTS_DIR}/nanotap2 && ./clean.sh && ./build.sh $DEBUG_OPTION --tap-remote $SMP_DEP_FLAG $TARGET_ARCH_PARAM clientcomm &&
    cd ${MSS_PROJECTS_DIR}/nanotap2 && ./clean.sh && ./build.sh --tap-remote $DEBUG_OPTION $SMP_DEP_FLAG $TARGET_ARCH_PARAM nanotap2 &&
    cd ${MSS_PROJECTS_DIR}/crypto && ./clean.sh && ./build.sh $DEBUG_OPTION --suiteb --tap --ssl $TARGET_ARCH_PARAM &&

if [ "$DO_BUILD_TPM12" == "true" ]; then
    cd ${MSS_PROJECTS_DIR}/tpm12 && ./clean.sh && ./build.sh --suiteb $DEBUG_OPTION $TARGET_ARCH_PARAM &&
    cd ${MSS_PROJECTS_DIR}/smp_tpm12 && ./clean.sh && ./build.sh --suiteb $DEBUG_OPTION $TARGET_ARCH_PARAM
fi

if [ "$DO_BUILD_TPM2" == "true" ]; then
    cd ${MSS_PROJECTS_DIR}/tpm2 && ./clean.sh && ./build.sh --suiteb $DEBUG_OPTION $TARGET_ARCH_PARAM &&
    cd ${MSS_PROJECTS_DIR}/smp_tpm2 && ./clean.sh && ./build.sh --suiteb $DEBUG_OPTION $TARGET_ARCH_PARAM
fi
    cd ${MSS_PROJECTS_DIR}/initialize && ./clean.sh && ./build.sh $DEBUG_OPTION $TARGET_ARCH_PARAM &&
    cd ${MSS_PROJECTS_DIR}/nanocert && ./clean.sh && ./build.sh --cms $DEBUG_OPTION --suiteb --tap $TARGET_ARCH_PARAM &&
    cd ${MSS_PROJECTS_DIR}/nanossl && ./clean.sh && ./build.sh --suiteb --tap $DEBUG_OPTION $TARGET_ARCH_PARAM nanossl

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
        # Build moctap tools
        cd ${MSS_PROJECTS_DIR}/moctap_tools && ./clean.sh && ./build.sh --clean $DEBUG_OPTION --tap-remote $TARGET_ARCH_PARAM all
        MOCTAP_BUILD_STATUS=$?
        echo moctap_tools build status - ${MOCTAP_BUILD_STATUS}
        if test "${MOCTAP_BUILD_STATUS}" != "0"; then
            echo "***************************************"
            echo "**** moctap Binaries build failed  ****"
            echo "***************************************"
            exit 1
        else
            echo "*********************************************"
            echo "**** moctap Binaries built successfully  ****"
            echo "*********************************************"
        fi
    fi
done

# Build NanoTAP Server program
echo "Building nanotap_server program in $pass pass"
cd ${MSS_PROJECTS_DIR}/nanotap_server && ./clean.sh && ./build.sh $DEBUG_OPTION $SMP_DEP_FLAG --tap-remote $loopbackflag $TARGET_ARCH_PARAM
if test "$?" != "0"; then
    echo "**************************************"
    echo "**** nanotap_server build failed  ****"
    echo "**************************************"
    exit 1
else
    echo "*********************************************"
    echo "**** nanotap_server built successfully  ****"
    echo "********************************************"
fi

# Build moctpm_ tools with smp=true.
# Admin tools including moctpm_changeownerauth moctpm_takeownership and moctpm_clear are needed to provision tpm
if [ "$DO_BUILD_TPM12" == "true" ]; then
    # Build smp_tpm12_* using cmake project
    cd ${MSS_PROJECTS_DIR}/moctpm12_tools && ./clean.sh && ./build.sh --clean $DEBUG_OPTION $TARGET_ARCH_PARAM --tap-remote all &&
    if test "$?" != "0"; then
        echo "*****************************************"
        echo "**** moctpm12 Binaries build failed  ****"
        echo "*****************************************"
        exit 1
    else
        echo "************************************************"
        echo "**** moctpm12 Binaries built successfully  *****"
        echo "************************************************"
    fi
fi

if [ "$DO_BUILD_TPM2" == "true" ]; then
    # Build TAP API example
    echo "Building tap_api_example in $pass pass"
    cd ${MSS_PROJECTS_DIR}/tap_api_example && ./clean.sh && ./build.sh $DEBUG_OPTION $SMP_DEP_FLAG --tap-remote $TARGET_ARCH_PARAM all
    if test "$?" != "0"; then
        echo "***************************************"
        echo "**** tap_api_example build failed  ****"
        echo "***************************************"
        exit 1
    else
        echo "*********************************************"
        echo "**** tap_api_example built successfully  ****"
        echo "*********************************************"
    fi

    echo "Building moctpm2 tools in $pass pass"
    cd ${MSS_PROJECTS_DIR}/moctpm2_tools && ./clean.sh && ./build.sh $DEBUG_OPTION --tap-remote $TARGET_ARCH_PARAM

    if test "$?" != "0"; then
        echo "*****************************************"
        echo "**** moctpm2 Binaries build failed  *****"
        echo "*****************************************"
        exit 1
    else
        echo "***********************************************"
        echo "**** moctpm2 Binaries built successfully  *****"
        echo "***********************************************"
   fi
fi
