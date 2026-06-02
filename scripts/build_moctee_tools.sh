#!/usr/bin/env bash

SCRIPT_DIR=$( cd $(dirname $0) ; pwd -P )
export WORKSPACE="${SCRIPT_DIR}/.."
echo "WORKSPACE=${WORKSPACE}"
export MSS_DIR=${WORKSPACE}
export MSS_PROJECTS_DIR=${MSS_DIR}/projects

TEE_PATH=
BUILD_OPTIONS=
INV_OPT=0
TAP_ARG=" --tap-local"
LIB_DIR=bin

function show_usage
{
  echo ""
  echo "Usage: $0 [--tee-path] [--tap-remote] [--toolchain <rpi32 | rpi64 | bbb | android>]"
  echo ""
  echo ""
  echo "   --tee-path       Just put the path to the folder containing libteec.so"
  echo "   --tap-remote     Build with TAP REMOTE rather than the default of TAP LOCAL"
  echo ""
  echo "   --toolchain <rpi32 | rpi64 | bbb | android> - Specify the toolchain to be used"
  echo "                        rpi32     For Raspberry Pi 32-bit"
  echo "                        rpi64     For Raspberry Pi 64-bit"
  echo "                        bbb       For BeagleBone Black"
  echo "                        android   For android"
  exit 255
}

function get_tee_lib {

    echo "Copying TEE library(s) from ${TEE_PATH}"
    cp "${TEE_PATH}/libteec.so" ${WORKSPACE}/${LIB_DIR}/
}

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
            ;;
        --tee-path)
            TEE_PATH="$2"
            ;;
        --tap-remote)
            echo "Building with TAP remote"
            TAP_ARG=" --tap-remote"
            ;;
        --toolchain)
            echo "Cross-compiling for $2"
            BUILD_OPTIONS+=" $1 $2"
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

# Check if building for OSI
source ${MSS_DIR}/scripts/check_for_osi.sh
if [ ${OSI_BUILD} -eq 1 ]; then
    LIB_DIR="lib"
fi

echo "***************************************************************"
echo "*** Building moctee tools..."
echo "***************************************************************"

for pass in first second
do
    if [ "$pass" == "first" ]; then
        echo "***************************************************************"
        echo "*** Cleaning binaries and libraries "
        echo "***************************************************************"

        rm ${WORKSPACE}/bin/moctee_getpolicystorage
        rm ${WORKSPACE}/bin/moctee_setpolicystorage
        rm ${WORKSPACE}/bin/moctee_delpolicystorage
        rm ${WORKSPACE}/${LIB_DIR}/*.so

        if [ ! -z "${TEE_PATH}" ]; then
           get_tee_lib
        fi
    fi
    
    if [ "${TAP_ARG}" == " --tap-local" ]; then
        cd ${MSS_PROJECTS_DIR}/platform && ./clean.sh && ./build.sh --gdb --debug $BUILD_OPTIONS &&
        cd ${MSS_PROJECTS_DIR}/common && ./clean.sh && ./build.sh --gdb --debug $BUILD_OPTIONS &&
        cd ${MSS_PROJECTS_DIR}/nanotap2_common && ./clean.sh && ./build.sh --debug --gdb $BUILD_OPTIONS --disable-suiteb --tee --tap-min --tap-local &&
        cd ${MSS_PROJECTS_DIR}/nanotap2 && ./clean.sh && ./build.sh --tap-local --debug --gdb $BUILD_OPTIONS --tee --tap-min nanotap2 &&
        cd ${MSS_PROJECTS_DIR}/smp_tee && ./clean.sh && ./build.sh --debug --gdb $BUILD_OPTIONS --tee
    else
        cd ${MSS_PROJECTS_DIR}/platform && ./build.sh --gdb --debug $BUILD_OPTIONS &&
        cd ${MSS_PROJECTS_DIR}/common && ./build.sh --gdb $BUILD_OPTIONS --debug --json --uri --cmake-opt "-DCM_TAP_TYPE=REMOTE" &&
        cd ${MSS_PROJECTS_DIR}/asn1 && ./build.sh --gdb --debug $BUILD_OPTIONS --cms &&
        cd ${MSS_PROJECTS_DIR}/nanocap && ./build.sh --gdb --debug $BUILD_OPTIONS --suiteb && 
        cd ${MSS_PROJECTS_DIR}/nanotap2_common && ./build.sh --debug --gdb $BUILD_OPTIONS --suiteb --tap-remote --tee && 
        cd ${MSS_PROJECTS_DIR}/nanotap2_configparser && ./build.sh --gdb --debug $BUILD_OPTIONS &&
        cd ${MSS_PROJECTS_DIR}/nanotap2 && ./build.sh --tap-remote --debug --gdb $BUILD_OPTIONS --tcp-close-msg clientcomm &&
        cd ${MSS_PROJECTS_DIR}/nanotap2 && ./build.sh --tap-remote  --debug --gdb $BUILD_OPTIONS --tee nanotap2 &&
        cd ${MSS_PROJECTS_DIR}/crypto && ./build.sh --gdb --debug $BUILD_OPTIONS --suiteb --tap --ssl --tap-hybrid-sign &&
        cd ${MSS_PROJECTS_DIR}/smp_tee && ./clean.sh && ./build.sh --debug --gdb $BUILD_OPTIONS --tee &&
        cd ${MSS_PROJECTS_DIR}/initialize && ./build.sh --debug --gdb $BUILD_OPTIONS ${DATA_PROTECT_ARG} ${TAP_DATA_PROTECT_ARG} &&
        cd ${MSS_PROJECTS_DIR}/nanocert && ./build.sh --gdb --suiteb --debug $BUILD_OPTIONS --ocsp --tap --cms --cmc --json-verify --cert &&
        cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh --clean --gdb --suiteb --debug $BUILD_OPTIONS  --tap --tap-remote --ocsp nanossl --mauth
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

    if [ "$pass" == "second" ]; then
        # Build binaries only on the second pass
        cd ${MSS_PROJECTS_DIR}/moctee_tools && ./clean.sh && ./build.sh --gdb --debug ${TAP_ARG} $BUILD_OPTIONS &&

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

