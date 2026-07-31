#!/usr/bin/env bash

######################
function show_usage
{
  echo ""
  echo "./build.sh --mbed_path <path_to_libraries> [Options] "
  echo ""
  echo "   --gdb             - Build Debug version."
  echo "   --debug           - Build with Digicert logging enabled for specific build executable."
  echo "   --help            - Show Usage"
  echo "   --x32              - Creates build for 32Bit machine. By default creates build for 64Bit machine."
  echo "   --x64              - Creates build for 64Bit machine. By default creates build for 64Bit machine."
  echo "   --toolchain <toolchain> - Cross compile build using the specified toolchain. This toolchain"
  echo "                             must have the appropriate handling in MocPlatform.cmake"
  echo ""
  exit -1
}

BUILD_OPTIONS=""
IS_32_BIT_BUILD=false
IS_64_BIT_BUILD=false
TARGET_ARCH_PARAM=--x64
TOOLCHAIN=""
INV_OPT=0

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


echo "***************************************************************"
echo "*** Building local version of moctpm2 tools..."
echo "***************************************************************"

for pass in first second
do
    if [ "$pass" == "first" ]; then
        echo "***************************************************************"
        echo "*** Cleaning binaries and libraries "
        echo "***************************************************************"

        rm ${LIB_DIR}/*.so
        rm ${LIB_DIR}/*.a
        rm bin/digicert_tpm2_*
        rm bin/tap_api_example
        rm bin/smp_tpm2_getidstr_bin
    fi

    cd ${MSS_PROJECTS_DIR}/common && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM &&
    cd ${MSS_PROJECTS_DIR}/platform && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM &&
    cd ${MSS_PROJECTS_DIR}/asn1 && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM &&
    cd ${MSS_PROJECTS_DIR}/nanocap && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM --suiteb &&
    cd ${MSS_PROJECTS_DIR}/nanotap2_common && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM --suiteb --tpm2 --tap-local &&
    cd ${MSS_PROJECTS_DIR}/nanotap2_configparser && ./clean.sh &&./build.sh &&
    cd ${MSS_PROJECTS_DIR}/nanotap2 && ./clean.sh && ./build.sh --tap-local $BUILD_OPTIONS $TARGET_ARCH_PARAM --tpm2 nanotap2 &&
    cd ${MSS_PROJECTS_DIR}/crypto && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM --suiteb --tap --tpm2 &&
    cd ${MSS_PROJECTS_DIR}/tpm2 && ./clean.sh && ./build.sh --suiteb $BUILD_OPTIONS $TARGET_ARCH_PARAM &&
    cd ${MSS_PROJECTS_DIR}/smp_tpm2 && ./clean.sh && ./build.sh --suiteb $BUILD_OPTIONS $TARGET_ARCH_PARAM &&
    cd ${MSS_PROJECTS_DIR}/initialize && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM &&
    cd ${MSS_PROJECTS_DIR}/nanocert && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM --suiteb --tap
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
        cd ${MSS_PROJECTS_DIR}/moctpm2_tools && ./clean.sh && ./build.sh --clean $BUILD_OPTIONS $TARGET_ARCH_PARAM --tap-local all &&
        cd ${MSS_PROJECTS_DIR}/tap_api_example && ./clean.sh && ./build.sh --clean $BUILD_OPTIONS $TARGET_ARCH_PARAM --tap-local --tpm2 all

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

