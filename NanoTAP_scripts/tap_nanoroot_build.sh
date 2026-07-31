#!/usr/bin/env bash

######################
function show_usage
{
  echo ""
  echo "./build.sh [Options] "
  echo ""
  echo "   --gdb             - Build Debug version."
  echo "   --debug           - Build with Digicert logging enabled for specific build executable."
  echo "   --help            - Show Usage"
  echo "   --x32              - Creates build for 32Bit machine. By default creates build for 64Bit machine."
  echo "   --x64              - Creates build for 64Bit machine. By default creates build for 64Bit machine."
  echo "   --toolchain <toolchain> - Cross compile build using the specified toolchain. This toolchain"
  echo "                             must have the appropriate handling in MocPlatform.cmake"
  echo ""
  exit 1
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

if [ -n "${BUILD_OPTIONS}" ]; then
  echo "BUILD_OPTIONS=${BUILD_OPTIONS}"
  echo ""
fi

######################

SCRIPT_DIR=$( cd $(dirname $0) ; pwd -P )
export WORKSPACE="${SCRIPT_DIR}/.."
echo "WORKSPACE=${WORKSPACE}"
export MSS_DIR=${WORKSPACE}
export MSS_PROJECTS_DIR=${MSS_DIR}/projects

echo "***************************************************************"
echo "*** Building tap_nanoroot_example ..."
echo "***************************************************************"

for pass in first second
do
    if [ "$pass" == "first" ]; then
        echo "***************************************************************"
        echo "*** Cleaning binaries and libraries "
        echo "***************************************************************"

        rm bin/*.so
        rm bin/*.a
        rm bin/tap_api_example
        rm bin/tap_nanoroot_example
    fi

    cd ${MSS_PROJECTS_DIR}/common && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM &&
    cd ${MSS_PROJECTS_DIR}/platform && ./clean.sh && ./build.sh $BUILD_OPTIONS --process $TARGET_ARCH_PARAM &&
    cd ${MSS_PROJECTS_DIR}/asn1 && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM &&
    cd ${MSS_PROJECTS_DIR}/nanocap && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM --suiteb &&
    cd ${MSS_PROJECTS_DIR}/nanotap2_common && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM --suiteb --nanoroot &&
    cd ${MSS_PROJECTS_DIR}/nanotap2_configparser && ./clean.sh && ./build.sh &&
    cd ${MSS_PROJECTS_DIR}/nanotap2 && ./clean.sh && ./build.sh --tap-local $BUILD_OPTIONS $TARGET_ARCH_PARAM --nanoroot nanotap2 &&
    cd ${MSS_PROJECTS_DIR}/crypto && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM --suiteb --tap --rsa_8k &&
    cd ${MSS_PROJECTS_DIR}/initialize && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM &&
    cd ${MSS_PROJECTS_DIR}/nanocert && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM --suiteb --tap
    cd ${MSS_PROJECTS_DIR}/smp_nanoroot && ./clean.sh && ./build.sh $BUILD_OPTIONS $TARGET_ARCH_PARAM
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
        cd ${MSS_PROJECTS_DIR}/tap_api_example && ./clean.sh && ./build.sh --clean $BUILD_OPTIONS $TARGET_ARCH_PARAM --nanoroot all
        cd ${MSS_PROJECTS_DIR}/tap_nanoroot_example && ./clean.sh && ./build.sh --clean $BUILD_OPTIONS $TARGET_ARCH_PARAM all

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

