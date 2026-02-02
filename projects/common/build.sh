#!/usr/bin/env bash


######################
function show_usage
{
  echo ""
  echo "./build.sh --gdb --debug --suiteb --libtype <static | shared> "
  echo "           [--x32 | --x64] --mpart --json --uri --toolchain <string> --platform <string> <MAKETARGETS>"
  echo ""
  echo "   --help            - Build options information"
  echo "   --gdb             - Build a Debug version or Makefiles & Projects. (Release is default)"
  echo "   --pg              - Build with call stack tracing."
  echo "   --debug           - Build with Mocana logging enabled for specific build executable."
  echo "   --fips            - Build with FIPS enabled."
  echo "   --no-mstdlib      - Build with Mocana standard library APIs disabled."
  echo "   --ipv6            - Build with IPV6 enabled."
  echo "   --uri             - Build with URI enabled."
  echo "   --mpart           - Build with memory partition enabled."
  echo "   --mpart-tpla      - Build with memory partition enabled and configured for TPLA."
  echo "   --mem-profile     - Build with memory profiling capability"
  echo "   --no-malloc-limit - Build without any restriction for the malloc size."
  echo "   --data-protect    - Build with Data Protection (dynamic loading) enabled."
  echo "   --dynamic-load    - Build with dynamic library loading."
  echo "   --no-cryptointerface - Build with Crypto Interface disabled."
  echo "   --disable-error-code-lookup - Build with error code lookup disabled."
  echo "   --vlong-const     - Build with constant time vlong ops."
  echo "   --msg-logger      - Build with message logger."
  echo "   --msg-timestamp   - Enable timestamps with message logger."
  echo "   --protobuf        - Build with protobuf APIs."
  echo "   --mime-parser     - Build with MIME parser APIs."
  echo "   --libtype <static | shared> - Build a library either static type or shared type default is shared."
  echo "   --toolchain <rpi32 | rpi64 | bbb | android> - Specify the toolchain to be used"
  echo "                        rpi32     For Raspberry Pi 32-bit"
  echo "                        rpi64     For Raspberry Pi 64-bit"
  echo "                        bbb       For BeagleBone Black"
  echo "                        android   For android"
  echo "   --x32             - Creates build for 32Bit machine. By default creates build for 64Bit machine."
  echo "   --x64             - Creates build for 64Bit machine. By default creates build for 64Bit machine."
  echo "   --json            - Enable JSON parsing APIs"
  echo "   --build-info      - Capture build information"
  echo "   --arg-parser      - Compile APIs used for argument parsing"
  echo "   --common-utils    - Build with common_utils code"
  echo "   --version-string  - Semantic version string for build"
  echo "   --cmake-opt       - Use this parameter to pass extra CMAKE parameters."
  echo "                        exa: --cmake-opt -D<MACRO>=<VALUE>"
  echo "   <MAKETARGETS>     - Make targets to build. ('all' is default)"
  echo ""
  exit -1
}

# Place us in the dir of this script
cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null
CURR_DIR=$(pwd)

unamestr=`uname`
printf "\n\nBuilding common library.\n\n\n"

if [[ "$unamestr" == 'Darwin' ]]; then
    SHARED_LIB_NAME=libcommon.dylib
else
    SHARED_LIB_NAME=libcommon.so
fi

echo "Calling: clean.sh..."
. clean.sh
mkdir build
cd build
is_static_lib=0
is_32bit_build=0
is_64bit_build=0

BUILD_OPTIONS=
BUILD_TYPE=Release
BUILD_TGT=
ADD_ARGS=
INV_OPT=0
TARGET_PLATFORM=
VERSION_STRING=""
SECURE_PATH_VAR=""

source $CURR_DIR/../shared_cmake/get_toolchain.sh

while test $# -gt 0
do
    case "$1" in
        --help)
            INV_OPT=1
            ;;
        --gdb)
            echo "Enabling Debug build...";
            BUILD_TYPE="Debug";
            BUILD_OPTIONS+=" -DCMAKE_BUILD_TYPE=Debug"
            ;;
        --pg)
            echo "Enabling callstack tracing build...";
            BUILD_OPTIONS+=" -DCM_ENABLE_PG=ON"
            ;;
        --debug)
            echo "Building with Debug logs enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_DEBUG=ON"
            ;;
        --libtype)
            case "$2" in
                static)
                    is_static_lib=1;
		            echo "Building static library...";
                    BUILD_OPTIONS+=" -DLIB_TYPE:STRING=STATIC"
                    ;;
                shared)
                    echo "Building shared library...";
                    BUILD_OPTIONS+=" -DLIB_TYPE:STRING=SHARED"
                    ;;
                *)
                    echo "Error reading libtype $2";
                    BUILD_OPTIONS+=" -DLIB_TYPE:STRING=SHARED"
                    ;;
            esac
            shift
            ;;
        --fips)
            echo "Building with FIPS enabled ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_FIPS=ON"
            ;;
        --no-mstdlib)
            echo "Building with  mstdlib disabled ...";
            BUILD_OPTIONS+=" -DCM_DISABLE_MSTDLIB=ON"
            ;;
        --ipv6)
            echo "Building with IPV6 enabled ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_IPV6=ON"
            ;;
        --uri)
            echo "Building URI ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_URI=ON"
            ;;
        --mpart)
            echo "Building with __ENABLE_DIGICERT_MEM_PART__ enabled ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_MPART=ON"
            ;;
        --mpart-tpla)
            echo "Building with tpla memory partitioning enabled ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_MPART_TPLA=ON"
            ;;
        --mem-profile)
            echo "Building with memory profiling enabled ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_MEM_PROFILE=ON"
            ;;
        --no-cryptointerface)
            echo "Building with crypto interface disabled ...";
            BUILD_OPTIONS+=" -DCM_DISABLE_CI=ON"
            ;;
        --disable-error-code-lookup)
            echo "Building with error code lookup disabled..."
            BUILD_OPTIONS+=" -DCM_DISABLE_ERROR_CODE_LOOKUP=ON"
            ;;
        --no-malloc-limit)
            echo "Building with malloc limit disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_MALLOC_LIMIT=ON"
            ;;
        --json)
            echo "Building JSON...";
            BUILD_OPTIONS+=" -DCM_ENABLE_JSON=ON"
            ;;
        --toolchain)
            shift
            TARGET_PLATFORM=$(get_platform "${1}") || INV_OPT=1
            XC_BIN_PATH=$(get_sysroot_bin "${1}") || INV_OPT=1
            export PATH=${XC_BIN_PATH}:$PATH
            ;;
        --dynamic-load)
            BUILD_OPTIONS+=" -DCM_ENABLE_DYNAMIC_LOAD=ON"
            echo "Building with dynamic loading enabled...";
            ;;
        --data-protect)
            BUILD_OPTIONS+=" -DCM_ENABLE_DYNAMIC_LOAD=ON -DCM_ENABLE_DATA_PROTECT=ON"
            echo "Building with data protect (dynamic loading) enabled...";
            ;;
        --mbed)
            ;;
        --mbed-path)
            shift
            ;;
        --suiteb)
            ;;
        --build-info)
            BUILD_OPTIONS+=" -DCM_ENABLE_BUILD_INFO=ON"
            echo "Building with build info enabled..."
            ;;
        --arg-parser)
            BUILD_OPTIONS+=" -DCM_ENABLE_ARG_PARSER=ON"
            echo "Building with build info enabled..."
            ;;
        --absolute-path)
            echo "Building with absolute path enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_ABSOLUTE_PATH=ON"
            ;;
        --enable-posix)
            echo "Building with posix support enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_POSIX_SUPPORT=ON"
            ;;
        --secure-path)
            echo "Building with secure path enabled..."
            SECURE_PATH_VAR="-DSECURE_PATH=\"${2}\""
            shift
            ;;
        --msg-logger)
            BUILD_OPTIONS+=" -DCM_ENABLE_MSG_LOG=ON"
            echo "Building with message logger enabled..."
            ;;
        --msg-timestamp)
            BUILD_OPTIONS+=" -DCM_ENABLE_MSG_LOG_TIMESTAMP=ON"
            echo "Enable timestamps with message logger..."
            ;;
        --protobuf)
            BUILD_OPTIONS+=" -DCM_ENABLE_PROTOBUF=ON"
            echo "Building with Protobuf APIs..."
            ;;
        --mime-parser)
            BUILD_OPTIONS+=" -DCM_ENABLE_MIME_PARSER=ON"
            echo "Building with mime parser APIs..."
            ;;
        --common-utils)
            BUILD_OPTIONS+=" -DCM_ENABLE_COMMON_UTILS=ON"
            echo "Building with common utils enabled..."
            ;;
        --vlong-const)
            BUILD_OPTIONS+=" -DCM_ENABLE_VLONG_CONST=ON"
            echo "Building with constant time vlong operations enabled";
            ;;
        --x32)
            is_32bit_build=1;
            BUILD_OPTIONS+=" -DCM_BUILD_X32=ON"
            echo "Building for x32 machine...";
            ;;
        --x64)
            is_64bit_build=1;
            BUILD_OPTIONS+=" -DCM_BUILD_X64=ON"
            echo "Building for x64 machine...";
            ;;
        --version-string)
            shift
            VERSION_STRING="${1}"
            ;;
        --cmake-opt)
            shift
            echo "Setting extra flags for cmake execution...";
            BUILD_OPTIONS+=" ${1}"
            ;;
        --build-for-osi)
            echo "Enabling BUILD_FOR_OSI...";
            BUILD_OPTIONS+=" -DBUILD_FOR_OSI=ON"
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

# Check if building for OSI
source $CURR_DIR/../../scripts/check_for_osi.sh
if [ ${OSI_BUILD} -eq 1 ]; then
    BUILD_OPTIONS+=" -DBUILD_FOR_OSI=ON"
fi

if [ ${INV_OPT} -eq 1 ]; then
  show_usage
fi

if [ ! -z "${BUILD_OPTIONS}" ]; then
  echo "BUILD_OPTIONS=${BUILD_OPTIONS}"
fi

if [ ! -z "${ADD_ARGS}" ]; then
  BUILD_TGT=${ADD_ARGS}
  echo "BUILD_TGT=${BUILD_TGT}"
else
  BUILD_TGT=all
fi

if [ $is_32bit_build -eq 1 -a $is_64bit_build -eq 1 ]; then
   echo "Error: Both the flags --x32 and --x64 should not be enabled. Either one of the flags --x32 or --x64 should be enabled."
   exit 1
fi

echo ""
echo "Calling: cmake ${TARGET_PLATFORM}
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
      ${BUILD_OPTIONS} CMakeLists.txt ../."
echo ""
if [ -z "${VERSION_STRING}" ]; then
cmake ${TARGET_PLATFORM} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} ${SECURE_PATH_VAR} \
      CMakeLists.txt ../.
else
cmake ${TARGET_PLATFORM} -DCM_VERSION_STRING=${VERSION_STRING} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} ${SECURE_PATH_VAR} \
      CMakeLists.txt ../.
fi


echo "Calling: make ${BUILD_TGT}"
make ${BUILD_TGT}

echo "Copying library to bin..."
if [ $is_static_lib -eq 0 ]; then
    cp libs/${SHARED_LIB_NAME} ../../../bin/
else
    cp libcommon.a ../../../bin_static/
fi
