#!/usr/bin/env bash


######################
function show_usage
{
  echo ""
  echo "./build.sh --gdb --debug --tap --tap-extern --openssl [--scep --scep-example-client --scep-sample-client]"
  echo "           --cms --cmc --cert --data-protect --aide --pic --des --proxy --cvc"
  echo "           [--x32 | --x64] --toolchain <string> <MAKETARGETS>"
  echo ""
  echo "   --gdb             - Build a Debug version or Makefiles & Projects. (Release is default)"
  echo "   --debug           - Build with Mocana logging enabled for specific build executable."
  echo "   --pg              - Build with call stack tracing."
  echo "   --fips            - Build with FIPS enabled."
  echo "   --ipv6            - Build with IPV6 enabled."
  echo "   --libtype <static | shared> - Build a library either static type or shared type default is shared."
  echo "   --tap             - Build with TAP Mode"
  echo "   --tap-extern      - Build with TAP extern"
  echo "   --cms             - Build with CMS API."
  echo "   --cmc             - Build with CMC API. This will also enabled the CMS API."
  echo "   --cert            - Build with certificate search support."
  echo "   --data-protect    - Build with Data Protection support."
  echo "   --ocsp            - Build with OCSP APIs."
  echo "   --ocsp_cert       - Build with OCSP Certificate APIs."
  echo "   --rsa_8k          - Build with RSA 8K support."
  echo "   --minimal-ca      - Build with minimal CA APIs."
  echo "   --aide            - Build with Aide server API. It will also enable CMS and CMC API."
  echo "   --pic             - Build with position independent code enabled."
  echo "   --export          - Build the Export Edition of this library."
  echo "   --openssl         - Build the openssl shim"
  echo "   --no-cryptointerface - Build with Crypto Interface disabled."
  echo "   --toolchain <rpi32 | rpi64 | bbb | android> - Specify the toolchain to be used"
  echo "                        rpi32     For Raspberry Pi 32-bit"
  echo "                        rpi64     For Raspberry Pi 64-bit"
  echo "                        bbb       For BeagleBone Black"
  echo "                        android   For android"
  echo "   --x32             - Creates build for 32Bit machine. By default creates build for 64Bit machine."
  echo "   --x64             - Creates build for 64Bit machine. By default creates build for 64Bit machine."
  echo "   --scep            - Build the scep client binary"
  echo "   --ssh             - Build for NANOSSH"
  echo "   --scep-example-client   - Build the scep example client binary"
  echo "   --scep-sample-client    - Build the scep sample client binary"
  echo "   --est             - Build with EST support."
  echo "   --disable-strict-ca-check       - Disable strict CA check. "
  echo "   --disable_cert_ext_check - Disable certificate extension check."
  echo "   --json-verify     - Enable JSON sign and verify APIs."
  echo "   --cmake-opt       - Use this parameter to pass extra CMAKE parameters."
  echo "                        exa: --cmake-opt -D<MACRO>=<VALUE>"
  echo "   --no-pubkey-name  - Build with support for no public key name in public key blob."
  echo "   --des             - Build with single DES"
  echo "   --arc4            - Build with ARC4"
  echo "   --proxy           - Build with http proxy support"
  echo "   --cvc             - Build with cvc certificates"
  echo ""
  exit -1
}

# Place us in the dir of this script
cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null
CURR_DIR=$(pwd)

unamestr=`uname`
if [[ "$unamestr" == 'Darwin' ]]; then
    SHARED_LIB_NAME=libnanocert.dylib
else
    SHARED_LIB_NAME=libnanocert.so
fi

printf "\n\nBuilding NanoCert library.\n\n"
. clean.sh
mkdir build
cd build

is_static_lib=0
is_32bit_build=0
is_64bit_build=0

BUILD_OPTIONS=
BUILD_TYPE=Release
INV_OPT=0
ADD_ARGS=

TARGET_PLATFORM=

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
        --fips)
            echo "Building with FIPS enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_FIPS=ON -DCM_DISABLE_PQC=ON"
            ;;
        --export)
            echo "Building Export Edition library...";
            BUILD_OPTIONS+=" -DCM_ENABLE_EXPORT_ED=ON -DCM_DISABLE_PQC=ON"
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
        --toolchain)
            shift
            TARGET_PLATFORM=$(get_platform "${1}") || INV_OPT=1
            XC_BIN_PATH=$(get_sysroot_bin "${1}") || INV_OPT=1
            export PATH=${XC_BIN_PATH}:$PATH
            ;;
        --suiteb)
            echo "suiteb is enabled by default (legacy --suiteb flag ignored)...";
            ;;
        --disable-suiteb)
            echo "Building with suiteb disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_SUITEB=ON"
            ;;
        --no-cryptointerface)
            echo "Building with crypto interface disabled ...";
            BUILD_OPTIONS+=" -DCM_DISABLE_CI=ON"
            ;;
        --ipv6)
            echo "Building with IPV6 enabled ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_IPV6=ON"
            ;;
        --tap)
            echo "Building with TAP...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP=ON"
            ;;
        --tap-extern)
            echo "Building with TAP extern...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP_EXTERN=ON"
            ;;
        --cms)
            echo "Building with CMS...";
            BUILD_OPTIONS+=" -DCM_ENABLE_CMS=ON"
            ;;
        --cert)
            echo "Building with certificate search support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_CERT=ON"
            ;;
        --cert-blob-extract)
            echo "Building with certificate blob extract support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_CERT_BLOB_EXTRACT=ON"
            ;;
        --data-protect)
            echo "Building with data protect support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_DATA_PROTECT=ON"
            ;;
        --pqc)
            echo "PQC is enabled by default (legacy --pqc flag ignored)...";
            ;;
        --disable-pqc)
            echo "Building with pqc disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_PQC=ON";
            ;;
        --oqs)
            echo "PQC is enabled by default (legacy --oqs flag ignored)...";
            ;;
        --cmc)
            echo "Building with CMC...";
            BUILD_OPTIONS+=" -DCM_ENABLE_CMC=ON"
            ;;
        --ocsp)
            echo "Building with OCSP...";
            BUILD_OPTIONS+=" -DCM_ENABLE_OCSP=ON"
            ;;
        --ocsp_cert)
            echo "Building with OCSP...";
            BUILD_OPTIONS+=" -DCM_ENABLE_OCSP_CERT=ON"
            ;;
        --rsa_8k)
            echo "Building with RSA 8K support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_RSA_8K=ON"
            ;;
        --minimal-ca)
            echo "Building with minimal CA APIs...";
            BUILD_OPTIONS+=" -DCM_ENABLE_MINIMAL_CA=ON"
            ;;
        --aide)
            echo "Building with aide...";
            BUILD_OPTIONS+=" -DCM_ENABLE_AIDE=ON -DCM_ENABLE_CMS=ON -DCM_ENABLE_CMC=ON"
            ;;
        --openssl)
            echo "Building with openssl_shim...";
            BUILD_OPTIONS+=" -DCM_ENABLE_OPENSSL_SHIM=ON"
            ;;
        --scep)
            echo "Building SCEP ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SCEP=ON"
            ;;
        --ssh)
            echo "Building for SSH";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSH=ON"
            ;;
        --scep-example-client)
            echo "Building SCEP Example Client...";
            BUILD_OPTIONS+=" -DCM_BUILD_SCEP_EXAMPLE_CLIENT=ON"
            ;;
        --scep-sample-client)
            echo "Building SCEP Sample Client...";
            BUILD_OPTIONS+=" -DCM_BUILD_SCEP_SAMPLE_CLIENT=ON"
            ;;
        --est)
            echo "Building with EST support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_EST=ON"
            ;;
        --mbed)
            ;;
        --mbed-path)
            shift
            ;;
        --pic)
            echo "Building with position independent code enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_COMPOUND_LIB=ON";
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
        --disable-strict-ca-check)
            BUILD_OPTIONS+=" -DCM_DISABLE_STRICT_CA_CHECK=ON"
            echo "Disable strict CA check...";
            ;;
        --disable_cert_ext_check)
            echo "Disable certificate extension check..."
            BUILD_OPTIONS+=" -DCM_DISABLE_CERT_EXT_CHECK=ON"
            ;;
        --disable-rsa)
            echo "Building with RSA disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_RSA=ON"
            ;;
        --disable-dsa)
            echo "Building with DSA disabled..."
            BUILD_OPTIONS+=" -DCM_DISABLE_DSA=ON"
            ;;
        --disable-tdes)
            echo "Building with TDES disabled..."
            BUILD_OPTIONS+=" -DCM_DISABLE_TDES=ON"
            ;;
        --json-verify)
            BUILD_OPTIONS+=" -DCM_ENABLE_JSON_VERIFY=ON"
            echo "Enable JSON sign and verify APIs...";
            ;;
        --status-log)
            BUILD_OPTIONS+=" -DCM_ENABLE_STATUS_LOG=ON"
            echo "Building with status logging...";
            ;;
        --cmake-opt)
            shift
            echo "Setting extra flags for cmake execution...";
            BUILD_OPTIONS+=" ${1}"
            ;;
        --no-pubkey-name)
            echo "Build with support for no public key name in public key blob.";
            BUILD_OPTIONS+=" -DCM_BUILD_MOCANA_NO_PUBKEY_NAME=ON";
            ;;
        --des)
            echo "Build with DES"
            BUILD_OPTIONS+=" -DCM_ENABLE_DES=ON"
            ;;
        --arc4)
            echo "Build with ARC4"
            BUILD_OPTIONS+=" -DCM_ENABLE_ARC4=ON"
            ;;
        --disable-http)
            echo "Building with HTTP disabled"
            BUILD_OPTIONS+=" -DCM_DISABLE_HTTP=ON"
            ;;
        --proxy)
            echo "Build with http proxy support"
            BUILD_OPTIONS+=" -DCM_ENABLE_PROXY=ON"
            ;;
        --cvc)
            echo "Build with cv certificate support"
            BUILD_OPTIONS+=" -DCM_ENABLE_CVC=ON"
            ;;
        --enable-pc)
            echo "Build with Certificate/CSR printing enabled"
            BUILD_OPTIONS+=" -DCM_ENABLE_CERT_PRINT=ON"
            ;;
        --scram)
            echo "Build with SCRAM client support"
            BUILD_OPTIONS+=" -DCM_ENABLE_SCRAM_CLIENT=ON"
            ;;
        --build-for-osi)
            echo "Enabling BUILD_FOR_OSI...";
            BUILD_OPTIONS+=" -DBUILD_FOR_OSI=ON"
            ;;
        -h|--help|--h)
            INV_OPT=1
            ;;
        --*)
            echo "Invalid option: $1";
            INV_OPT=1
            ;;
        *)
            echo "Argument: $1";
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

if [ $is_32bit_build -eq 1 -a $is_64bit_build -eq 1 ]; then
   echo "Error: Both the flags --x32 and --x64 should not be enabled. Either one of the flags --x32 or --x64 should be enabled."
   exit 1
fi

echo ""
echo "Calling: cmake ${TARGET_PLATFORM} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
      ${BUILD_OPTIONS} CMakeLists.txt ../."
echo ""

cmake ${TARGET_PLATFORM} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} \
      ${ADD_ARGS} CMakeLists.txt ../.

make -j$(getconf _NPROCESSORS_ONLN)

printf "\nCopying library to bin...\n"
if [ $is_static_lib -eq 0 ]; then
    cp libs/${SHARED_LIB_NAME} ../../../bin/
else
    cp libs/libnanocert.a ../../../bin_static/
fi
