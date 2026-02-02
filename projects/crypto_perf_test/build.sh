#!/usr/bin/env bash

###
# Usage: ./build.sh
#
##
function show_usage
{
echo ""
echo "./build.sh <--ni> <--openssl> <--mbedtls> <--x32>"
echo ""
echo " --ni       Build AES tests with NI"
echo " --cryptointerface Build with Crypto Interface enabled"
echo " --openssl  Build with openssl timing tests"
echo " --mbedtls  Build with mbedtls timing tests"
echo " --oqs      Adds oqs tests"
echo " --oqs-path Argument for path to OQS Library. Must be followed by the path."
echo " --wolfssl  Build only wolfssl tests."
echo " --liboqs   Build only direct liboqs tests."
echo " --x32      Build for 32-bit platform, adds -O1 option"
echo "--toolchain <rpi64|rpi32|qnx-x86> - Specify the toolchain to be used"
echo "                          rpi64     For Raspberry Pi 64-bit"
echo "                          rpi32     For Raspberry Pi 32-bit"
echo ""
}

BUILD_OPTIONS=
INV_OPT=0
OQS_PATH=0
WOLF_BUILD=0
LIBOQS_BUILD=0

# Default to x64 unless toolchain is provided
X64=" --x64"
TARGET_PLATFORM=
XC_BIN_PATH=
TOOLCHAIN=

source ../shared_cmake/get_toolchain.sh

while test $# -gt 0
do
    case "$1" in
        --ni)
            echo "Enabling AES NI...";
            BUILD_OPTIONS+=" -DCM_ENABLE_AES_NI=ON"
            ;;
        --cryptointerface)
            echo "Enabling Crypto Interface...";
            BUILD_OPTIONS+=" -DCM_ENABLE_CI=ON"
            ;;
        --openssl)
            echo "Enabling openssl tests...";
            BUILD_OPTIONS+=" -DCMAKE_BUILD_OPENSSL=ON"
            ;;
        --mbedtls)
            echo "Enabling mbedtls tests...";
            BUILD_OPTIONS+=" -DCMAKE_BUILD_MBEDTLS=ON"
            ;;
        --oqs)
            echo "-- Building with oqs enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_OQS=ON";
            ;;
        --oqs-path)
            OQS_PATH=$2; BUILD_OPTIONS+=" -DCM_OQS_PATH=$OQS_PATH";
            shift
            ;;
        --wolfssl)
            echo "-- Building wolfssl tests...";
            BUILD_OPTIONS+=" -DCM_ENABLE_WOLF=ON";
            WOLF_BUILD=1
            ;;
        --liboqs)
            echo "-- Building direct liboqs tests...";
            BUILD_OPTIONS+=" -DCM_ENABLE_LIBOQS=ON";
            LIBOQS_BUILD=1
            ;;
        --toolchain)
            X64=""
            TOOLCHAIN=" --toolchain ${2}"
            BUILD_OPTIONS+=" -DCM_TOOLCHAIN=${2}"
            TARGET_PLATFORM=$(get_platform "${2}") || INV_OPT=1
            XC_BIN_PATH=$(get_sysroot_bin "${2}") || INV_OPT=1
            export PATH=${XC_BIN_PATH}:$PATH
            shift
            ;;
        --x32)
            echo "Enabling 32-bit build...";
            BUILD_OPTIONS+=" -DCMAKE_BUILD_32BIT=ON"
            ;;
        --*)
            echo "Invalid option: $1";
            INV_OPT=1
            ;;
    esac
    shift
done

if [ ${INV_OPT} -eq 1 ]; then
  show_usage
fi

echo "Building Crypto Performance Test project."

if [ ${WOLF_BUILD} -eq 1 ]; then
  echo "Checking out wolfssl"
  if cd wolfssl 2> /dev/null; then
    git fetch --tags --prune; else
    git clone https://github.com/wolfSSL/wolfssl wolfssl;
    cd wolfssl
  fi
  echo "Building wolfssl"
  git checkout $(git tag -l "v*" --sort -version:refname | head -n 1)
  ./autogen.sh
  ./configure --enable-experimental --enable-dilithium --enable-kyber --enable-static --disable-dh --enable-debug --disable-sys-ca-certs --enable-asm
  make -j8
  cd ..
fi

if [ ${LIBOQS_BUILD} -eq 1 ]; then
  echo "Checking out liboqs"
  if cd liboqs 2> /dev/null; then
    git fetch --tags --prune; else
    git clone https://github.com/open-quantum-safe/liboqs.git;
    cd liboqs
  fi
  echo "Building liboqs"
  git checkout $(git tag -l "[0-9]*" --sort=creatordate | tail -n 1)
  rm -rf build
  mkdir build
  cd build
  cmake -GNinja -DBUILD_SHARED_LIBS=OFF -DOQS_USE_OPENSSL=OFF ..
  ninja
  cd ../..
fi

if [ ! -z "${BUILD_OPTIONS}" ]; then
  echo "BUILD_OPTIONS=${BUILD_OPTIONS}"
fi

. clean.sh

echo "BUILD_OPTIONS=${BUILD_OPTIONS}"
echo "TARGET_PLATFORM=${TARGET_PLATFORM}"

cmake ${TARGET_PLATFORM} -DCMAKE_BUILD_TYPE=Release ${BUILD_OPTIONS} CMakeLists.txt

echo "Calling: make all"
make -j$(getconf _NPROCESSORS_ONLN) all
