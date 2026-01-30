#!/usr/bin/env bash

###
# Usage: ./build.sh
#
##
function show_usage
{
echo ""
echo "./build.sh"
echo ""
echo " --no-bssl-build   Don't checkout and rebuild boringssl"
echo " --no-wolf-build   Don't checkout and rebuild wolfssl"
echo " --x32             Build for 32-bit platform, adds -O1 option"
echo ""
}

BUILD_OPTIONS=
INV_OPT=0
WOLF_BUILD=1
BSSL_BUILD=1

while test $# -gt 0
do
    case "$1" in
        --no-wolf-build)
            WOLF_BUILD=0
            ;;
        --no-bssl-build)
            BSSL_BUILD=0
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

if [ ${BSSL_BUILD} -eq 1 ]; then
  echo "Checking out boringssl"
  if cd boringssl 2> /dev/null; then
    git pull; else
    git clone https://boringssl.googlesource.com/boringssl boringssl;
    cd boringssl
  fi
  echo "Building boringssl"
  cmake -GNinja -B build
  ninja -C build
  cd ..
fi

if [ ${WOLF_BUILD} -eq 1 ]; then
  echo "Checking out wolfssl"
  if cd wolfssl 2> /dev/null; then
    git pull; else
    git clone https://github.com/wolfSSL/wolfssl wolfssl;
    cd wolfssl
  fi
  echo "Building wolfssl"
  ./autogen.sh
  ./configure --enable-experimental --enable-dilithium --enable-kyber --enable-static --disable-dh --enable-debug
  make
  cd ..
fi

echo "Building Crypto Interopability Test project."

if [ ! -z "${BUILD_OPTIONS}" ]; then
  echo "BUILD_OPTIONS=${BUILD_OPTIONS}"
fi

cmake -DCMAKE_BUILD_TYPE=Debug ${BUILD_OPTIONS} CMakeLists.txt -GNinja
ninja clean
ninja
