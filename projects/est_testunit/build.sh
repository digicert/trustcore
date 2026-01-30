#!/usr/bin/env bash

######################
function show_usage
{
    echo ""
    echo "./build.sh"
    echo ""
    echo "   --help            - Display help menu"
    echo "   --gdb             - Build with debug symbols"
    echo "   --enable-coverage  - Build with gcov code coverage support"
    echo ""
    exit -1
}

# Place us in the dir of this script
cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null
CURR_DIR=$(pwd)

MSS_DIR="${CURR_DIR}/../.."

if [ ! -f "${MSS_DIR}/bin_static/libcmocka-static.a" ]; then
    echo "*************************************************************************"
    echo "*** CMocka not found. Building CMocka library..."
    echo "*************************************************************************"

    if [ ! -d "${MSS_DIR}/cmocka-1.1.5" ]; then
        echo "Error: cmocka-1.1.5 source not found in ${MSS_DIR}"
        echo "Please download cmocka-1.1.5.tar.xz and extract it to the workspace root"
        echo "Or run: wget https://cmocka.org/files/1.1/cmocka-1.1.5.tar.xz && tar -xf cmocka-1.1.5.tar.xz"
        exit 1
    fi

    cd ${MSS_DIR}/cmocka-1.1.5
    mkdir -p build
    cd build
    cmake -D WITH_STATIC_LIB=ON ..
    make
    cp ${MSS_DIR}/cmocka-1.1.5/build/src/libcmocka-static.a ${MSS_DIR}/bin_static/
    cd ../..

    if [ ! -d "${MSS_DIR}/thirdparty/cmocka-1.1.5" ]; then
        cp -r ${MSS_DIR}/cmocka-1.1.5 ${MSS_DIR}/thirdparty/
    fi

    echo "CMocka build complete."
    cd ${CURR_DIR}
fi

rm -rf build
mkdir build

cd build

BUILD_OPTIONS=
BUILD_TYPE=Release
BUILD_TGT=all
INV_OPT=0

while test $# -gt 0
do
    case "$1" in
        --help)
            INV_OPT=1
            ;;
        --gdb)
            echo "Enabling Debug build..."
            BUILD_TYPE="Debug"
            BUILD_OPTIONS+=" -DCMAKE_BUILD_TYPE=Debug"
            ;;
        --enable-coverage)
            echo "Building with gcov code coverage support..."
            BUILD_OPTIONS+=" -DCM_ENABLE_COVERAGE=ON"
            ;;
        *)
            echo "Invalid option: $1"
            INV_OPT=1
            ;;
    esac
    shift
done

if [ ${INV_OPT} -eq 1 ]; then
  show_usage
fi

echo "Calling: cmake ${TARGET_PLATFORM}\
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
      ${BUILD_OPTIONS} CMakeLists.txt ../."

cmake ${TARGET_PLATFORM} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} \
      CMakeLists.txt ../.

echo "Calling: make ${BUILD_TGT}"
make ${BUILD_TGT}
