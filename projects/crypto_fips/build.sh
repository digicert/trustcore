#! /usr/bin/env bash
###

function show_usage
{
  echo ""
  echo "Usage: ./build.sh [--gdb] [--fips-persist] [--host-only] [--x32|--x64] [--platform <string>] [--build_id <string>] [--lib-path <string>]"
  echo ""
  echo "--gdb               - Enable debugger symbols"
  echo "--fips-persist      - Enable persisted FIPS selftest status and filepath for persist file (MSSP)"
  echo "--fips-key <path>   - Replace the 'default' integrity key with the contents of the file (expert only!)"
  echo "--disable-pqc       - Build with Post Quantum Cryptography disabled"
  echo "--enable-jent-lib   - Build with Jitter entropy input (library) for NIST DRBG"
  echo "--enable-jent-lkm   - Build with Jitter entropy input (kernel mod)  for NIST DRBG"
  echo "--enable-urand      - Build with entropy input from Linux urandom  for NIST DRBG"
  echo "--test-jent-lib     - Add entropy to DRBG from application using JENT LIB (not allowed with NIST DRBG)"
  echo "--test-jent-lkm     - Add entropy to DRBG from application using JENT LKM (not allowed with NIST DRBG)"
  echo "--host-only         - Compile host tools, only"
  echo "--x32               - Compile for 32 bit"
  echo "--x64               - Compile for 64 bit"
  echo "--toolchain <name>  - Name of the platform toolchain"
  echo "--toolpath <name>   - Name of the platform toolpath"
  echo "--platform <name>   - Name the platform of the generated installer package."
  echo "--build_id <string> - Jenkins Build Job # and/or Git Commit hash. (e.g. 42:4687928 )"
  echo "--lib-path <string> - The target's path to the MSS libaries [default '/usr/local/lib']"
  exit
}

function make_so_sign
{
  mkdir -p so_sign
  pushd so_sign
  
  echo ""
  echo "Calling: cmake -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} \
 -DMSS_BUILD_STR=\"${BUILD_STR}\" -DMSS_BUILDTIME_STR=\"${MY_DATE}\" \
 CMakeLists.txt ../../so_sign "
  echo ""

  cmake -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} \
      -DMSS_BUILD_STR="${BUILD_STR}" -DMSS_BUILDTIME_STR="${MY_DATE}" \
      CMakeLists.txt ../../so_sign

  # Make
  make

  popd
}

function make_libmss
{
  mkdir -p libmss
  pushd libmss
  
  echo ""
  echo "Calling: cmake ${TARGET_PLATFORM}
 -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} \
 -DMSS_BUILD_STR=\"${BUILD_STR}\" -DMSS_BUILDTIME_STR=\"${MY_DATE}\" \
 CMakeLists.txt ../../libmss "
  echo ""

  cmake ${TARGET_PLATFORM} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} \
      -DMSS_BUILD_STR="${BUILD_STR}" -DMSS_BUILDTIME_STR="${MY_DATE}" \
      CMakeLists.txt ../../libmss

  # Make
  make

  popd
}

###########################################
## HMAC Key stuff. 
###########################################

function make_new_key
{
    local in_file="$1"
    echo "Change HMAC key, using '${in_file}'!"
    ${CURR_DIR}/change_hmac_key.sh "${in_file}" "${CURR_DIR}/../../src/crypto/fips_integ.c" "${CURR_DIR}/fips_integ.c.bak"
}

function restore_old_key
{
    echo "Restore HMAC key!"
    cp -a  "${CURR_DIR}/fips_integ.c.bak" "${CURR_DIR}/../../src/crypto/fips_integ.c"
    rm -f "${CURR_DIR}/fips_integ.c.bak"
}

###########################################
# Save where the user calls this
OLD_PWD=$(pwd)

# Place us in the dir of this script
cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null
CURR_DIR=$(pwd)

unamestr=`uname`

BUILD_OPTIONS=
BUILD_TYPE=Release
BUILD_TGT=
ADD_ARGS=
INV_OPT=0
TARGET_PLATFORM=
HOST_ONLY=0
REPLACE_KEY=0
USE_NIST_DRBG=0
USE_NON_NIST_DRBG=0

source $CURR_DIR/../shared_cmake/get_toolchain.sh

######################

while test $# -gt 0
do
    case "$1" in
        --gdb)
            BUILD_TYPE=Debug
            BUILD_STR=Dev
            ;;
        --fips-persist)
            shift
            BUILD_OPTIONS+=" -DCM_FIPS_PERSIST=ON"
            BUILD_OPTIONS+=" -DMSS_FINAL_PERSIST_PATH=${1}"
            ;;
        --fips-key)
            shift
            REPLACE_KEY=1
            REPLACE_KEY_PATH="${1}"
            ;;
        --disable-pqc)
            echo "Building with pqc disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_PQC=ON";
            ;;
        --enable-jent-lib)
            echo "Building with JEnt library enabled...";
            USE_NIST_DRBG=1
            BUILD_OPTIONS+=" -DCM_ENABLE_JENT_LIB=ON";
            ;;
        --enable-jent-lkm)
            echo "Building with JEnt kernel module enabled...";
            USE_NIST_DRBG=1
            BUILD_OPTIONS+=" -DCM_ENABLE_JENT_LKM=ON";
            ;;
        --enable-urand)
            echo "Building with Entropy from Linux urandom enabled...";
            USE_NIST_DRBG=1
            BUILD_OPTIONS+=" -DCM_ENABLE_URANDOM=ON";
            ;;
        --test-jent-lib)
            echo "Building with test entropy JENT/LIB enabled...";
            USE_NON_NIST_DRBG=1
            BUILD_OPTIONS+=" -DCM_TEST_JENT_LIB=ON";
            ;;
        --test-jent-lkm)
            echo "Building with test entropy JENT/LKM enabled...";
            USE_NON_NIST_DRBG=1
            BUILD_OPTIONS+=" -DCM_TEST_JENT_LKM=ON";
            ;;
        --host-only)
            HOST_ONLY=1
            ;;
        --x32)
            BUILD_OPTIONS+=" -DCM_SELECT_64BIT=OFF"
            BUILD_OPTIONS+=" -DCMAKE_MOCANA_PLATFORM=x86_32"
            ;;
        --x64)
            BUILD_OPTIONS+=" -DCM_SELECT_64BIT=ON"
            BUILD_OPTIONS+=" -DCMAKE_MOCANA_PLATFORM=x86_64"
            ;;
        --toolchain)
            shift
            TARGET_PLATFORM=$(get_platform "${1}") || INV_OPT=1
            XC_BIN_PATH=$(get_sysroot_bin "${1}") || INV_OPT=1
            #export PATH=${XC_BIN_PATH}:$PATH
            ;;
        --tool-path)
            shift
            BUILD_OPTIONS+=" -DCM_TOOL_PATH=${1}"
            ;;
        --platform)
            shift
            BUILD_OPTIONS+=" -DCM_SYSTEM_NAME=${1}"
            ;;
        --build_id)
            shift
            BUILD_OPTIONS+=" -DCM_SYSTEM_BUILD_ID=${1}"
            ;;
        --lib-path)
            shift
            BUILD_OPTIONS+=" -DMSS_FINAL_LIB_PATH=${1}"
            ;;
        --*) echo "Invalid option: $1"; INV_OPT=1
            ;;
        *) echo "Adding Argument: $1"; ADD_ARGS+=" $1"
            ;;
    esac
    shift
done

if [ ${INV_OPT} -eq 1 ]; then
  show_usage
fi
if [ ${USE_NON_NIST_DRBG} -eq 1 ] && [ ${USE_NIST_DRBG} -eq 1 ]; then
  echo "You chose options for BOTH NIST DRBG and Non-NIST DRBG configuration. ABORT!"
  exit 1
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

# Set date
MY_DATE=`date +"%F %H:%M"`
MY_GIT=`(cd ${CURR_DIR} ; git branch | grep "\*" | head -1 | cut -c3-43)`

if [ -z ${BUILD_STR} ]; then
  BUILD_STR="git-[${MY_GIT}]"
fi

# Clean
rm -rf build
mkdir build
cd build

# Replace key with different value
if (( ${REPLACE_KEY} == 1)); then
    make_new_key "${REPLACE_KEY_PATH}"
fi

make_so_sign
if (( ${HOST_ONLY} == 1)); then
    echo "Built all host tools... Stop."
    exit 0
fi

make_libmss

# Sign files
if [ -e so_sign/so_sign ]; then
    ./so_sign/so_sign libmss/libmss.so libmss/libmss.so.sig
else
    echo "No signing tool available. Skipped signing!!"
fi

# Replace key with original value
if (( ${REPLACE_KEY} == 1)); then
    restore_old_key
fi

# Back
cd "${OLD_PWD}"
