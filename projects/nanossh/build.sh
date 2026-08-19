#!/usr/bin/env bash

PROJECT_NAME=libnanossh
######################
function show_usage
{
  echo ""
  echo "./build.sh --gdb --debug --< tap-local | tap-remote  > --toolchain <string> --platform <string> <MAKETARGETS>"
  echo ""
  echo "   --gdb                       - Build a Debug version or Makefiles & Projects. (Release is default)"
  echo "   --debug                     - Build with Mocana logging enabled for specific build executable."
  echo "   --disable-suiteb            - Build with suiteb disabled."
  echo "   --disable-pqc               - Build with PQC disabled."
  echo "   --pqc-composite             - Build with pqc composite signature algs"
  echo "   --libtype <static | shared> - Build a library either static type or shared type default is shared."
  echo "   --toolchain <rpi32 | rpi64 | bbb> - Specify the toolchain to be used"
  echo "                        rpi32     For Raspberry Pi 32-bit"
  echo "                        rpi64     For Raspberry Pi 64-bit"
  echo "                        bbb       For BeagleBone Black"
  echo "   --platform <name>           - Name the platform of the generated installer package."
  echo "   --clean                     - Clean build."
  echo "   --server_cert_auth          - Building with server_cert_auth..."
  echo "   --cert                      - Building With Cert Enabled..."
  echo "   --ocsp_cert                 - Building with ocsp cert enabled..."
  echo "   --ocsp_config_timeout       - Building with ocsp timeout enabled..."
  echo "   --client_auth               - Building with client auth enabled..."
  echo "   --client_cert_auth          - Building with client cert auth enabled..."
  echo "   --port_forwarding           - Building with port forwarding..."
  echo "   --remote_port_forwarding    - Building with remote port forwarding..."
  echo "   --radius                    - Building with radius..."
  echo "   --scp-example               - Building with SCP example..."
  echo "   --emulator                  - Building with emulator..."
  echo "   --library                   - Building Shared Library..."
  echo "   --no-pubkey-name            - Build with support for no public key name in public key blob."
  echo "   --serial-channel            - Build with support for serial channels on single connection."
  echo "   --rfc4256                   - Build with RFC4256 support enabled."
  echo "   --fips                      - Build with FIPS enabled."
  echo "   --strict_dh                 - Build with strict DH enabled..."
  echo "   --data-protect              - Build with Data Protection"
  echo "   --enable-chachapoly         - Build with ChaChaPoly support"
  echo "   --enable-blowfish           - Build with Blowfish support"
  echo "   --enable-dsa                - Build with DSA suport"
  echo "   --disable-eddsa-25519       - Build without Ed25519 support"
  echo "   --disable-eddh-25519        - Build without ECDH with Curve25519 support"
  echo "   --graceful_shutdown         - Shutdown the server or client example gracefully."
  echo "   --enable-weak-ciphers       - Build with weak ciphers enabled."
  echo "     ssh_server                - Build the SSH Server."
  echo "     ssh_client                - Build the SSH Client."
  echo "     <MAKETARGETS>             - Make targets to build. ('all' is default)"
  echo ""
  exit -1
}


# Place us in the dir of this script
CURR_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
MSS_DIR=$CURR_DIR/../..

unamestr=`uname`
printf "\n\nBuilding ${PROJECT_NAME}.\n\n\n"

if [[ "$unamestr" == 'Darwin' ]]; then
    SHARED_LIB_NAME=${PROJECT_NAME}.dylib
else
    SHARED_LIB_NAME=${PROJECT_NAME}.so
fi

if [ -d "build" ]; then
    rm -rf build
    mkdir build
else
    mkdir build
fi

is_static_lib=0
is_tap_enabled=0
is_tap_remote_enabled=0
is_build_nanossh_enabled=0
is_build_ssh_aps_enabled=0
is_build_openssh_shim_aps_enabled=0
is_tpm12_enabled=0
is_clean_build=0
is_32bit_build=0
is_64bit_build=0
is_shared_lib=0
is_client=1

BUILD_OPTIONS=
BUILD_TYPE=Release
BUILD_TGT=
ADD_ARGS=
CLEAN_LIBS_ARGS=
INV_OPT=0
TOOLCHAIN_FILE=
CMAKE_MOCANA_PLATFORM_NAME=
MBED_ENABLED=0
SECURE_PATH_VAR=""

function set_toolchain_file()
{
    case "$1" in
        rpi32)
            echo "-- Setting toolchain for Raspberry Pi 32-bit";
            TOOLCHAIN_FILE="-DCMAKE_TOOLCHAIN_FILE=../shared_cmake/toolchains/arm-linux-gnu-toolchain.cmake"
            CMAKE_MOCANA_PLATFORM_NAME="-DCMAKE_MOCANA_PLATFORM=rpi3_raspbian_9.4"
            ;;
        rpi64)
            echo "-- Setting toolchain for Raspberry Pi 64-bit";
            TOOLCHAIN_FILE="-DCMAKE_TOOLCHAIN_FILE=../shared_cmake/toolchains/aarch64-linux-gnu-toolchain.cmake"
            CMAKE_MOCANA_PLATFORM_NAME="-DCMAKE_MOCANA_PLATFORM=rpi3_raspbian_9.4"
            ;;
        bbb)
            echo "-- Setting toolchain for BeagleBone Black";
            TOOLCHAIN_FILE="-DCMAKE_TOOLCHAIN_FILE=../shared_cmake/toolchains/arm-linux-gnu-toolchain.cmake"
            CMAKE_MOCANA_PLATFORM_NAME="-DCMAKE_MOCANA_PLATFORM=bbb_ubuntu_16.04"
            ;;
    esac
}

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
        --export)
            echo "Building Export Edition library...";
            BUILD_OPTIONS+=" -DCM_ENABLE_EXPORT_ED=ON -DCM_DISABLE_PQC=ON"
            ;;
        --suiteb)
            echo "suiteb is enabled by default (legacy --suiteb flag ignored)...";
            ;;
        --pqc)
            echo "PQC is enabled by default (legacy --pqc flag ignored)...";
            ;;
        --oqs)
            echo "PQC is enabled by default (legacy --oqs flag ignored)...";
            ;;
        --disable-suiteb)
            echo "Building with suiteb disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_SUITEB=ON -DCM_DISABLE_PQC=ON"
            ;;
        --disable-pqc)
            echo "Building with PQC disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_PQC=ON"
            ;;
        --pqc-composite)
            echo "Building with PQC composite...";
            BUILD_OPTIONS+=" -DCM_ENABLE_PQC_COMPOSITE=ON";
            ;;
        --tap-off)
            ;;
        --absolute-path)
            echo "Building with absolute path enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_ABSOLUTE_PATH=ON"
            ;;
        --secure-path)
            echo "Building with secure path enabled..."
            SECURE_PATH_VAR="-DSECURE_PATH=\"${2}\""
            shift
            ;;
        --tap-local)
            echo "Building with tap local...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP=ON -DCM_ENABLE_TAP_LOCAL=ON"
            ;;
        --tap-remote)
            echo "Building with tap remote...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP=ON -DCM_ENABLE_TAP_REMOTE=ON"
            ;;
        --cert)
            echo "Building With Cert Enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_X509_CERTS=ON"
            ;;
        --server_cert_auth)
            echo "Building with server_cert_auth...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SERVER_CERT_AUTH=ON"
            ;;
        --ocsp_cert)
            echo "Building with ocsp cert enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_OCSP_CERT=ON"
            ;;
        --ocsp_config_timeout)
            echo "Building with ocsp timeout enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_OCSP_TIMEOUT_CONFIG=ON"
            ;;
        --client_auth)
            echo "Building with client auth enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_CLIENT_AUTH=ON"
            ;;
        --client_cert_auth)
            echo "Building with client cert auth enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_CLIENT_CERT_AUTH=ON"
            ;;
        --port_forwarding)
            echo "Building with port forwarding...";
            BUILD_OPTIONS+=" -DCM_ENABLE_MOCANA_PORT_FORWARD=ON"
            ;;
        --remote_port_forwarding)
            echo "Building with remote port forwarding...";
            BUILD_OPTIONS+=" -DCM_ENABLE_MOCANA_REMOTE_PORT_FORWARD=ON"
            ;;
        --radius)
            echo "Building with radius...";
            BUILD_OPTIONS+=" -DCM_ENABLE_RADIUS=ON"
            ;;
        --scp-example)
            echo "Building with SCP example..."
            BUILD_OPTIONS+=" -DCM_ENABLE_SCP_EXAMPLE=ON"
            ;;
        --emulator)
            echo "Building with emulator...";
            BUILD_OPTIONS+=" -DCM_ENABLE_EMULATOR=ON"
            ;;
        --platform)
            shift
            BUILD_OPTIONS+=" -DCP_SYSTEM_NAME=${1}"
            ;;
        --toolchain)
            shift
            echo "Setting toolchain for ${1}"
            set_toolchain_file $1
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
        --clean)
            echo "Clean build";
            is_clean_build=1;
            ;;
        --library)
            echo "Build Shared Library";
            BUILD_OPTIONS+=" -DCM_BUILD_SHARED_LIBS=ON";
            is_shared_lib=1
            ;;
        --no-pubkey-name)
            echo "Build with support for no public key name in public key blob.";
            BUILD_OPTIONS+=" -DCM_ENABLE_MOCANA_NO_PUBKEY_NAME=ON";
            ;;
        --serial-channel)
            echo "Build with support for serial channels on single connection.";
            BUILD_OPTIONS+=" -DCM_ENABLE_SERIAL_CHANNEL=ON";
            ;;
        --fips)
            echo "-- Building with FIPS enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_FIPS=ON"
            ;;
        --strict_dh)
            echo "Building with strict dh ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_STRICT_DH=ON"
            ;;
        --rfc4256)
            echo "Building with RFC 4256 support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_KEYBOARD_INTERACTIVE=ON"
            ;;
        --data-protect)
            echo "Enabling data protection"
            BUILD_OPTIONS+=" -DCM_ENABLE_DATA_PROTECTION=ON"
            ;;
        --enable-chachapoly)
            echo "Enabling ChaCha20 and Poly1305 support"
            BUILD_OPTIONS+=" -DCM_ENABLE_CHACHAPOLY=ON"
            ;;
        --enable-blowfish)
            echo "Enabling Blowfish support"
            BUILD_OPTIONS+=" -DCM_ENABLE_BLOWFISH=ON"
            ;;
        --enable-dsa)
            echo "Enabling DSA support in NanoSSH"
	    BUILD_OPTIONS+=" -DCM_ENABLE_DSA_SUPPORT=ON"
            ;;
        --disable-eddsa-25519)
            echo "Dsiabling Ed25519 support in NanoSSH"
            BUILD_OPTIONS+=" -DCM_DISABLE_EDDSA_25519_SUPPORT=ON"
            ;;
        --disable-eddsa-448)
            echo "Dsiabling Ed448 support in NanoSSH"
            BUILD_OPTIONS+=" -DCM_DISABLE_EDDSA_448_SUPPORT=ON"
            ;;
        --disable-eddh-25519)
            echo "Disabling ECDH with Curve25519 support in NanoSSH"
            BUILD_OPTIONS+=" -DCM_DISABLE_ECDH_25519_SUPPORT=ON"
            ;;
        --graceful_shutdown)
            echo "Building with server or client example shutdown gracefully..."
            BUILD_OPTIONS+=" -DCM_ENABLE_MOCANA_SSH_EXAMPLE_GRACEFUL_SHUTDOWN=ON"
            ;;
	--skip-disconnect)
           echo "Build with server skipping disconnect message for client initiated close"
	   BUILD_OPTIONS+=" -DCM_ENABLE_SSH_SERVER_SKIP_DISCONNECT_ON_CLOSE=ON"
	   ;;
        --enable-weak-ciphers)
            echo "Building with weak ciphers enabled..."
            BUILD_OPTIONS+=" -DCM_ENABLE_WEAK_CIPHERS=ON"
            ;;
        ssh_client)
            echo "Build the ssh_client application...";
            BUILD_OPTIONS+=" -DCM_BUILD_SSH_CLIENT=ON"
            ADD_ARGS+=" ssh_client"
            CLEAN_LIBS_ARGS+=" ssh_client"
            is_build_ssh_aps_enabled=1;
            ;;
        ssh_server)
            echo "Build the ssh_server application...";
            BUILD_OPTIONS+=" -DCM_BUILD_SSH_SERVER=ON"
            ADD_ARGS+=" ssh_server"
            CLEAN_LIBS_ARGS+=" ssh_server"
            is_build_ssh_aps_enabled=1;
            is_client=0;
            ;;
        ssh_server_sp800_135)
            echo "Build the ssh_server for testing SP800-135...";
            BUILD_OPTIONS+=" -DCM_BUILD_SSH_SERVER_SP800_135=ON"
            ADD_ARGS+=" ssh_server_sp800_135"
            CLEAN_LIBS_ARGS+=" ssh_server_sp800_135"
            is_build_ssh_aps_enabled=1;
            is_client=0;
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

# Check if building for OSI
source $CURR_DIR/../../scripts/check_for_osi.sh
if [ ${OSI_BUILD} -eq 1 ]; then
    BUILD_OPTIONS+=" -DBUILD_FOR_OSI=ON"
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

if [[ $is_tap_enabled -eq 1 ]] && [[ $is_tpm12_enabled -eq 1 ]]; then
   echo "Error: Both the flags --tap and --tpm12 should not be enabled. Either one of the flags --tap or --tpm12 should be enabled."
   exit 1
fi
if [[ $is_tap_enabled -eq 0 ]] && [[ $is_tap_remote_enabled -eq 1 ]]; then
   echo "Error: Enable the flag --remote only in case if --tap is enabled."
   exit 1
fi

if [ $is_32bit_build -eq 1 -a $is_64bit_build -eq 1 ]; then
   echo "Error: Both the flags --x32 and --x64 should not be enabled. Either one of the flags --x32 or --x64 should be enabled."
   exit 1
fi

#if [[ $is_build_nanossh_enabled -eq 1 ]] && [[ $is_build_ssh_aps_enabled -eq 1 ]]; then
#   echo "Error: Build the Either nanossh or ssh Applications only."
#   exit 1
#fi

cd $CURR_DIR
if [ ! -d $CURR_DIR/build ]; then
    mkdir build
fi

if [ $is_clean_build -eq 1 ]; then
    echo "Calling: clean.sh..."
    . clean.sh "${CLEAN_LIBS_ARGS}"
    mkdir build
fi

cd $CURR_DIR/build
echo "Calling: ${TOOLCHAIN_FILE} ${CMAKE_MOCANA_PLATFORM_NAME} ${SECURE_PATH_VAR} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} CMakeLists.txt ../."

cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 ${TOOLCHAIN_FILE} ${SECURE_PATH_VAR} \
      ${CMAKE_MOCANA_PLATFORM_NAME} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} CMakeLists.txt ../.


if [ $is_shared_lib -eq 1 ]; then
    if [ $is_client -eq 1 ]; then
        echo "Calling: make libnanosshc"
        make -j12 nanosshc
    else
        echo "Calling: make libnanosshs"
        make -j12 nanosshs
    fi
else
    echo "Calling: make ${BUILD_TGT}"
    make -j12 ${BUILD_TGT}
fi

