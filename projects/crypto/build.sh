#!/usr/bin/env bash

######################
function show_usage
{
  echo ""
  echo "./build.sh --gdb --debug <additional cipher options> --export --openssl --tap --tap-extern --tap-remote
           --operator-path <path> --mbed --mbed-path <path> --oqs --oqs-path <path> [--x32 | --x64]
           --toolchain <string> <MAKETARGETS>"
  echo ""
  echo "   --gdb             - Build a Debug version or Makefiles & Projects. (Release is default)"
  echo "   --pg              - Build with call stack tracing."
  echo "   --debug           - Build with Mocana logging enabled for specific build executable."
  echo "   --aesni           - Build with AES-Ni support"
  echo "   --aes-small       - Build with AES small"
  echo "   --chacha20        - Build with ChaCha20 enabled."
  echo "   --des             - Build with DES enabled."
  echo "   --blowfish        - Build with BLOWFISH enabled."
  echo "   --sha3            - Build with SHA3 enabled."
  echo "   --pkcs1           - Build with PKCS1 enabled."
  echo "   --poly1305        - Build with POLY1305 enabled."
  echo "   --rsa_8k          - Build with RSA 8K enabled."
  echo "   --aes-gcm-4k      - Build with AES-GCM 4K table (only)"
  echo "   --aes-gcm-256b    - Build with AES-GCM 256b table (only)"
  echo "   --disable-pqc     - Build with Post Quantum Cryptography disabled"
  echo "   --disable-aes     - Build with AES disabled."
  echo "   --disable-aes-ccm - Build with AES-CCM disabled."
  echo "   --disable-aes-cmac- Build with AES-CMAC disabled."
  echo "   --disable-aes-ctr - Build with AES-CTR disabled."
  echo "   --disable-aes-eax - Build with AES-EAX disabled."
  echo "   --disable-aes-mmo - Build with AES-MMO disabled."
  echo "   --disable-aes-xcbc-mac-96 - Build with AES-XCBC MAC 96 disabled."
  echo "   --disable-aes-xts - Build with AES-XTS disabled."
  echo "   --disable-dh      - Build with DH disabled."
  echo "   --disable-rng     - Build with RNG disabled."
  echo "   --disable-rsa     - Build with RSA disabled."
  echo "   --disable-rc4     - Build with RC4 disabled."
  echo "   --disable-rc5     - Build with RC5 disabled."
  echo "   --disable-sha224  - Build with SHA224 disabled."
  echo "   --disable-sha256  - Build with SHA256 disabled."
  echo "   --disable-sha384  - Build with SHA384 disabled."
  echo "   --disable-sha512  - Build with SHA512 disabled."
  echo "   --disable-tdes    - Build with TDES disabled."
  echo "   --libtype <static | shared> - Build a library either static type or shared type default is shared."
  echo "   --operator-path   - Path and name of static library with operator implementations"
  echo "   --mbed            - Build with mbed enabled. Path must be specified."
  echo "   --mbed-path       - Path to mbedTLS installation."
  echo "   --oqs             - Build with oqs enabled. Path must be specified."
  echo "   --oqs-path        - Path to OQS install dir"
  echo "   --export          - Build the Export Edition of this library."
  echo "   --openssl         - Build with OpenSSL shim support."
  echo "   --pss-var-salt    - Auto recover PSS salt length during inline PSS verify during PSS sign operation for TAP."
  echo "   --ssh             - Build with required SSH algorithms."
  echo "   --ssh-no-chachapoly - Build with SSH algorithms minus chachapoly."
  echo "   --ssl             - Build with NanoSSL support."
  echo "   --tpm2            - Build with TPM2.0 support."
  echo "   --scep            - Build with SCEP support."
  echo "   --ike             - Build with IKE support."
  echo "   --ipv6            - Build with IPV6 enabled."
  echo "   --wpa2            - Build with WPA2 support."
  echo "   --ipsec           - Build with IPSEC support."
  echo "   --openssl         - Build with Mocana OpenSSL."
  echo "   --openssl3        - Build with Digicert Openssl 3.0 provider support"
  echo "   --nil-cipher      - Build with Nil Cipher enabled."
  echo "   --mcp             - Enable IPSEC service for CryptoInterface"
  echo "   --fips            - Build with FIPS."
  echo "   --fips-700-compat - Build with backward compatibility with FIPS REL_700_U1 binary."
  echo "   --hw-accel        - Building Hardware Accelerator support..."
  echo "   --tap             - Build with TAP."
  echo "   --tap-remote      - Build with TAP remote."
  echo "   --tap-extern      - Build with TAP extern."
  echo "   --tap-hybrid-sign - Build with hybrid signing scheme using for SW and HW."
  echo "   --vlong-const     - Build with constant time vlong ops."
  echo "   --cvc             - Build with CV cert functionality."
  echo "   --ci-tests        - Build all algorithms for crypto interface unittests."
  echo "   --toolchain <rpi32 | rpi64 | bbb | android> - Specify the toolchain to be used"
  echo "                        rpi32     For Raspberry Pi 32-bit"
  echo "                        rpi64     For Raspberry Pi 64-bit"
  echo "                        bbb       For BeagleBone Black"
  echo "                        android   For android"
  echo "   --x32             - Creates build for 32Bit machine. By default creates build for 64Bit machine."
  echo "   --x64             - Creates build for 64Bit machine. By default creates build for 64Bit machine."
  echo "   --cmake-opt       - Use this parameter to pass extra CMAKE parameters."
  echo "                        exa: --cmake-opt -D<MACRO>=<VALUE>"
  echo "   <MAKETARGETS>     - Make targets to build. ('all' is default)"
  echo ""
  exit -1
}

# Place us in the dir of this script
cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null
CURR_DIR=$(pwd)

printf "\n\nBuilding crypto libraries.\n\n"
. clean.sh
mkdir build
cd build
is_static_lib=0
is_32bit_build=0
is_64bit_build=0

CI_DISABLED=0
BUILD_OPTIONS=
BUILD_TYPE=Release
BUILD_TGT=
ADD_ARGS=
INV_OPT=0
TARGET_PLATFORM=
OQS_BUILD=0
EXPORT_BUILD=0

source $CURR_DIR/../shared_cmake/get_toolchain.sh

while test $# -gt 0
do
    case "$1" in
        --gdb)
            echo "Enabling Debug build...";
            BUILD_OPTIONS+=" -DCMAKE_BUILD_TYPE=Debug"
            ;;
        --pg)
            echo "Enabling callstack tracing build...";
            BUILD_OPTIONS+=" -DCM_ENABLE_PG=ON"
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
        --suiteb)
            echo "suiteb is enabled by default (legacy --suiteb flag ignored)...";
            ;;
        --disable-suiteb)
            echo "Building with suiteb disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_SUITEB=ON"
            ;;
        --nil-cipher)
            echo "Building with Nil Cipher enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_NIL=ON"
            ;;
        --chacha20)
            echo "Building with ChaCha20 enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_CHACHA20=ON"
            ;;
        --rsa_8k)
            echo "Building with RSA 8K enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_RSA_8K=ON"
            ;;
        --blake2)
            echo "Building with blake2 enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_BLAKE2=ON"
            ;;
        --md4)
            echo "Building with md4 enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_MD4=ON"
            ;;
        --des)
            echo "Building with des enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_DES=ON"
            ;;
        --blowfish)
            echo "Building with blowfish enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_BLOWFISH=ON"
            ;;
        --sha3)
            echo "Building with SHA3 enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SHA3=ON"
            ;;
        --pkcs1)
            echo "Building with PKCS1 enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_PKCS1=ON"
            ;;
        --poly1305)
            echo "Building with POLY1305 enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_POLY1305=ON"
            ;;
        --disable-aes)
            echo "Building with AES disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_AES=ON"
            ;;
        --disable-aes-ccm)
            echo "Building with AES-CCM disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_AES_CCM=ON"
            ;;
        --disable-aes-cmac)
            echo "Building with AES-CMAC disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_AES_CMAC=ON"
            ;;
        --disable-aes-ctr)
            echo "Building with AES-CTR disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_AES_CTR=ON"
            ;;
        --disable-aes-eax)
            echo "Building with AES-EAX disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_AES_EAX=ON"
            ;;
        --disable-aes-mmo)
            echo "Building with AES-MMO disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_AES_MMO=ON"
            ;;
        --disable-aes-xcbc-mac-96)
            echo "Building with AES-XCBC MAC 96 disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_AES_XCBC_MAC_96=ON"
            ;;
        --disable-aes-xts)
            echo "Building with AES-XTS disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_AES_XTS=ON"
            ;;
        --disable-chacha20)
            echo "Building with ChaCha20 disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_CHACHA20=ON"
            ;;
        --disable-des)
            echo "Building with DES disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_DES=ON"
            ;;
        --disable-pkcs1)
            echo "Building with PKCS1 disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_PKCS1=ON"
            ;;
        --disable-dh)
            echo "Building with DH disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_DH=ON"
            ;;
        --disable-ec-elgamal)
            echo "Building with EC ElGamal disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_EC_ELGAMAL=ON"
            ;;
        --disable-ec-mqv)
            echo "Building with EC MQV disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_EC_MQV=ON"
            ;;
        --disable-ed)
            echo "Building with ED curves disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_ED=ON"
            ;;
        --disable-dsa)
            echo "Building with DSA disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_DSA=ON"
            ;;
        --disable-fips186-rng)
            echo "Building with FIPS 186 RNG disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_FIPS186_RNG=ON"
            ;;
        --disable-math)
            echo "Building with math operations disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_MATH=ON"
            ;;
        --disable-nist-kdf)
            echo "Building with NIST KDF disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_NIST_KDF=ON"
            ;;
        --disable-poly1305)
            echo "Building with Poly1305 disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_POLY1305=ON"
            ;;
        --disable-rng)
            echo "Building with RNG disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_RNG=ON"
            ;;
        --disable-rsa)
            echo "Building with RSA disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_RSA=ON"
            ;;
        --disable-rc4)
            echo "Building with RC4 disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_RC4=ON"
            ;;
        --disable-rc5)
            echo "Building with RC5 disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_RC5=ON"
            ;;
        --disable-sha224)
            echo "Building with SHA224 disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_SHA224=ON"
            ;;
        --disable-sha256)
            echo "Building with SHA256 disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_SHA256=ON"
            ;;
        --disable-sha384)
            echo "Building with SHA384 disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_SHA384=ON"
            ;;
        --disable-sha512)
            echo "Building with SHA512 disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_SHA512=ON"
            ;;
        --disable-sha3)
            echo "Building with SHA3 disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_SHA3=ON"
            ;;
        --disable-tdes)
            echo "Building with TDES disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_TDES=ON"
            ;;
        --debug)
            echo "Building with Debug logs enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_DEBUG=ON"
            ;;
        --keygen)
            echo "Building with crypto keygen APIs...";
            BUILD_OPTIONS+=" -DCM_ENABLE_KEYGEN=ON"
            ;;
        --aesni)
            echo "Building for AES-Ni";
            BUILD_OPTIONS+=" -DCM_ENABLE_AES_NI=ON"
            ;;
        --aes-gcm-4k)
            echo "Building for AES-GCM 4k";
            BUILD_OPTIONS+=" -DCM_ENABLE_AES_GCM_4K=ON"
            ;;
        --aes-gcm-256b)
            echo "Building for AES-GCM 256b";
            BUILD_OPTIONS+=" -DCM_ENABLE_AES_GCM_256B=ON"
            ;;
        --small-footprint)
            echo "Building with small footprint"
            BUILD_OPTIONS+=" -DCM_ENABLE_SMALL_FOOTPRINT=ON"
            ;;
        --ssl)
            echo "Building with NanoSSL support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL=ON"
            ;;
        --tpm2)
            echo "Building with TPM2 support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TPM2=ON"
            ;;
        --pss-var-salt)
            echo "Building with variable salt length for TAP...";
            BUILD_OPTIONS+=" -DCM_ENABLE_PSS_VAR_SALT=ON"
            ;;
        --ssh)
            echo "Building with NanoSSH support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSH=ON"
            ;;
        --ssh-no-chachapoly)
            echo "Building with NanoSSH support (no chachapoly)...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSH_NO_CHACHAPOLY=ON"
            ;;
        --scep)
            echo "Building with SCEP support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SCEP=ON"
            ;;
        --ike)
            echo "Building with IKE support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_IKE=ON"
            ;;
        --ipv6)
            echo "Building with IPV6 enabled ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_IPV6=ON"
            ;;
        --wpa2)
            echo "Building with WPA2 support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_WPA2=ON"
            ;;
        --eap)
            echo "Building with EAP support..."
            BUILD_OPTIONS+=" -DCM_ENABLE_EAP=ON"
            ;;
        --ipsec)
            echo "Building with IPSEC support..."
            BUILD_OPTIONS+=" -DCM_ENABLE_IPSEC=ON"
            ;;
        --openssl)
            echo "Building with Mocana OpenSSL...";
            BUILD_OPTIONS+=" -DCM_ENABLE_OPENSSL_SHIM=ON"
            ;;
        --openssl3)
            echo "Building with Digicert OpenSSL 3.0 provider support";
            BUILD_OPTIONS+=" -DCM_ENABLE_OPENSSL3=ON"
            ;;
        --tap)
            echo "Building with TAP...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP=ON"
            ;;
        --tap-local)
            ;;
        --tap-remote)
            echo "Building with TAP Remote...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP_REMOTE=ON"
            ;;
        --tap-extern)
            echo "Building with TAP extern...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP_EXTERN=ON"
            ;;
        --tap-hybrid-sign)
            echo "Building with TAP hybrid sign...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP_HYBRID_SIGN=ON"
            ;;
        --export)
            echo "Building Export Edition library...";
            BUILD_OPTIONS+=" -DCM_ENABLE_EXPORT_ED=ON"
            EXPORT_BUILD=1
            ;;
        --mcp)
            echo "Enable IPSEC service for Crypto interface...";
            BUILD_OPTIONS+=" -DCM_ENABLE_MCPA=ON"
            ;;
        --fips)
            echo "Enable FIPS build...";
            BUILD_OPTIONS+=" -DCM_ENABLE_FIPS=ON"
            ;;
        --fips-700-compat)
            echo "Enable FIPS REL_700_U1 binary compatible build...";
            BUILD_OPTIONS+=" -DCM_ENABLE_FIPS_700_U1_COMPAT=ON"
            ;;
        --hw-accel)
            echo "Build with Hardware Acceleration...";
            BUILD_OPTIONS+=" -DCM_ENABLE_HW_ACCEL=ON"
            ;;
        --ci-tests)
            echo "Enable all algorithms for Crypto Interface unit tests...";
            BUILD_OPTIONS+=" -DCM_ENABLE_CITESTS=ON"
            ;;
        --toolchain)
            shift
            TARGET_PLATFORM=$(get_platform "${1}") || INV_OPT=1
            XC_BIN_PATH=$(get_sysroot_bin "${1}") || INV_OPT=1
            export PATH=${XC_BIN_PATH}:$PATH
            ;;
        --prod-rng)
            echo "Building with production RNG...";
            BUILD_OPTIONS+=" -DCM_ENABLE_PROD_RNG=ON";
            ;;
        --operator-path)
            BUILD_OPTIONS+=" -DCM_ENABLE_OPERATORS=ON -DCM_OPERATOR_PATH=$2";
            shift
            ;;
        --mbed)
            echo "Building with mbed enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_MBED=ON";
            ;;
        --mbed-path)
            BUILD_OPTIONS+=" -DCM_MBED_PATH=${2}";
            shift
            ;;
        --pqc)
            echo "PQC is enabled by default (legacy --pqc flag ignored)...";
            ;;
        --disable-pqc)
            echo "Building with pqc disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_PQC=ON";
            ;;
        --oqs)
            echo "Building with oqs enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_OQS=ON";
            OQS_BUILD=1
            ;;
        --oqs-path)
            BUILD_OPTIONS+=" -DCM_OQS_PATH=${2}";
            shift
            ;;
        --no-cryptointerface)
            echo "Building with crypto interface disabled ...";
            CI_DISABLED=1
            ;;
        --vlong-const)
            BUILD_OPTIONS+=" -DCM_ENABLE_VLONG_CONST=ON"
            echo "Building with constant time vlong operations enabled";
            ;;
        --cvc)
            BUILD_OPTIONS+=" -DCM_ENABLE_CVC=ON"
            echo "Building with CV Cert functionality.";
            ;;
        --enable-pc)
            BUILD_OPTIONS+=" -DCM_ENABLE_CERT_PRINT=ON"
            echo "Building with Certificate/CSR printing enabled.";
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
        --cmake-opt)
            shift
            echo "Setting extra flags for cmake execution...";
            BUILD_OPTIONS+=" ${1}"
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
            echo "Adding Argument: $1";
            ADD_ARGS+=" $1"
            ;;
    esac
    shift
done
echo ""

# Check if building for OSI
source $CURR_DIR/../../scripts/check_for_osi.sh
if [ ${OSI_BUILD} -eq 1 ]; then
    BUILD_OPTIONS+=" -DBUILD_FOR_OSI=ON"
fi

if [ ${INV_OPT} -eq 1 ]; then
  show_usage
fi

if [ ${CI_DISABLED} -eq 0 ]; then
    BUILD_OPTIONS+=" -DCM_ENABLE_CRYPTOINTERFACE=ON"
fi

if [ $OQS_BUILD -eq 0 ] && [ $EXPORT_BUILD -eq 1 ]; then
    echo "Export Build with no oqs, disabling PQC";
    BUILD_OPTIONS+=" -DCM_DISABLE_PQC=ON"
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

echo "Calling: cmake ${TARGET_PLATFORM} \
-DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} CMakeLists.txt ../. "

cmake ${TARGET_PLATFORM} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} CMakeLists.txt ../.


echo "Calling: make ${BUILD_TGT}"
make ${BUILD_TGT}
