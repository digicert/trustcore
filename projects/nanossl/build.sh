#!/usr/bin/env bash

PROJECT_NAME=libnanossl
######################
function show_usage
{
  echo ""
  echo "./build.sh --gdb --debug --< tap-local | tap-remote | tap-remote-tcp > --toolchain <string> <MAKETARGETS>"
  echo ""
  echo "   --help            - Build options information"
  echo "   --gdb             - Build a Debug version or Makefiles & Projects. (Release is default)"
  echo "   --pg              - Build with call stack tracing."
  echo "   --debug           - Build with Mocana logging enabled for specific build executable."
  echo "   --disable-tls13   - Build with TLS 1.3 disabled."
  echo "   --disable-psk     - Build with TLS 1.3 PSK disabled."
  echo "   --disable-0rtt    - Build with TLS 1.3 0-RTT disabled."
  echo "   --libtype <static | shared> - Build a library either static type or shared type default is shared."
  echo "   --toolchain <rpi32 | rpi64 | bbb | android> - Specify the toolchain to be used"
  echo "                        rpi32     For Raspberry Pi 32-bit"
  echo "                        rpi64     For Raspberry Pi 64-bit"
  echo "                        bbb       For BeagleBone Black"
  echo "                        android   For android"
  echo "   --tap             - Build with tap for nanossl library."
  echo "   --tap-local       - Build with tap-local."
  echo "   --tap-remote      - Build with tap-remote."
  echo "   --tap-remote-tcp  - Build with tap-remote-tcp."
  echo "   --tap-extern      - Build with tap-extern."
  echo "   --tap-deferred-unload - Build with tap-deferred-unload."
  echo "   --proxy           - Build with transport handlers for proxy support"
  echo "   --dtls            - Build with dtls."
  echo "   --srtp            - Build with SRTP profiles for dtls."
  echo "   --mauth           - Build with mutual authentication."
  echo "   --pss-auto-recover - Allow NanoSSL to recover the salt length for PSS signatures."
  echo "   --ossl-tls-unique - Build with additional TLS unique support for the OpenSSL shim/connector."
  echo "   --openssl_shim    - Build with openssl_shim enabled."
  echo "   --ossl_multipacket_read - Enable reading of multiple records in a loop."
  echo "   --ossl_multipacket_bio_retry - Enable read until data is recieved."
  echo "   --disable-pqc     - Build without pqc"
  echo "   --pqc-composite   - Build with pqc composite signature algs"
  echo "   --ipv6            - Build with IPV6 enabled."
  echo "   --nil-cipher      - Build with Nil Cipher enabled."
  echo "   --mbed            - Enable mbed Operators"
  echo "   --export          - Build the Export Edition of this library"
  echo "   --oqs             - Build with OQS support"
  echo "   --self_signed     - Enable self signed cert"
  echo "   --non_trusted     - Enable non trust cert"
  echo "   --cert_status_override   - Override the OpenSSL shim certificate status if NanoSSL certificate validation is successful."
  echo "   --ocsp            - Enable OCSP"
  echo "   --rsa_8k          - Enable RSA 8K"
  echo "   --gcc_profile     - Enable gcc profile"
  echo "   --fips            - Enable fips module"
  echo "   --strict_dh       - Build with strict DH enabled..."
  echo "   --no-cryptointerface - Build with Crypto Interface disabled."
  echo "   --disable_rsa     - Disable rsa support"
  echo "   --enable_des      - Enable DES cipher support"
  echo "   --enable_3des     - Enable 3DES cipher support"
  echo "   --disable-cbc     - Disable CBC cipher support"
  echo "   --disable_polychacha_tls12 - Diable CHACHA20-POLY1305 ciphers for TLS 1.2 and lower versions"
  echo "   --enable_ecp192   - Enable EC P-192 curve support"
  echo "   --dh_pub_pad      - Pad DH public keys"
  echo "   --enable_eap_fast - Enable EAP fast support"
  echo "   --redefine        - Enable redefine"
  echo "   --rehandshake     - Enable rehandshake"
  echo "   --anon-support    - Enable anonymous suites"
  echo "   --openssl_1_1_x   - (OBSOLETE) Build with openssl 1_1_x"
  echo "   --openssl_1_1_1   - (OBSOLETE) Build with openssl 1_1_1"
  echo "   --openssl_1_1_1f  - (OBSOLETE) Build with openssl 1_1_1f"
  echo "   --openssl_1_1_1i  - Build with openssl 1_1_1i"
  echo "   --openssl_1_1_1k  - Build with openssl 1_1_1k"
  echo "   --openssl_3_0_7   - Build with openssl 3_0_7"
  echo "   --openssl_3_0_12  - Build with openssl 3_0_12"
  echo "   --openssl_1_0_2u  - (OBSOLETE) Build with openssl 1_0_2u"
  echo "   --openssl_1_0_2t  - (OBSOLETE) Build with openssl 1_0_2t"
  echo "   --openssl_1_0_2p  - (OBSOLETE) Build with openssl 1_0_2p"
  echo "   --openssl_1_0_2j  - (OBSOLETE) Build with openssl 1_0_2j"
  echo "   --openssl_load_algos - Build option to load all algorithms"
  echo "   --osslc_thread_safe - Build with thread safe handling for OpenSSL connector client."
  echo "   --extended-key    - Enable extended key usage"
  echo "   --rsa1024         - Set the minimum RSA key size to 1024 (unsecure)"
  echo "   --sha1            - Build NanoSSL with the SHA-1 algorithm allowed"
  echo "   --dsa             - Build NanoSSL with the DSA support"
  echo "   --aes-gcm-4k      - Build with AES-GCM 4K table"
  echo "   --aes-gcm-256b    - Build with AES-GCM 256b table"
  echo "   --tls12-fallback  - Build NanoSSL TLS 1.2 fallback enabled"
  echo "   --disable-servername-validation - Server flag to ignore the certificate common name."
  echo "   --disable-client-commonname-validation - Client flag to ignore the certificate common name check."
  echo "   --disable_ossl_default_trust_certs     - Disable loading of default CA Certs"
  echo "   --force_cert_chain - Enable loading of full cert chain along with the leaf cert"
  echo "   --defer-encoding-client-cert-auth - Defer encoding of client certificate authentication digest message"
  echo "   --version-logging - Enable version_logging."
  echo "   --redirect-log    - Redirect printf logs to stderr in OpenSSL Connector."
  echo "   --ossl_log        - Enable logging in OpenSSL Connector."
  echo "   --x32             - Creates build for 32Bit machine. By default creates build for 64Bit machine."
  echo "   --x64             - Creates build for 64Bit machine. By default creates build for 64Bit machine."
  echo "   --clean           - Clean build."
  echo "   --srp             - Enable SRP(Secure Remote Password)."
  echo "   --monolithic      - Build executables as a single binary with all dependencies."
  echo "   --enable_ticket_tls12 - Enable server side session ticket implementation as per RFC 5077."
  echo "   --enable_heartbeat - Enable the heart beat protocol as per RFC 6520."
  echo "   --enable_extended_master_secret - Enable support for computation of Extended Master Secret as per RFC 7627."
  echo "   --enable_session_id - Enable session resumption with session ID"
  echo "   --ossl_rx_buf_8k  - Build with 8K receive buffer."
  echo "   --ossl_rx_buf_4k  - Build with 4K receive buffer."
  echo "   --ossl_rx_buf_2k  - Build with 2K receive buffer."
  echo "   --opensslld_override - Build with ld file from thirdparty directory"
  echo "   --disable_peek_error - Building with peer error disabled."
  echo "   --keylog          - Building with key logging enabled."
  echo "   --keylog_env_var  - Use environment variable for key logging."
  echo "   --ossl_disable_read_ahead - Disable read ahead by default."
  echo "   --ossl_single_read - Build with 1K buffer and single read."
  echo "   --enforce_cert_sig_algo - Enforce certificate signature check when validating peer certificate chain."
  echo "   --ssl_client_example_aesgcm - Enable only AES-GCM ciphers on SSL Client Example."
  echo "   --ssl_interop_test - Build ssl example with interop test updates."
  echo "   --ssl_interop_psk_test - Build ssl client example with interop PSK test updates."
  echo "   --ssl_interop_ex_psk_test - Build ssl client example with interop external PSK test updates."
  echo "   --ssl_interop_ticket_test - Build ssl client example with interop ticket and heartbeat test updates."
  echo "   --ssl_interop_sessionid_test - Build ssl client example with interop session ID test updates."
  echo "   --dtls_interop_test - Build dtls example with interop test updates."
  echo "   --dtls_interop_rehandshake_test - Build dtls example with interop rehandshake test updates."
  echo "   --cvc               - Enable support for Card Verifiable Certificates."
  echo "   --client-cert-cb    - Enable client cert callback."
  echo "   --graceful_shutdown - Shutdown the server or client example gracefully."
  echo "   --post_client_auth  - Enable Post Client Authentication example."
  echo "   --pkcs12            - Build server with PKCS12 support."
  echo "   --disable-weak-ciphers - Build ssl server example with ssl weak ciphers disabled."
  echo "   --ssl-example-smart-card - Build ssl server example with ssl smart card."
  echo "   --enable-no-cipher-match - Build DTLS server for no cipher match condition to stop the timer."
  echo "     ssl_server      - Build the SSl Server."
  echo "     ssl_server_async - Build the SSl Async Server."
  echo "     ssl_client      - Build the SSL Client."
  echo "     ssl_client_async - Build the SSL Async Client."
  echo "     dtls_server     - Build the DTLS Server."
  echo "     dtls_client     - Build the DTLS Client."
  echo "     nanossl             - Build the nanossl library."
  echo "     nanodtls_client     - Build the nanodtls Client."
  echo "     nanodtls_server     - Build the nanodtls Server."
  echo "     openssl_shim_lib    - Build the openssl-shim library."
  echo "   --cmake-opt       - Use this parameter to pass extra CMAKE parameters."
  echo "                        exa: --cmake-opt -D<MACRO>=<VALUE>"
  echo "     <MAKETARGETS>       - Make targets to build. ('all' is default)"
  echo ""
  exit -1
}

# Place us in the dir of this script
CURR_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
MSS_DIR=$CURR_DIR/../..
cd $CURR_DIR

unamestr=`uname`
printf "\n\nBuilding ${PROJECT_NAME}.\n\n\n"

if [[ "$unamestr" == 'Darwin' ]]; then
    SHARED_LIB_NAME=${PROJECT_NAME}.dylib
else
    SHARED_LIB_NAME=${PROJECT_NAME}.so
fi

is_static_lib=0
is_tap_enabled=0
is_tap_remote_enabled=0
is_build_nanossl_enabled=0
is_build_ssl_aps_enabled=0
is_build_openssl_shim_aps_enabled=0
is_tpm12_enabled=0
is_clean_build=0
is_32bit_build=0
is_64bit_build=0

BUILD_MONOLITHIC=0
BUILD_OPTIONS=
BUILD_TYPE=Release
BUILD_TGT=
ADD_ARGS=
CLEAN_LIBS_ARGS=
INV_OPT=0
TARGET_PLATFORM=
OQS_BUILD=0
EXPORT_BUILD=0

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
        --disable-tls13)
            echo "Building with TLS 1.3 disabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TLS13=OFF"
            ;;
        --disable-psk)
            echo "Building with TLS 1.3 PSK disabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TLS13_PSK=OFF"
            ;;
        --disable-0rtt)
            echo "Building with TLS 1.3 0-RTT disabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TLS13_0RTT=OFF"
            ;;
        --disable-dual-mode-api)
            echo "Building without dual mode APIs..."
            BUILD_OPTIONS+=" -DCM_DISABLE_DUAL_MODE_API=ON"
            ;;
        --disable-server-async)
            echo "Building without server async APIs..."
            BUILD_OPTIONS+=" -DCM_DISABLE_SERVER_ASYNC_API=ON"
            ;;
        --disable-client-async)
            echo "Building without client async APIs..."
            BUILD_OPTIONS+=" -DCM_DISABLE_CLIENT_ASYNC_API=ON"
            ;;
        --disable-server)
            echo "Building without server APIs..."
            BUILD_OPTIONS+=" -DCM_DISABLE_SERVER_API=ON"
            ;;
        --disable-ciphersuite-select)
            echo "Building without ciphersuite select APIs"
            BUILD_OPTIONS+=" -DCM_DISABLE_CIPHERSUITE_SELECT=ON"
            ;;
        --disable-key-expansion)
            echo "Building without SSL key expansion"
            BUILD_OPTIONS+=" -DCM_DISABLE_SSL_KEY_EXPANSION=ON"
            ;;
        --psk)
            echo "Build with PSK support for TLS 1.2 and below...";
            BUILD_OPTIONS+=" -DCM_ENABLE_PSK=ON"
            ;;
        --suiteb)
            echo "suiteb is always enabled (legacy --suiteb flag ignored)...";
            ;;
        --ipv6)
            echo "Building with IPV6 enabled ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_IPV6=ON"
            ;;
        --oqs)
            OQS_BUILD=1;
            ;;
        --pqc)
            echo "PQC is enabled by default (legacy --pqc flag ignored)...";
            ;;
        --disable-pqc)
            echo "Building with pqc disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_PQC=ON";
            ;;
        --pqc-composite)
            echo "Building with pqc composite...";
            BUILD_OPTIONS+=" -DCM_ENABLE_PQC_COMPOSITE=ON";
            ;;
        --nil-cipher)
            echo "Building with Nil Cipher enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_NIL=ON"
            ;;
        --tap-off)
            ;;
        --tap)
            echo "Building with tap ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP=ON -DCM_ENABLE_NANOSSL_TAP=ON"
            ;;
        --tap-local)
            echo "Building with tap local...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP=ON -DCM_ENABLE_TAP_LOCAL=ON"
            ;;
        --tap-remote)
            echo "Building with tap remote...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP=ON -DCM_ENABLE_TAP_REMOTE=ON"
            ;;
        --tap-remote-tcp)
            echo "Building with tap remote tcp...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP=ON -DCM_ENABLE_TAP_REMOTE_TCP=ON"
            ;;
        --tap-extern)
            echo "Building with tap extern...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP_EXTERN=ON"
            ;;
        --tap-deferred-unload)
            echo "Building with tap deferred unload...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TAP_DEFER_UNLOADKEY=ON"
            ;;
        --proxy)
            echo "Building with handlers for ssl proxy support"
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL_PROXY_CONNECT=ON"
            ;;
        --dtls)
            echo "Building with dtls...";
            BUILD_OPTIONS+=" -DCM_ENABLE_DTLS=ON"
            ;;
        --srtp)
            echo "Building with srtp dtls...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SRTP=ON"
            ;;
        --mbed-path)
            shift
            ;;
        --mauth)
            echo "Building with mutual authentication...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL_MAUTH_SUPPORT=ON"
            ;;
        --pss-auto-recover)
            echo "Building with PSS auto recover...";
            BUILD_OPTIONS+=" -DCM_ENABLE_PSS_AUTO_RECOVER=ON"
            ;;
        --ossl-tls-unique)
            echo "Building with additional TLS unique support for OpenSSL shim/connector...";
            BUILD_OPTIONS+=" -DCM_ENABLE_OSSL_TLS_UNIQUE=ON"
            ;;
        --openssl_load_algos)
            echo "Build option to load all algorithms";
            BUILD_OPTIONS+=" -DCM_ENABLE_OSSL_LOAD_ALGOS=ON"
            ;;
        --osslc_thread_safe)
            echo "Build with thread safe handling for OpenSSL connector client"
            BUILD_OPTIONS+=" -DCM_ENABLE_OSSLC_THREAD_SAFE=ON"
            ;;
        --export)
            echo "Building Export Edition library...";
            BUILD_OPTIONS+=" -DCM_ENABLE_EXPORT_ED=ON"
            EXPORT_BUILD=1
            ;;
        --self_signed)
            echo "Building with self signed cert...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL_SELF_SIGNED_CERT=ON"
            ;;
        --non_trusted)
            echo "Building with non trusted cert...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL_NONTRUSTED_CERT=ON"
            ;;
        --cert_status_override)
            echo "Building with certificate status override...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL_CERT_STATUS_OVERRIDE=ON"
            ;;
        --force_cert_chain)
            echo "Building with force cert chain...";
            BUILD_OPTIONS+=" -DCM_ENABLE_OSSL_FORCE_CERT_CHAIN=ON"
            ;;
        --ocsp)
            echo "Building with OCSP...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL_OCSP=ON"
            ;;
        --rsa_8k)
            echo "Building with RSA 8K...";
            BUILD_OPTIONS+=" -DCM_ENABLE_RSA_8K=ON"
            ;;
        --gcc_profile)
            echo "Building with gcc profile...";
            BUILD_OPTIONS+=" -DCM_ENABLE_GCC_PROFILING=ON"
            ;;
        --fips)
            echo "Building with fips module...";
            BUILD_OPTIONS+=" -DCM_ENABLE_FIPS=ON"
            ;;
        --strict_dh)
            echo "Building with strict dh ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_STRICT_DH=ON"
            ;;
        --rsa1024)
            echo "Building with 1024 minimum RSA key sizes...";
            BUILD_OPTIONS+=" -DCM_ENABLE_RSA_1024_SUPPORT=ON"
            ;;
        --sha1)
            echo "Building with SHA-1 enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SHA1_SUPPORT=ON"
            ;;
        --dsa)
            echo "Building with DSA enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_DSA_SUPPORT=ON"
            ;;
        --tls12-fallback)
            echo "Building with TLS 1.2 fallback enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_TLS12_FALLBACK=ON"
            ;;
        --no-cryptointerface)
            echo "Building with crypto interface disabled ...";
            BUILD_OPTIONS+=" -DCM_DISABLE_CI=ON"
            ;;
        --disable_rsa)
            echo "Building with disable rsa...";
            BUILD_OPTIONS+=" -DCM_DISABLE_RSA_SUPPORT=ON"
            ;;
        --enable_des)
            echo "Building with DES enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_DES_SUPPORT=ON"
            ;;
        --enable_3des)
            echo "Building with 3DES enabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_3DES_SUPPORT=OFF"
            ;;
        --disable-cbc)
            echo "Building with disable CBC...";
            BUILD_OPTIONS+=" -DCM_DISABLE_CBC_SUPPORT=ON"
            ;;
        --disable_polychacha_tls12)
            echo "Building with disable polychacha for TLS 1.2"
            BUILD_OPTIONS+=" -DCM_DISABLE_POLYCHACHA_TLS12_SUPPORT=ON"
            ;;
        --disable_chacha20poly1305)
            echo "Building with ChaCha20-Poly1305 disabled"
            BUILD_OPTIONS+=" -DCM_DISABLE_CHACHA20POLY1305=ON"
            ;;
        --enable_ecp192)
            echo "Building with EC P-192 enabled..."
            BUILD_OPTIONS+=" -DCM_ENABLE_ECP192_SUPPORT=ON"
            ;;
        --disable-aes-ccm)
            echo "Building with AES-CCM disabled"
            BUILD_OPTIONS+=" -DCM_DISABLE_AES_CCM=ON"
            ;;
        --disable-weak-ciphers)
            echo "Building with weak ciphers disabled"
            BUILD_OPTIONS+=" -DCM_DISABLE_WEAK_CIPHERS=ON"
            ;;
        --aes-gcm-4k)
            echo "Building for AES-GCM 4k";
            BUILD_OPTIONS+=" -DCM_ENABLE_AES_GCM_4K=ON"
            ;;
        --aes-gcm-256b)
            echo "Building for AES-GCM 256b";
            BUILD_OPTIONS+=" -DCM_ENABLE_AES_GCM_256B=ON"
            ;;
        --dh_pub_pad)
            echo "Building with DH public key padding"
            BUILD_OPTIONS+=" -DCM_ENABLE_DH_PUB_PAD=ON"
            ;;
        --enable_eap_fast)
            echo "Building with eap fast enabled...";
            BUILD_OPTIONS+=" -DCM_ENABLE_EAP_FAST=ON"
            ;;
        --redefine)
            echo "Building with redefine ssl pem read ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL_PEM_R_BIO_REDEFINE=ON"
            ;;
        --rehandshake)
            echo "Building with rehandshake feature ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL_REHANDSHAKE=ON"
            ;;
        --anon-support)
            echo "Building with anonymous suite support ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL_ANON=ON"
            ;;
        --openssl_1_1_x)
            echo "(OBSOLETE) Building with openssl_1_1_x libs ...";
            INV_OPT=1
            ;;
        --openssl_3_0_7)
            echo "Building with openssl_3_0_7 libs ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL_OPENSSL_LIB_3_0_7=ON"
            ;;
	--openssl_3_0_12)
            echo "Building with openssl_3_0_12 libs ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL_OPENSSL_LIB_3_0_12=ON"
            ;;
        --openssl_1_1_1)
            echo "(OBSOLETE) Building with openssl_1_1_1 libs ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL_OPENSSL_LIB_1_1_1=ON"
            ;;
        --openssl_1_1_1f)
            echo "(OBSOLETE) Building with openssl_1_1_1f libs ...";
            INV_OPT=1
            ;;
        --openssl_1_1_1i)
            echo "Building with openssl_1_1_1i libs ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL_OPENSSL_LIB_1_1_1I=ON"
            ;;
        --openssl_1_1_1k)
            echo "Building with openssl_1_1_1k libs ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL_OPENSSL_LIB_1_1_1K=ON"
            ;;
        --openssl_1_0_2u)
            echo "(OBSOLETE) Building with openssl_1_0_2u libs ...";
            INV_OPT=1
            ;;
        --openssl_1_0_2t)
            echo "(OBSOLETE) Building with openssl_1_0_2t libs ...";
            INV_OPT=1
            ;;
        --openssl_1_0_2n)
            echo "(OBSOLETE) Building with openssl_1_0_2n libs ...";
            INV_OPT=1
            ;;
        --openssl_1_0_2j)
            echo "(OBSOLETE) Building with openssl_1_0_2j libs ...";
            INV_OPT=1
            ;;
        --openssl_1_0_2p)
            echo "(OBSOLETE) Building with openssl_1_0_2p libs ...";
            INV_OPT=1
            ;;
        --extended-key)
            echo "Building with extended key usage feature ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL_EXTENDED_KEYUSAGE=ON"
            ;;
        --disable-servername-validation)
            echo "Building with no server name check ...";
            BUILD_OPTIONS+=" -DCM_DISABLE_SSL_SERVER_NAME=ON"
            ;;
        --disable-client-commonname-validation)
            echo "Building with no client common name verification ...";
            BUILD_OPTIONS+=" -DCM_DISABLE_SSL_CLIENT_COMMON_NAME_VALIDATION=ON"
            ;;
        --defer-encoding-client-cert-auth)
            echo "Building with deferred encoding ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_DEFER_CLIENT_AUTH=ON"
            ;;
        --disable_ossl_default_trust_certs)
            echo "Building with disable default trust certs...";
            BUILD_OPTIONS+=" -DCM_DISABLE_OSSL_DEFAULT_TRUST_CERTS=ON"
            ;;
        --version-logging)
            echo "Building with version_logging ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_VERSION_LOGGING=ON"
            ;;
        --redirect-log)
            echo "Building with redirect-log...";
            BUILD_OPTIONS+=" -DCM_ENABLE_LOGGING_REDIRECT=ON"
            ;;
        --ossl_log)
            echo "Building with ossl_log ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_OSSL_LOG=ON"
            ;;
        --tpm12)
            ;;
        --toolchain)
            shift
            TARGET_PLATFORM=$(get_platform "${1}") || INV_OPT=1
            XC_BIN_PATH=$(get_sysroot_bin "${1}") || INV_OPT=1
            export PATH=${XC_BIN_PATH}:$PATH
            ;;
        --clean)
            echo "Clean build";
            is_clean_build=1;
            ;;
        --srp)
            echo "Building with SRP";
            BUILD_OPTIONS+="    -DCM_ENABLE_SSL_SRP=ON";
            ;;
        --monolithic)
            echo "Building as monolithic...";
            BUILD_OPTIONS+=" -DCM_ENABLE_MONOLITHIC_BUILD=ON"
            BUILD_MONOLITHIC=1
            ;;
        --nanossl-common)
            echo "Linking to common nanossl.so library...";
            BUILD_OPTIONS+=" -DCM_ENABLE_COMMON_LINK=ON"
            ;;
        --openssl_shim)
            echo "Building with openssl_shim...";
            BUILD_OPTIONS+=" -DCM_ENABLE_OPENSSL_SHIM=ON"
            is_build_ssl_aps_enabled=1;
            ;;
        --ossl_multipacket_read)
            echo "Building with ossl multipacket read...";
            BUILD_OPTIONS+=" -DCM_ENABLE_OSSL_MULTIPACKET_READ=ON"
            ;;
        --ossl_multipacket_bio_retry)
            echo "Building with ossl multipacket bio retry...";
            BUILD_OPTIONS+=" -DCM_ENABLE_OSSL_MULTIPACKET_BIO_RETRY=ON"
            ;;
        --disable_peek_error)
            echo "Building with peer error disabled...";
            BUILD_OPTIONS+=" -DCM_DISABLE_PEER_ERROR=ON"
            ;;
        --enable_ticket_tls12)
            echo "Building with server side session ticket handling...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SESSION_TICKET_RFC_5077=ON"
            ;;
        --enable_heartbeat)
            echo "Building with heartbeat protocol handling...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL_HEARTBEAT_RFC_6520=ON"
            ;;
        --enable_extended_master_secret)
            echo "Building with extended master secret support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL_EXTENDED_MASTERSECRET_RFC_7627=ON"
            ;;
        --enable_session_id)
            echo "Building with session ID support...";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL_SESSION_CACHE=ON"
            ;;
        --ossl_rx_buf_8k)
            echo "Building with 8K RX buffer for OpenSSL shim...";
            BUILD_OPTIONS+=" -DCM_ENABLE_OSSL_RX_BUF_8K=ON"
            ;;
        --ossl_rx_buf_4k)
            echo "Building with 4K RX buffer for OpenSSL shim...";
            BUILD_OPTIONS+=" -DCM_ENABLE_OSSL_RX_BUF_4K=ON"
            ;;
        --ossl_rx_buf_2k)
            echo "Building with 2K RX buffer for OpenSSL shim...";
            BUILD_OPTIONS+=" -DCM_ENABLE_OSSL_RX_BUF_2K=ON"
            ;;
        --ossl_rx_buf_1k)
            echo "Building with 1K RX buffer for OpenSSL shim...";
            BUILD_OPTIONS+=" -DCM_ENABLE_OSSL_RX_BUF_1K=ON"
            ;;
        --opensslld_override)
            echo "Building with ld override option...";
            BUILD_OPTIONS+=" -DCM_ENABLE_OSSL_LD_OVERRIDE=ON"
            ;;
        --keylog)
            echo "Building with key logging enabled....";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL_KEYLOG_FILE=ON"
            ;;
        --keylog_env_var)
            echo "Building with key logging environment variable enabled....";
            BUILD_OPTIONS+=" -DCM_ENABLE_SSL_KEYLOG_ENV_VAR=ON"
            ;;
        --ossl_disable_read_ahead)
            echo "Building with read ahead disabled by default...";
            BUILD_OPTIONS+=" -DCM_DISABLE_OSSL_READ_AHEAD=ON"
            ;;
        --ossl_single_read)
            echo "Building with read ahead disabled by default...";
            BUILD_OPTIONS+=" -DCM_DISABLE_OSSL_READ_AHEAD=ON -DCM_ENABLE_OSSL_RX_BUF_1K=ON"
            ;;
        --enforce_cert_sig_algo)
            echo "Building with certificate signature algorithm checks enabled"
            BUILD_OPTIONS+=" -DCM_ENABLE_ENFORCE_CERT_SIG_ALGO=ON"
            ;;
        --ssl_client_example_aesgcm)
            echo "Building with enable AES-GCM ciphers only on SSL Client Example...";
            BUILD_OPTIONS+=" -DCM_ENABLE_MOCANA_EXAMPLE_AESGCM_CIPHERS_ONLY=ON"
            ;;
        --ssl_interop_test)
            echo "Building ssl server example with interop test updates ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_MOCANA_EXAMPLE_INTEROP_TEST=ON"
            ;;
        --ssl_interop_psk_test)
            echo "Building ssl example with interop PSK test updates ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_MOCANA_EXAMPLE_INTEROP_PSK_TEST=ON"
            ;;
        --ssl_interop_ex_psk_test)
            echo "Building ssl server example with interop external PSK test updates ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_MOCANA_EXAMPLE_INTEROP_EXTERNAL_PSK_TEST=ON"
            ;;
        --ssl_interop_ticket_test)
            echo "Building ssl server example with interop ticket and heartbeat test updates ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_MOCANA_EXAMPLE_INTEROP_TICKET_TEST=ON"
            ;;
        --ssl_interop_sessionid_test)
            echo "Building ssl server example with interop sessionid test updates ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_MOCANA_EXAMPLE_INTEROP_SESSIONID_TEST=ON"
            ;;
        --dtls_interop_test)
            echo "Building dtls example with interop test updates ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_MOCANA_DTLS_EXAMPLE_INTEROP_TEST=ON"
            ;;
        --dtls_interop_rehandshake_test )
            echo "Building dtls example with interop rehandshake test updates ...";
            BUILD_OPTIONS+=" -DCM_ENABLE_MOCANA_DTLS_EXAMPLE_INTEROP_REHANDSHAKE_TEST=ON"
            ;;
        --data-protect)
            echo "Building with data protect..."
            BUILD_OPTIONS+=" -DCM_ENABLE_MOCANA_DATA_PROTECTION=ON"
            ;;
        --cvc)
            echo "Building with CVC..."
            BUILD_OPTIONS+=" -DCM_ENABLE_CVC=ON"
            ;;
        --client-cert-cb)
            echo "Building with client certificate callback..."
            BUILD_OPTIONS+=" -DCM_ENABLE_CLIENT_CERT_CB=ON"
            ;;
        --graceful_shutdown)
            echo "Building with server or client example shutdown gracefully..."
            BUILD_OPTIONS+=" -DCM_ENABLE_MOCANA_SSL_EXAMPLE_GRACEFUL_SHUTDOWN=ON"
            ;;
        --post_client_auth)
            echo "Enable TLSv1.3 post client authentication example..."
            BUILD_OPTIONS+=" -DCM_ENABLE_MOCANA_SSL_POST_CLIENT_AUTH_EXAMPLE=ON"
            ;;
        --pkcs12)
            echo "Building with server example using PKCS12 cert..."
            BUILD_OPTIONS+=" -DCM_ENABLE_MOCANA_PKCS12_CERT=ON"
            ;;
        --sp800-135)
            echo "Building for testing SP800-135..."
            BUILD_OPTIONS+=" -DCM_ENABLE_SP800_135=ON"
            ;;
        --ssl-example-smart-card)
            echo "Building with ssl example smart card..."
            BUILD_OPTIONS+=" -DCM_ENABLE_MOCANA_SSL_EXAMPLE_SMART_CARD=ON"
            ;;
        --enable-no-cipher-match)
            echo "Building DTLS server for no cipher match to stop the timer..."
            BUILD_OPTIONS+=" -DCM_ENABLE_ERR_SSL_NO_CIPHER_MATCH=ON"
            ;;
        openssl_shim_lib)
            echo "Build the openssl_shim library...";
            BUILD_OPTIONS+=" -DCM_BUILD_OPENSSL_SHIM_LIB=ON"
            ADD_ARGS+=" openssl_shim"
            CLEAN_LIBS_ARGS+=" libopenssl_shim"
            is_build_openssl_shim_aps_enabled=1;
            ;;
        nanossl)
            echo "Build the nanossl library ...";
            BUILD_OPTIONS+=" -DCM_BUILD_NANOSSL_LIB=ON"
            ADD_ARGS+=" nanossl"
            CLEAN_LIBS_ARGS+=" libnanossl"
            is_build_nanossl_enabled=1;
            ;;
        nanodtls_client)
            echo "Build the nanodtls client library ...";
            BUILD_OPTIONS+=" -DCM_BUILD_NANO_DTLS_CLIENT=ON"
            ADD_ARGS+=" nanodtls_client"
            CLEAN_LIBS_ARGS+=" libnanodtls_client"
            ;;
        nanodtls_server)
            echo "Build the nanodtls server library ...";
            BUILD_OPTIONS+=" -DCM_BUILD_NANO_DTLS_SERVER=ON"
            ADD_ARGS+=" nanodtls_server"
            CLEAN_LIBS_ARGS+=" libnanodtls_server"
            ;;
        ssl_client)
            echo "Build the ssl_client application...";
            BUILD_OPTIONS+=" -DCM_BUILD_SSL_CLIENT=ON"
            ADD_ARGS+=" ssl_client"
            CLEAN_LIBS_ARGS+=" ssl_client"
            is_build_ssl_aps_enabled=1;
            ;;
        ssl_client_async)
            echo "Build the ssl_client_async application...";
            BUILD_OPTIONS+=" -DCM_BUILD_SSL_CLIENT_ASYNC=ON"
            ADD_ARGS+=" ssl_client_async"
            CLEAN_LIBS_ARGS+=" ssl_client_async"
            is_build_ssl_aps_enabled=1;
            ;;
        ssl_client_async_external_psk)
            echo "Build the ssl_client_async_external_psk application...";
            BUILD_OPTIONS+=" -DCM_BUILD_SSL_CLIENT_ASYNC_EXTERNAL_PSK=ON"
            ADD_ARGS+=" ssl_client_async_external_psk"
            CLEAN_LIBS_ARGS+=" ssl_client_async_external_psk"
            is_build_ssl_aps_enabled=1;
            ;;
        ssl_client_sp800_135)
            echo "Build the ssl_client for testing SP800-135...";
            BUILD_OPTIONS+=" -DCM_BUILD_SSL_CLIENT_SP800_135=ON"
            ADD_ARGS+=" ssl_client_sp800_135"
            CLEAN_LIBS_ARGS+=" ssl_client_sp800_135"
            is_build_ssl_aps_enabled=1;
            ;;
        ssl_server)
            echo "Build the ssl_server application...";
            BUILD_OPTIONS+=" -DCM_BUILD_SSL_SERVER=ON"
            ADD_ARGS+=" ssl_server"
            CLEAN_LIBS_ARGS+=" ssl_server"
            is_build_ssl_aps_enabled=1;
            ;;
        ssl_server_gw)
            echo "Build the ssl_server_gw application...";
            BUILD_OPTIONS+=" -DCM_BUILD_SSL_SERVER_GW=ON"
            ADD_ARGS+=" ssl_server_gw"
            CLEAN_LIBS_ARGS+=" ssl_server_gw"
            is_build_ssl_aps_enabled=1;
            ;;
        ssl_server_async)
            echo "Build the ssl_server_async application...";
            BUILD_OPTIONS+=" -DCM_BUILD_SSL_SERVER_ASYNC=ON"
            ADD_ARGS+=" ssl_server_async"
            CLEAN_LIBS_ARGS+=" ssl_server_async"
            is_build_ssl_aps_enabled=1;
            ;;
        ssl_server_async_external_psk)
            echo "Build the ssl_server_async_external_psk application...";
            BUILD_OPTIONS+=" -DCM_BUILD_SSL_SERVER_ASYNC_EXTERNAL_PSK=ON"
            ADD_ARGS+=" ssl_server_async_external_psk"
            CLEAN_LIBS_ARGS+=" ssl_server_async_external_psk"
            is_build_ssl_aps_enabled=1;
            ;;
        ssl_serialize_psk)
            echo "Build the ssl_serialize_psk application...";
            BUILD_OPTIONS+=" -DCM_BUILD_SSL_SERIALIZE_PSK=ON"
            ADD_ARGS+=" ssl_serialize_psk"
            CLEAN_LIBS_ARGS+=" ssl_serialize_psk"
            is_build_ssl_aps_enabled=1;
            ;;
        dtls_client)
            echo "Build the dtls_client application...";
            BUILD_OPTIONS+=" -DCM_BUILD_DTLS_CLIENT=ON"
            ADD_ARGS+=" dtls_client"
            CLEAN_LIBS_ARGS+=" dtls_client"
            ;;
        dtls_server)
            echo "Build the dtls_server application...";
            BUILD_OPTIONS+=" -DCM_BUILD_DTLS_SERVER=ON"
            ADD_ARGS+=" dtls_server"
            CLEAN_LIBS_ARGS+=" dtls_server"
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

#if [[ $is_build_nanossl_enabled -eq 1 ]] && [[ $is_build_ssl_aps_enabled -eq 1 ]]; then
#   echo "Error: Build the Either nanossl or SSL Applications only."
#   exit 1
#fi

if [ ! -d $CURR_DIR/build ]; then
    mkdir build
fi

if [ $is_clean_build -eq 1 ]; then
    echo "Calling: clean.sh..."
    . clean.sh "${CLEAN_LIBS_ARGS}"
    mkdir build
fi

cd $CURR_DIR/build
echo "Calling: ${TARGET_PLATFORM} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} CMakeLists.txt ../."

cmake ${TARGET_PLATFORM} \
      -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ${BUILD_OPTIONS} CMakeLists.txt ../.


echo "Calling: make ${BUILD_TGT}"
make ${BUILD_TGT}
