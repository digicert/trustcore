#!/usr/bin/env bash

set -e

######################
function show_usage
{
  echo ""
  echo "./build.sh [Options] "
  echo ""
  echo "   --gdb             - Build Debug version."
  echo "   --debug           - Build with Mocana logging enabled for specific build executable."
  echo "   --fips            - Build with FIPS enabled."
  echo "   --fips-700-compat - Build with backward compatibility with FIPS REL_700_U1 binary."
  echo "   --disable-pqc     - Build without PQC support."
  echo "   --custom-entropy  - Build with custom entropy."
  echo "   --force-entropy-example - Build with force entropy example."
  echo "   --dtls            - Build with DTLS support."
  echo "   --redefine        - Redefine the PEM_read_bio_PrivateKey function."
  echo "   --disable-tls13   - Disable with TLS 1.3."
  echo "   --disable-psk     - Build with TLS 1.3 PSK disabled."
  echo "   --disable-0rtt    - Build with TLS 1.3 0-RTT disabled."
  echo "   --openssl_1_0_2j  - (OBSOLETE) Build with openssl 1.0.2j."
  echo "   --openssl_1_0_2n  - (OBSOLETE) Build with openssl 1.0.2n."
  echo "   --openssl_1_0_2p  - (OBSOLETE) Build with openssl 1.0.2p."
  echo "   --openssl_1_0_2t  - (OBSOLETE) Build with openssl 1.0.2t."
  echo "   --openssl_1_0_2u  - (OBSOLETE) Build with openssl 1.0.2u."
  echo "   --openssl_1_1_x   - (OBSOLETE) Build with openssl 1.1.0x."
  echo "   --openssl_1_1_1   - (OBSOLETE) Build with openssl 1.1.1."
  echo "   --openssl_1_1_1f  - (OBSOLETE) Build with openssl 1.1.1f."
  echo "   --openssl_1_1_1i  - Build with openssl 1.1.1i."
  echo "   --openssl_1_1_1k  - Build with openssl 1.1.1k."
  echo "   --openssl_3_0_7   - Build with openssl 3.0.7."
  echo "   --openssl_3_0_12  - Build with openssl 3.0.12."
  echo "   --rsa1024         - Build with RSA 1024 support."
  echo "   --rsa_8k          - Build with RSA 8K support."
  echo "   --disable-rc5     - Build with RC5 disabled."
  echo "   --sha1            - Build with support for SHA1."
  echo "   --enable_ecp192   - Build with support for EC P-192."
  echo "   --ocsp            - Build with OCSP support."
  echo "   --ocsp_cert       - Build with OCSP Cert API support."
  echo "   --enable_ticket_tls12 - Build with Session Ticket feature"
  echo "   --enable_extended_master_secret - Build with support for Extended Master Secret"
  echo "   --disable-servername-validation - Server flag to ignore the certificate common name."
  echo "   --disable-client-commonname-validation - Client flag to ignore the certificate common name check."
  echo "   --defer-encoding-client-cert-auth - Defer encoding of client certificate authentication digest message"
  echo "   --dsa             - Build NanoSSL with the DSA support"
  echo "   --enable_3des     - Enable 3DES cipher support"
  echo "   --dh_pub_pad      - Pad DH public keys"
  echo "   --strict_dh       - Enable strict check for DH group in compliance with FIPS 140-3"
  echo "   --openssl_load_algos - Build option to load all algorithms"
  echo "   --ossl_multipacket_read - Enable reading of multiple records in a loop."
  echo "   --ossl_multipacket_bio_retry - Enable read until data is recieved."
  echo "   --ossl_log        - Enable logging in OpenSSL Connector."
  echo "   --osslc_thread_safe - Build with thread safe handling for OpenSSL connector client."
  echo "   --ossl_rx_buf_8k  - Build with 8K receive buffer."
  echo "   --ossl_rx_buf_4k  - Build with 4K receive buffer."
  echo "   --ossl_rx_buf_2k  - Build with 2K receive buffer."
  echo "   --self_signed     - Enable self signed cert"
  echo "   --non_trusted     - Enable non trust cert"
  echo "   --cert_status_override   - Override the OpenSSL shim certificate status if NanoSSL certificate validation is successful."
  echo "   --force_cert_chain - Enable loading of full cert chain along with the leaf cert"
  echo "   --rehandshake     - Enable rehandshake"
  echo "   --srp             - Enable SRP(Secure Remote Password)."
  echo "   --disable_polychacha_tls12 - Diable CHACHA20-POLY1305 ciphers for TLS 1.2 and lower versions"
  echo "   --extended-key    - Enable extended key usage"
  echo "   --disable_ossl_default_trust_certs     - Disable loading of default CA Certs"
  echo "   --disable_peek_error - Building with peer error disabled."
  echo "   --disable-strict-ca-check - Disable strict CA check. "
  echo "   --disable_cert_ext_check - Disable certificate extension check."
  echo "   --keylog          - Building with key logging enabled."
  echo "   --ossl_disable_read_ahead - Disable read ahead by default."
  echo "   --ossl_single_read - Build with 1K receive buffer and read ahead disabled."
  echo "   --opensslld_override - Build with OpenSSL LD override file."
  echo "   --version-logging - Enable version_logging"
  echo "   --redirect-log    - Redirect printf logs to stderr in OpenSSL Connector."
  echo "   --ossl_config_cmd - Specify configuration command that should be run."
  echo "   --ipv6            - Build with IPV6 enabled."
  echo "   --disable-tcp-init      - Disable Mocana TCP init."
  echo "   --disable-override-digiprov-status - Disable overriding Digi provider status."
  echo "   --static          - Build as static library."
  echo "   --toolchain <toolchain> - Cross compile build using the specified toolchain. This toolchain"
  echo "                             must have the appropriate handling in MocPlatform.cmake"
  echo ""
  exit 1
}

BUILD_OPTIONS=""
DEBUG_OPTIONS=""
FIPS_OPTION=""
FIPS_700_COMPAT_OPTION=""
FIPS_MAKE_OPTION=""
FIPS_MAKE30_OPTION=""
CUSTOM_ENTROPY_OPTION=""
FORCE_ENTROPY_EXAMPLE_OPTION=""
DTLS_OPTION=""
DTLS_SRTP_OPTION=""
REDEFINE_OPTION=""
REDEFINE_LIB_OPTION=""
TLS13_OPTION=""
# Default to openssl-3.0.12 version
OPENSSL_OPTION="--openssl_3_0_12"
OPENSSL_VER="3.0.12"
OPENSSL_LIB_OPTION="openssl-3.0.12"
SAMPLE_CRYPTOINTERFACE_OPTION="cryptointerface=true"
OSSL_VER="3"
OPENSSL_GDB_OPTIONS=""
OPENSSL_ENGINE_TYPE=""
INV_OPT=0
DYN_ENG=0
RSA1024_OPTION=""
RSA8K_OPTION=""
SHA1_OPTION=""
RC5_DISABLE_OPTION=""
RC5_DISABLE_CRYPTO_OPTION=""
OSSL3_RC5_OPTION="enable-rc5"
OCSP_OPTION=""
OCSP_CERT_OPTION=""
URI_OPTION=""
STATIC_OPTION=""
NANOSSL_OSSL_OPTIONS=""
SESSION_TICKET_OPTION=""
SAMPLE_SESSION_TICKET_OPTION=""
DISABLE_STRICT_CA_CHECK_OPTION=""
DISABLE_CERT_EXT_CHECK_OPTION=""
OSSL_CONFIG_CMD=""
SAMPLE_GDB_OPTION=""
IPV6_OPTIONS=""
DISABLE_TCP_INIT_OPTIONS=""
TOOLCHAIN=""
STRICT_DH_OPTION=""
STRICT_DH_OPTION_OSSL=""
STRICT_DH_OPTION_OSSL3=""
OSSL_EXTRA_OPTS=""
DISABLE_PQC_OPT=""
OSSL_PQC_OPTION=" enable-mocana-pqc"
BUILD_FOR_OSI=0

while test $# -gt 0
do
    case "$1" in
        --gdb)
            echo "Enabling Debug build...";
            BUILD_OPTIONS+=" $1"
            OPENSSL_GDB_OPTIONS+="-d"
            SAMPLE_GDB_OPTION="gdb=true"
            ;;
        --debug)
            echo "Building with Debug logs enabled...";
            BUILD_OPTIONS+=" $1"
            DEBUG_OPTIONS="debug=true"
            ;;
        --fips)
            echo "Building with FIPS enabled..."
            FIPS_OPTION=" $1"
            FIPS_MAKE_OPTION=" fips=true"
            FIPS_MAKE30_OPTION="enable-mocana-fips"
            DISABLE_PQC_OPT=" --disable-pqc"
            OSSL_PQC_OPTION=""
            ;;
        --fips-700-compat)
            echo "Build with backward compatibility with FIPS REL_700_U1 binary."
            FIPS_700_COMPAT_OPTION=" $1"
            ;;
        --disable-pqc)
            echo "Building without PQC support"
            DISABLE_PQC_OPT=" --disable-pqc"
            OSSL_PQC_OPTION=""
            ;;
        --custom-entropy)
            echo "Build with custom entropy";
            CUSTOM_ENTROPY_OPTION=" $1"
            ;;
        --force-entropy-example)
            echo "Build with force entropy example";
            FORCE_ENTROPY_EXAMPLE_OPTION=" --force-entropy"
            ;;
        --dtls)
            echo "Building with DTLS enabled..."
            DTLS_OPTION=" $1"
            ;;
        --srtp)
            echo "Building with DTLS SRTP enabled..."
            DTLS_SRTP_OPTION=" $1"
            ;;
        --redefine)
            echo "Redefine the PEM_read_bio_PrivateKey function...";
            REDEFINE_OPTION=" $1"
            REDEFINE_LIB_OPTION="redefine=true"
            ;;
        --disable-tls13)
            echo "Building with TLS 1.3 disabled..."
            TLS13_OPTION+=" $1"
            ;;
        --disable-psk)
            echo "Building with TLS 1.3 PSK disabled..."
            TLS13_OPTION+=" $1"
            ;;
        --disable-0rtt)
            echo "Building with TLS 1.3 0-RTT disabled..."
            TLS13_OPTION+=" $1"
            ;;
        --openssl_1_1_x)
            echo "(OBSOLETE) Build with openssl 1.1.0x...";
            INV_OPT=1
            ;;
        --openssl_1_1_1)
            echo "(OBSOLETE) Build with openssl 1.1.1c...";
            INV_OPT=1
            ;;
        --openssl_1_1_1f)
            echo "(OBSOLETE) Build with openssl 1.1.1f...";
            INV_OPT=1
            ;;
        --openssl_1_1_1i)
            echo "Build with openssl 1.1.1i...";
            OPENSSL_OPTION=" $1"
            OPENSSL_LIB_OPTION="openssl-1.1.1i"
            OPENSSL_ENGINE_TYPE="enable-static-engine"
            OPENSSL_VER="1.1.1"
            SAMPLE_CRYPTOINTERFACE_OPTION=""
            OSSL_VER=""
            ;;
        --openssl_1_1_1k)
            echo "Build with openssl 1.1.1k...";
            OPENSSL_OPTION=" $1"
            OPENSSL_LIB_OPTION="openssl-1.1.1k"
            OPENSSL_ENGINE_TYPE="enable-static-engine"
            OPENSSL_VER="1.1.1"
            SAMPLE_CRYPTOINTERFACE_OPTION=""
            OSSL_VER=""
            ;;
        --openssl_1_0_2u)
            echo "(OBSOLETE) Build with openssl 1.0.2u...";
            INV_OPT=1
            ;;
        --openssl_1_0_2t)
            echo "(OBSOLETE) Build with openssl 1.0.2t...";
            INV_OPT=1
            ;;
        --openssl_1_0_2n)
            echo "(OBSOLETE) Build with openssl 1.0.2n...";
            INV_OPT=1
            ;;
        --openssl_1_0_2j)
            echo "(OBSOLETE) Build with openssl 1.0.2j...";
            INV_OPT=1
            ;;
        --openssl_1_0_2p)
            echo "(OBSOLETE) Build with openssl 1.0.2p...";
            INV_OPT=1
            ;;
        --openssl_3_0_7)
            echo "Build with openssl 3.0.7...";
            OPENSSL_OPTION=" $1"
            OPENSSL_LIB_OPTION="openssl-3.0.7"
            OPENSSL_ENGINE_TYPE=
            OPENSSL_VER="3.0.7"
            SAMPLE_CRYPTOINTERFACE_OPTION="cryptointerface=true"
            OSSL_VER="3"
            ;;
	--openssl_3_0_12)
	    echo "Build with openssl 3.0.12..."
            OPENSSL_OPTION=" $1"
            OPENSSL_LIB_OPTION="openssl-3.0.12"
            OPENSSL_ENGINE_TYPE=
            OPENSSL_VER="3.0.12"
            SAMPLE_CRYPTOINTERFACE_OPTION="cryptointerface=true"
            OSSL_VER="3"
            ;;
        --rsa1024)
            echo "Build with support for RSA 1024";
            RSA1024_OPTION=" $1"
            ;;
        --rsa_8k)
            echo "Build with support for RSA 8K";
            RSA8K_OPTION=" $1"
            ;;
        --sha1)
            echo "Build with support for SHA1";
            SHA1_OPTION=" $1"
            ;;
        --enable_ecp192)
            echo "Build with support for EC P-192";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --disable-rc5)
            echo "Build with RC5 disabled";
            RC5_DISABLE_CRYPTO_OPTION=" $1"
            RC5_DISABLE_OPTION="disable_rc5=true"
            OSSL3_RC5_OPTION=
            ;;
        --static)
            echo "Build static library..";
            STATIC_OPTION=" --libtype static "
            ;;
        --ocsp)
            echo "Build with OCSP support..";
            OCSP_OPTION=" $1"
            URI_OPTION=" --uri"
            ;;
        --ocsp_cert)
            echo "Build with OCSP Cert support..";
            OCSP_CERT_OPTION=" $1"
            ;;
        --disable-servername-validation)
            echo "Building with no server name check ...";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --disable-client-commonname-validation)
            echo "Building with no client common name verification ...";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --defer-encoding-client-cert-auth)
            echo "Building with deferred encoding ...";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --dsa)
            echo "Building with DSA enabled...";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --enable_3des)
            echo "Building with 3DES enabled...";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --dh_pub_pad)
            echo "Building with DH public padding...";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --strict_dh)
            echo "Building with strict DH...";
            STRICT_DH_OPTION+=" $1"
            STRICT_DH_OPTION_OSSL=" strict_dh=true"
            STRICT_DH_OPTION_OSSL3="enable-mocana-strict-dh"
            ;;
        --openssl_load_algos)
            echo "Build option to load all algorithms";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --ossl_multipacket_read)
            echo "Building with ossl multipacket read...";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --ossl_multipacket_bio_retry)
            echo "Building with ossl multipacket bio retry...";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --ossl_log)
            echo "Building with ossl_log ...";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --osslc_thread_safe)
            echo "Build with thread safe handling for OpenSSL connector client"
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --ossl_rx_buf_8k)
            echo "Building with 8K RX buffer for OpenSSL shim...";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --ossl_rx_buf_4k)
            echo "Building with 4K RX buffer for OpenSSL shim...";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --ossl_rx_buf_2k)
            echo "Building with 2K RX buffer for OpenSSL shim...";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --enable_ticket_tls12)
            echo "Build with support for Session Tickets";
            SESSION_TICKET_OPTION=" $1"
            SAMPLE_SESSION_TICKET_OPTION=" enable_ticket_tls12=true"
            ;;
        --enable_extended_master_secret)
            echo "Build with support for Extended Master Secret";
            NANOSSL_OSSL_OPTIONS=" $1"
            ;;
        --self_signed)
            echo "Building with self signed cert...";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --non_trusted)
            echo "Building with non trusted cert...";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --cert_status_override)
            echo "Building with certificate status override...";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --force_cert_chain)
            echo "Building with cert chain load";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --rehandshake)
            echo "Building with rehandshake feature ...";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --srp)
            echo "Building with SRP";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --disable_polychacha_tls12)
            echo "Building with disable polychacha for TLS 1.2"
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --extended-key)
            echo "Building with extended key usage feature ...";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --disable_peek_error)
            echo "Building with peer error disabled...";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --disable_ossl_default_trust_certs)
            echo "Building with disable default trust certs...";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --keylog)
            echo "Building with key logging enabled....";
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --disable-strict-ca-check)
            echo "Disable strict CA check...";
            DISABLE_STRICT_CA_CHECK_OPTION="$1"
            ;;
        --disable_cert_ext_check)
            echo "Disable certificate extension check..."
            DISABLE_CERT_EXT_CHECK_OPTION="$1"
            ;;
        --ossl_disable_read_ahead)
            echo "Disable read ahead by default..."
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --ossl_single_read)
            echo "Build with 1K receive buffer and read ahead disabled"
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --opensslld_override)
            echo "Building with OpenSSL LD override file"
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --version-logging)
            echo "Building with version_logging..."
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --redirect-log)
            echo "Building with redirect-log..."
            NANOSSL_OSSL_OPTIONS+=" $1"
            ;;
        --ossl_config_cmd)
            echo "Run the following config command: $2";
            OSSL_CONFIG_CMD="$2"
            shift
            ;;
        --ipv6)
            echo "Building with IPv6..."
            IPV6_OPTIONS=" $1"
            ;;
        --disable-tcp-init)
            echo "Disable Mocana TCP init..."
            DISABLE_TCP_INIT_OPTIONS=" $1"
            ;;
        --disable-override-digiprov-status)
            echo "Disable overriding Digi provider status..."
	    OSSL_EXTRA_OPTS+=" disable-mocana-override-digiprov-status"
            ;;
        --toolchain)
            echo "Building with toolchain: $2"
            TOOLCHAIN="$2"
            BUILD_OPTIONS+=" --toolchain ${TOOLCHAIN}"
            shift
            ;;
        --build-for-osi)
            echo "Enabling BUILD_FOR_OSI...";
            BUILD_OPTIONS+=" --build-for-osi"
            BUILD_FOR_OSI=1
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

if [ ${DYN_ENG} -eq 1 ]; then
  OPENSSL_ENGINE_TYPE=""
fi

if [ ! -z "${BUILD_OPTIONS}" ]; then
  echo "BUILD_OPTIONS=${BUILD_OPTIONS}"
  echo ""
fi

if [ ! -z "${FORCE_ENTROPY_EXAMPLE_OPTION}" ] && [ ! -z "${CUSTOM_ENTROPY_OPTION}" ]; then
    echo "Only one of custom-entropy of force-entropy-example should be used"
    exit
fi

if [ "$CM_ENV_ENABLE_LEGACY_FIPS" = "1" ]; then
    LEGACY_FIPS_DEFINE="-D__ENABLE_DIGICERT_FIPS_LEGACY_LIB__"
    echo "Building with legacy FIPS support enabled..."
else
    LEGACY_FIPS_DEFINE=""
fi

#echo "BUILD_OPTIONS=$BUILD_OPTIONS"
#echo "DEBUG_OPTIONS=$DEBUG_OPTIONS"
#echo "DTLS_OPTION=$DTLS_OPTION"

######################

SCRIPT_DIR=$( cd $(dirname $0) ; pwd -P )

export WORKSPACE="${SCRIPT_DIR}/../../.."

echo "WORKSPACE=${WORKSPACE}"
export MSS_DIR=${WORKSPACE}
export MSS_PROJECTS_DIR=${MSS_DIR}/projects

# Check if building for OSI
source ${MSS_DIR}/scripts/check_for_osi.sh
if [ ${OSI_BUILD} -eq 1 ] || [ ${BUILD_FOR_OSI} -eq 1 ]; then
    BIN_DIR="lib"
else
    BIN_DIR="bin"
fi

echo "***************************************************************"
echo "*** Cleaning binaries and libraries "
echo "***************************************************************"

for libs in ${MSS_DIR}/${BIN_DIR}/*.so; do
    if [[ ! "$libs" == *libmss.so ]] || [[ -z "$FIPS_OPTION" ]]; then
        rm -f $libs
    fi
done

rm -f ${MSS_DIR}/${BIN_DIR}/*.a
rm -f ${MSS_DIR}/bin_static/*.a
rm -f ${MSS_DIR}/thirdparty/${OPENSSL_LIB_OPTION}/sample/openssl_client_local
export LD_LIBRARY_PATH=

echo "***************************************************************"
echo "*** Building openssl shim version of CAP..."
echo "***************************************************************"
for pass in first second
do

    cd ${MSS_PROJECTS_DIR}/platform && ./build.sh $BUILD_OPTIONS $FIPS_OPTION $STATIC_OPTION $IPV6_OPTIONS
    cd ${MSS_PROJECTS_DIR}/common && ./build.sh $BUILD_OPTIONS $FIPS_OPTION $URI_OPTION $STATIC_OPTION $IPV6_OPTIONS
    cd ${MSS_PROJECTS_DIR}/asn1 && ./build.sh $BUILD_OPTIONS $DISABLE_PQC_OPT $STATIC_OPTION $IPV6_OPTIONS
    cd ${MSS_PROJECTS_DIR}/initialize && ./build.sh $BUILD_OPTIONS $CUSTOM_ENTROPY_OPTION $FORCE_ENTROPY_EXAMPLE_OPTION $STATIC_OPTION $IPV6_OPTIONS $DISABLE_TCP_INIT_OPTIONS
    cd ${MSS_PROJECTS_DIR}/nanocap && ./build.sh $BUILD_OPTIONS $STATIC_OPTION $IPV6_OPTIONS
    cd ${MSS_PROJECTS_DIR}/crypto && ./build.sh $BUILD_OPTIONS $FIPS_OPTION $FIPS_700_COMPAT_OPTION $DISABLE_PQC_OPT --ssl --openssl${OSSL_VER} $RC5_DISABLE_CRYPTO_OPTION $STATIC_OPTION $RSA8K_OPTION $IPV6_OPTIONS
    cd ${MSS_PROJECTS_DIR}/nanocert && ./build.sh $BUILD_OPTIONS $FIPS_OPTION $DISABLE_PQC_OPT --openssl $DISABLE_STRICT_CA_CHECK_OPTION $DISABLE_CERT_EXT_CHECK_OPTION $OCSP_OPTION $OCSP_CERT_OPTION $STATIC_OPTION $RSA8K_OPTION $IPV6_OPTIONS
    cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh --clean $BUILD_OPTIONS $FIPS_OPTION $DISABLE_PQC_OPT --openssl_shim $DTLS_OPTION $DTLS_SRTP_OPTION $OPENSSL_OPTION $RSA1024_OPTION $SHA1_OPTION $TLS13_OPTION $OCSP_OPTION $SESSION_TICKET_OPTION $STATIC_OPTION $NANOSSL_OSSL_OPTIONS $STRICT_DH_OPTION $RSA8K_OPTION $IPV6_OPTIONS nanossl

    if [ "$pass" == "second" ]; then
        cd ${MSS_DIR}/thirdparty/${OPENSSL_LIB_OPTION}
        if [[ "$OSSL_CONFIG_CMD" == "" ]]; then
            if [[ "$OPENSSL_VER" == "3.0.7" ]] || [[ "$OPENSSL_VER" == "3.0.12" ]]; then
                ./Configure $OSSL3_RC5_OPTION $STRICT_DH_OPTION_OSSL3 enable-mocana-cryptointerface ${FIPS_MAKE30_OPTION} ${OPENSSL_GDB_OPTIONS} -D__ENABLE_DIGICERT_OSSL_V3_TEST__ enable-moc-ossl-v3-test ${OSSL_EXTRA_OPTS} ${OSSL_PQC_OPTION} ${LEGACY_FIPS_DEFINE}
            else
                ./config $OPENSSL_GDB_OPTIONS $OPENSSL_ENGINE_TYPE
                makefile="${MSS_DIR}/thirdparty/${OPENSSL_LIB_OPTION}/engines/mocana/Makefile"
                if [ -f "$makefile" ] && [[ -n "$LEGACY_FIPS_DEFINE" ]]; then
                    grep -q "__ENABLE_DIGICERT_FIPS_LEGACY_LIB__" "$makefile" || \
                    printf "\n# added by build script for legacy FIPS\noverride CFLAG += ${LEGACY_FIPS_DEFINE}\n" >> "$makefile"
                fi
            fi
        else
            eval ${OSSL_CONFIG_CMD}
            if [[ "$OPENSSL_VER" == "1.1.1" ]] || [[ "$OPENSSL_VER" == "3.0.7" ]] || [[ "$OPENSSL_VER" == "3.0.12" ]]; then
                make $FIPS_MAKE_OPTION $REDEFINE_LIB_OPTION $STRICT_DH_OPTION_OSSL build_generated
            fi
        fi

        if [[ "$STATIC_OPTION" == "" ]]; then
            make clean
            if [[ "$OPENSSL_VER" == "3.0.7" ]] || [[ "$OPENSSL_VER" == "3.0.12" ]]
            then
                make build_libs
                cp ${MSS_DIR}/thirdparty/${OPENSSL_LIB_OPTION}/libcrypto.so* ${MSS_DIR}/${BIN_DIR}
            elif [[ "$OPENSSL_VER" == "1.1.1" ]]
            then
                make $DEBUG_OPTIONS $FIPS_MAKE_OPTION $REDEFINE_LIB_OPTION $RC5_DISABLE_OPTION $STRICT_DH_OPTION_OSSL cryptointerface=true build_libs
                cp ${MSS_DIR}/thirdparty/${OPENSSL_LIB_OPTION}/libcrypto.so* ${MSS_DIR}/${BIN_DIR}
            else
                echo "Unsupported OpenSSL version"
                exit 1
            fi
        fi

        cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh --clean $BUILD_OPTIONS $FIPS_OPTION $REDEFINE_OPTION $DISABLE_PQC_OPT --openssl_shim $DTLS_OPTION $OPENSSL_OPTION $OCSP_OPTION $SESSION_TICKET_OPTION $STATIC_OPTION $NANOSSL_OSSL_OPTIONS $IPV6_OPTIONS openssl_shim_lib
    fi

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

done

if [[ "$STATIC_OPTION" == "" ]]; then
    if [[ "$OPENSSL_VER" == "3.0.7" ]] || [[ "$OPENSSL_VER" == "3.0.12" ]]
    then
        cd ${MSS_DIR}/${BIN_DIR} && ln -sf libopenssl_shim.so libssl.so
        cd ${MSS_DIR}/${BIN_DIR} && ln -sf libopenssl_shim.so libssl.so.3
    elif [[ "$OPENSSL_VER" == "1.1.1" ]]
    then
        cd ${MSS_DIR}/${BIN_DIR} && ln -sf libopenssl_shim.so libssl.so
        cd ${MSS_DIR}/${BIN_DIR} && ln -sf libopenssl_shim.so libssl.so.1.1
    else
        echo "Unsupported OpenSSL version"
        exit 1
    fi

    export LD_LIBRARY_PATH=${MSS_DIR}/${BIN_DIR}
    # Build binaries only on the second pass
    cd ${MSS_DIR}/thirdparty/${OPENSSL_LIB_OPTION}/sample
    make -f Makefile suiteb=true mauth=true clean $SAMPLE_SESSION_TICKET_OPTION $SAMPLE_CRYPTOINTERFACE_OPTION $SAMPLE_GDB_OPTION openssl_client_local
fi

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
