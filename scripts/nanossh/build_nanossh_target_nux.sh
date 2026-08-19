#!/usr/bin/env bash

set -e

######################
function show_usage
{
  echo "OPTIONS:"
  echo "    --gdb                   - Build with GDB enabled."
  echo "    --debug                 - Build with DEBUG flags enabled."
  echo "    --fips                  - Build with FIPS enabled."
  echo "    --fips-700-compat       - Build with backward compatibility with FIPS REL_700_U1 binary."
  echo "    --disable-suiteb        - Build with suiteb disabled."
  echo "    --disable-pqc           - Build with PQC disabled."
  echo "    --cert                  - Build with certificate authentication."
  echo "    --server_cert_auth      - Build with server certificate authentication."
  echo "    --client_cert_auth      - Build with client certificate authentication."
  echo "    --ocsp_cert             - Build with OCSP enabled."
  echo "    --ocsp_config_timeout   - Set timeout for OCSP."
  echo "    --oqs                   - Build with Open Quantum Safe algorithms."
  echo "    --oqs-path [PATH]       - Path to directory containing OQS library."
  echo "    --library               - Build as Shared Library."
  echo "    --hw-accel              - Build with Hardware Accelerator Support."
  echo "    --no-pubkey-name        - Build with support for no public key name in public key blob. Server only"
  echo "    --serial-channel        - Build support for serial channels on a single connection"
  echo "    --port_forwarding       - Build with Port Forwarding enabled."
  echo "    --remote_port_forwarding - Build with Remote Port Forwarding enabled. Client only."
  echo "    --radius                - Building with radius..."
  echo "    --rfc4256               - Build with RFC 4256 support enabled."
  echo "    --data-protect          - Enable Data Protection"
  echo "    --enable-chachapoly     - Enable ChaCha20 and Poly1305 support."
  echo "    --enable-blowfish       - Enable Blowfish support."
  echo "    --enable-dsa            - Enable DSA support in NanoSSH."
  echo "    --enable-weak-ciphers   - Build with weak ciphers enabled."
  echo "    --enable-posix          - Build with POSIX support enabled."
  exit
}

######################

SCRIPT_DIR=$( cd $(dirname $0) ; pwd -P )

export WORKSPACE="${SCRIPT_DIR}/../.."

echo "WORKSPACE=${WORKSPACE}"
MSS_DIR=${WORKSPACE}
MSS_PROJECTS_DIR=${MSS_DIR}/projects
SUITEB_OPTION=""
BUILD_OPTIONS=""
URI_OPTION=""
OCSP_OPTION=""
DEBUG_OPTIONS=""
PQC_ARG=""
PQC_COMP_ARG=""
OQS_PATH_ARG=""
OQS_PATH=""
OQS_BUILD=0
LIBRARY_OPTION=""
HW_ACCEL_OPTION=""
NO_PUBKEY_NAME_OPTION=""
SERIAL_CHANNEL_OPTION=""
PORT_FORWARD_OPTION=""
RFC4256_OPTION=""
ARCH_OPTION=""
INV_OPT=0
FIPS_OPTION=""
FIPS_700_COMPAT_OPTION=""
DATA_PROTECT_OPTION=""
EXPORT_OPTION=""
MBED_OPTION=""
MBED_PATH_ARG=""
TAP_TYPE=""
TAP_OPTION=""
TPM2_OPTION=""
SSL_OPTION=""
SSH_SERVER=""
SSH_CLIENT=""
CRYPTO_SSH_ARG="--ssh-no-chachapoly"
CHACHAPOLY=""
SECURE_PATH_VAR=""
ABSOLUTE_PATH=""
POSIX_OPTION=""

while test $# -gt 0
do
    case "$1" in
        --gdb)
            echo "Enabling GDB build...";
            DEBUG_OPTIONS+=" $1"
            ;;
        --debug)
            echo "Building with Debug logs enabled...";
            DEBUG_OPTIONS+=" $1"
            ;;
        --suiteb)
            echo "suiteb is enabled by default (legacy --suiteb flag ignored)...";
            ;;
        --secure-path)
            SECURE_PATH_VAR="--secure-path ${2}"
            ABSOLUTE_PATH="--absolute-path"
            shift
            ;;
        --disable-suiteb)
            echo "Building with suiteb disabled";
            SUITEB_OPTION=" --disable-suiteb"
            PQC_ARG=" --disable-pqc"
            ;;
        --enable-chachapoly)
            echo "Building with ChaCha20 and Poly1305 support.";
            CRYPTO_SSH_ARG="--ssh"
            CHACHAPOLY="--enable-chachapoly"
            ;;
        --enable-blowfish)
            echo "Enabling Blowfish support."
            BUILD_OPTIONS+=" $1"
            ;;
        --enable-dsa)
            echo "Enabling DSA support in NanoSSH."
	    BUILD_OPTIONS+=" $1"
            ;;
        --enable-weak-ciphers)
            echo "Building with weak ciphers enabled.";
            BUILD_OPTIONS+=" $1"
            ;;
        --cert)
            echo "Building with X509 Certificate Authentication enabled...";
            BUILD_OPTIONS+=" $1"
            ;;
        --server_cert_auth)
            echo "Building with Server Certificate Authentication enabled...";
            BUILD_OPTIONS+=" $1"
            ;;
        --ocsp_cert)
            echo "Building with OCSP Certificate Verification enabled...";
            BUILD_OPTIONS+=" $1"
            URI_OPTION="--uri"
            OCSP_OPTION="--ocsp --ocsp_cert"
            ;;
        --ocsp_config_timeout)
            echo "Building with OCSP Timeout enabled...";
            BUILD_OPTIONS+=" $1"
            ;;
        --client_auth)
            echo "Building with Client Public Key Authentication enabled...";
            BUILD_OPTIONS+=" $1"
            ;;
        --client_cert_auth)
            echo "Building with Client Certificate Authentication enabled...";
            BUILD_OPTIONS+=" $1"
            ;;
        --pqc)
            echo "PQC is enabled by default (legacy --pqc flag ignored)...";
            ;;
        --disable-pqc)
            echo "-- Building with PQC disabled";
            PQC_ARG=" --disable-pqc"
            ;;
        --pqc-composite)
            echo "Building with PQC composite...";
            PQC_COMP_ARG=" --pqc-composite";
            ;;
        --oqs)
            echo "-- Building with OQS enabled...";
            PQC_ARG=" --oqs"
            OQS_BUILD=1
            ;;
        --oqs-path)
            echo "Path to OQS library.";
            OQS_PATH_ARG="--oqs-path";
            OQS_PATH="$2"; shift
            ;;
        --library)
            echo "Build as Shared Library...";
            LIBRARY_OPTION="$1"
            ;;
        --enable-posix)
            echo "Enable posix support...";
            POSIX_OPTION="$1"
            ;;
        --hw-accel)
            echo "Build Hardware Accelerator Support";
            HW_ACCEL_OPTION="$1"
            ;;
        --no-pubkey-name)
            echo "Build with support for no public key name in public key blob."
            NO_PUBKEY_NAME_OPTION="$1"
            ;;
        --serial-channel)
            echo "Build with support for serial channels on single connection."
            SERIAL_CHANNEL_OPTION="$1"
            ;;
        --port_forwarding)
            echo "Build with Port Forwarding enabled";
            PORT_FORWARD_OPTION="$1"
            ;;
        --remote_port_forwarding)
            echo "Build with Remote Port Forwarding enabled";
            PORT_FORWARD_OPTION="$1";
            ;;
        --radius)
            echo "Build with NanoRADIUS authentication";
            PORT_FORWARD_OPTION="$1";
            ;;
        --data-protect)
            echo "Enabling data protection"
            DATA_PROTECT_OPTION="--data-protect"
            ;;
        --rfc4256)
            echo "Build RFC 4256 support enabled";
            RFC4256_OPTION="$1"
            ;;
        --fips)
            echo "Building with FIPS enabled.";
            FIPS_OPTION="$1"
            ;;
        --fips-700-compat)
            echo "Build with backward compatibility with FIPS REL_700_U1 binary."
            FIPS_700_COMPAT_OPTION=" $1"
            ;;
        --tap-local)
            echo "Building with TAP (local).";
            TAP_TYPE="$1"
            TAP_OPTION="--tap"
            TPM2_OPTION="--tpm2"
            BUILD_TAP_LOCAL=1
            ;;
        --tap-remote)
            echo "Building with TAP (remote).";
            TAP_TYPE="$1"
            TAP_OPTION="--tap"
            SSL_OPTION="--ssl"
            BUILD_TAP_REMOTE=1
            ;;
        --export)
            echo "Enable Export Edition"
            EXPORT_OPTION="$1"
            ;;
        --mbed)
            echo "Enable MbedTLS"
            MBED_OPTION="$1"
            ;;
        --mbed-path)
            MBED_PATH_ARG="$1"
            MBED_PATH="$2"
            shift
            ;;
        ssh_server)
            echo "Build NanoSSH Server"
            SSH_SERVER="$1"
            ;;
        ssh_server_sp800_135)
            echo "Build NanoSSH Server for testing SP800-135"
            SSH_SERVER="$1"
            ;;
        ssh_client)
            echo "Build NanoSSH Client"
            SSH_CLIENT="$1"
            ;;
        --x32)
            ARCH_OPTION="--x32"
            ;;
        --x64)
            ARCH_OPTION="--x64"
            ;;
        --help)
            INV_OPT=1
            ;;
        ?)
            INV_OPT=1
            ;;
        --*)
            echo "Invalid option: $1"
            INV_OPT=1
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

if [[ ! -z "${MBED_OPTION}" ]] && [[ -z "${MBED_PATH}" ]]; then
    echo "Path to MbedTLS library is required. Use --mbed-path."
    exit 1
fi

if [[ ! -z "${MBED_OPTION}" ]] && [ $OQS_BUILD -eq 0 ]; then
    echo "Export Build with no oqs, disabling PQC";
    PQC_ARG=" --disable-pqc"
fi

if [[ -z "${SSH_CLIENT}" ]] && [[ -z "${SSH_SERVER}" ]]; then
    echo "No target specified. Must be either ssh_server, ssh_client, or both"
    exit 1
fi

if [[ ${BUILD_TAP_LOCAL} -eq 1 ]] && [[ ${BUILD_TAP_REMOTE} -eq 1 ]]; then
    echo "Cannot build TAP Local and TAP Remote simultaneously. Only one allowed."
    exit 1
fi

if [[ ! -z "${FIPS_OPTION}" ]] && [[ ! -f "${MSS_DIR}/bin/libmss.so" ]] && [[ ! -f "${MSS_DIR}/lib/libmss.so" ]]; then
    echo "Unable to locate FIPS library in ${MSS_DIR}/bin or ${MSS_DIR}/lib. Required when enabling FIPS mode."
    exit 1
fi

build_message="without TAP"
if [[ ${BUILD_TAP_LOCAL} -eq 1 ]]; then
    build_message="TAP (local)"
elif [[ ${BUILD_TAP_REMOTE} -eq 1 ]]; then
    build_message="TAP (remote)"
fi

echo "***************************************************************"
echo "*** Building ssh server ${build_message} version of CAP..."
echo "***************************************************************"
for pass in first second
do
    if [ "$pass" == "first" ]; then
        echo "***************************************************************"
        echo "*** Cleaning binaries and libraries "
        echo "***************************************************************"

        if [[ -n "${SSH_SERVER}" ]]; then
            rm ${MSS_DIR}/bin/${SSH_SERVER} 2>/dev/null || true
        fi

        if [[ -n "${SSH_CLIENT}" ]]; then
            rm ${MSS_DIR}/bin/${SSH_CLIENT} 2>/dev/null || true
        fi

        if [[ -n "${OQS_PATH_ARG}" ]]; then
            for libs in ${MSS_DIR}/bin/liboqs*; do
                if [[ ! "$libs" == *libmss.so ]] || [[ -z "$FIPS_OPTION" ]]; then
                    rm -f $libs 2>/dev/null || true
                fi
            done
        fi

        if [[ -n "${MBED_OPTION}" ]]; then
            for libs in ${MSS_DIR}/bin/libmbed*; do
                if [[ ! "$libs" == *libmss.so ]] || [[ -z "$FIPS_OPTION" ]]; then
                    rm -f $libs 2>/dev/null || true
                fi
            done
        fi

        for libs in ${MSS_DIR}/bin/*.so; do
            if [[ ! "$libs" == *libmss.so ]] || [[ -z "$FIPS_OPTION" ]]; then
               rm -f $libs 2>/dev/null || true
            fi
        done
    fi
    
    cd ${MSS_PROJECTS_DIR}/platform && ./build.sh ${DEBUG_OPTIONS} ${ARCH_OPTION} ${FIPS_OPTION} ${SECURE_PATH_VAR} ${ABSOLUTE_PATH} &&
    cd ${MSS_PROJECTS_DIR}/common && ./build.sh ${DEBUG_OPTIONS} ${URI_OPTION} ${ARCH_OPTION} ${FIPS_OPTION} ${DATA_PROTECT_OPTION} ${SECURE_PATH_VAR} ${ABSOLUTE_PATH} ${POSIX_OPTION} &&
    cd ${MSS_PROJECTS_DIR}/asn1 && ./build.sh ${DEBUG_OPTIONS} ${ARCH_OPTION} ${PQC_ARG} &&
    cd ${MSS_PROJECTS_DIR}/initialize && ./build.sh ${DEBUG_OPTIONS} ${ARCH_OPTION} ${DATA_PROTECT_OPTION} ${TAP_DATA_PROTECT_OPTION} &&
    cd ${MSS_PROJECTS_DIR}/nanocap && ./build.sh ${DEBUG_OPTIONS} ${ARCH_OPTION} &&
    cd ${MSS_PROJECTS_DIR}/crypto && ./build.sh ${DEBUG_OPTIONS} ${SUITEB_OPTION} ${TAP_OPTION} ${TPM2_OPTION} ${SSL_OPTION} ${CRYPTO_SSH_ARG} ${ARCH_OPTION} \
        ${FIPS_OPTION} ${FIPS_700_COMPAT_OPTION} ${EXPORT_OPTION} ${HW_ACCEL_OPTION} ${PQC_ARG} ${OQS_PATH_ARG} "${OQS_PATH}" ${MBED_OPTION} ${MBED_PATH_ARG} "${MBED_PATH}"  &&
    cd ${MSS_PROJECTS_DIR}/nanocert && ./build.sh ${DEBUG_OPTIONS} ${OCSP_OPTION} ${SUITEB_OPTION} ${TAP_OPTION} --ssh ${ARCH_OPTION} ${NO_PUBKEY_NAME_OPTION} \
        ${FIPS_OPTION} ${PQC_ARG} ${EXPORT_OPTION} &&

    if [[ ${BUILD_TAP_LOCAL} -eq 1 ]] || [[ ${BUILD_TAP_REMOTE} -eq 1 ]]; then
        cd ${MSS_PROJECTS_DIR}/nanotap2_common && ./build.sh ${DEBUG_OPTIONS} ${SUITEB_OPTION} ${TPM2_OPTION} ${ARCH_OPTION} ${DATA_PROTECT_OPTION} ${TAP_TYPE} &&

        cd ${MSS_PROJECTS_DIR}/nanotap2_configparser && ./build.sh ${DEBUG_OPTIONS} ${ARCH_OPTION} &&


        cd ${MSS_PROJECTS_DIR}/nanotap2 && ./build.sh ${DEBUG_OPTIONS} ${TPM2_OPTION} ${ARCH_OPTION} ${DATA_PROTECT_OPTION} ${TAP_TYPE} nanotap2

        if [[ ${BUILD_TAP_REMOTE} -eq 1 ]]; then
            cd ${MSS_PROJECTS_DIR}/nanotap2 && ./build.sh ${DEBUG_OPTIONS} ${ARCH_OPTION} ${TAP_TYPE} clientcomm
        fi
    fi
    
    if [[ ${BUILD_TAP_LOCAL} -eq 1 ]]; then
        cd ${MSS_PROJECTS_DIR}/tpm2 && ./build.sh ${DEBUG_OPTIONS} ${SUITEB_OPTION} ${ARCH_OPTION} &&
        cd ${MSS_PROJECTS_DIR}/smp_tpm2 && ./build.sh ${DEBUG_OPTIONS} ${SUITEB_OPTION} ${ARCH_OPTION}
    fi

    if [[ ${BUILD_TAP_REMOTE} -eq 1 ]]; then
        cd ${MSS_PROJECTS_DIR}/nanossl && ./build.sh --clean ${PQC_ARG} ${PQC_COMP_ARG} ${DEBUG_OPTIONS} ${EXPORT_OPTION} ${SUITEB_OPTION} ${TAP_OPTION} ${ARCH_OPTION} nanossl
    fi

    if [[ -n "${DATA_PROTECT_OPTION}" ]]; then
        cd ${MSS_PROJECTS_DIR}/data_protection && ./build.sh ${DEBUG_OPTIONS} ${ARCH_OPTION}
    fi

    echo "***********************************************"
    echo "****  $pass pass library build successful  ****"
    echo "***********************************************"
done

if [[ -n "${SSH_CLIENT}" ]]; then
    echo "cd ${MSS_PROJECTS_DIR}/nanossh && ./build.sh --clean ${DEBUG_OPTIONS} ${SUITEB_OPTION} ${BUILD_OPTIONS} ${ARCH_OPTION} ${LIBRARY_OPTION} ${PORT_FORWARD_OPTION} ${FIPS_OPTION} ${PQC_ARG} ${PQC_COMP_ARG} ${RFC4256_OPTION} ${DATA_PROTECT_OPTION} ${EXPORT_OPTION} ${TAP_TYPE} ${SERIAL_CHANNEL_OPTION} ${CHACHAPOLY} ${SSH_CLIENT}"
    cd ${MSS_PROJECTS_DIR}/nanossh && ./build.sh --clean ${DEBUG_OPTIONS} ${SUITEB_OPTION} ${BUILD_OPTIONS} ${ARCH_OPTION} ${LIBRARY_OPTION} \
        ${PORT_FORWARD_OPTION} ${FIPS_OPTION} ${PQC_ARG} ${PQC_COMP_ARG} ${RFC4256_OPTION} ${DATA_PROTECT_OPTION} ${EXPORT_OPTION} ${TAP_TYPE} ${SERIAL_CHANNEL_OPTION} ${CHACHAPOLY} ${SECURE_PATH_VAR} ${ABSOLUTE_PATH} ${SSH_CLIENT}
fi 
if [[ -n "${SSH_SERVER}" ]]; then
    echo "cd ${MSS_PROJECTS_DIR}/nanossh && ./build.sh --clean ${DEBUG_OPTIONS} ${SUITEB_OPTION} ${BUILD_OPTIONS} ${ARCH_OPTION} ${LIBRARY_OPTION} ${NO_PUBKEY_NAME_OPTION} ${PORT_FORWARD_OPTION} ${FIPS_OPTION} ${PQC_ARG} ${PQC_COMP_ARG} ${RFC4256_OPTION} ${DATA_PROTECT_OPTION} ${EXPORT_OPTION} ${TAP_TYPE} ${SERIAL_CHANNEL_OPTION} ${CHACHAPOLY} ${SSH_SERVER}"
    cd ${MSS_PROJECTS_DIR}/nanossh && ./build.sh --clean ${DEBUG_OPTIONS} ${SUITEB_OPTION} ${BUILD_OPTIONS} ${ARCH_OPTION} ${LIBRARY_OPTION} ${NO_PUBKEY_NAME_OPTION} \
        ${PORT_FORWARD_OPTION} ${FIPS_OPTION} ${PQC_ARG} ${PQC_COMP_ARG} ${RFC4256_OPTION} ${DATA_PROTECT_OPTION} ${EXPORT_OPTION} ${TAP_TYPE} ${SERIAL_CHANNEL_OPTION} ${CHACHAPOLY} ${SECURE_PATH_VAR} ${ABSOLUTE_PATH} ${SSH_SERVER}
fi

echo "**************************************"
echo "**** Binaries built successfully  ****"
echo "**************************************"
