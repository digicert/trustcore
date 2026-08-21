#!/usr/bin/env bash

set -euo pipefail
set -m

show_usage()
{
  echo "OPTIONS:"
  echo "   --bootstrap <path>  - path to bootstrap ZIP."
  echo "   --help              - Build options information."
}

SCRIPT_DIR=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
MSS_DIR=$( cd "${SCRIPT_DIR}/../../.." ; pwd -P )
TRUSTEDGE_ZIP="${MSS_DIR}/projects/trustedge/trustedge_2.0.2.arm.zip"
BOOTSTRAP_PATH=""
LOAD_CERTS=0
PROVISION_PID=""

cleanup_on_exit()
{
    local exit_code=$?

    trap - EXIT INT TERM

    if [ ${exit_code} -ne 0 ] && [ -n "${PROVISION_PID}" ] && kill -0 "${PROVISION_PID}" 2>/dev/null; then
        kill "${PROVISION_PID}" 2>/dev/null || true
        wait "${PROVISION_PID}" 2>/dev/null || true
    fi

    exit ${exit_code}
}

make_absolute_path()
{
    local input_path="$1"
    local input_dir
    local input_file

    input_dir=$(dirname -- "${input_path}")
    input_file=$(basename -- "${input_path}")

    printf '%s/%s\n' "$( cd "${input_dir}" ; pwd -P )" "${input_file}"
}

download_file()
{
    local output_path="$1"
    local url="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "${output_path}" "${url}"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "${output_path}" "${url}"
    else
        echo "Error: neither curl nor wget found. Please install one of them."
        return 1
    fi
}

prepare_server_certs()
{
    local cert_dir="${MSS_DIR}/pki_certs"
    local ext_file="${cert_dir}/server.ext"

    mkdir -p "${cert_dir}"

    download_file "${cert_dir}/DigiCertGlobalRootG2.crt" "https://cacerts.digicert.com/DigiCertGlobalRootG2.crt"
    download_file "${cert_dir}/DigiCertGlobalRootCA.crt" "https://cacerts.digicert.com/DigiCertGlobalRootCA.crt"

    if [ -f "${cert_dir}/server.pem" ] && [ -f "${cert_dir}/server.key" ]; then
        return 0
    fi

    if ! command -v openssl >/dev/null 2>&1; then
        echo "Error: openssl is required to generate native_sim REST API server certificates."
        return 1
    fi

    openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
        -keyout "${cert_dir}/rootCA.key" \
        -out "${cert_dir}/rootCA.pem" \
        -subj "/CN=TrustEdge native_sim local root CA"

    openssl req -newkey rsa:2048 -nodes \
        -keyout "${cert_dir}/server.key" \
        -out "${cert_dir}/server.csr" \
        -subj "/CN=localhost"

    chmod 600 "${cert_dir}/rootCA.key" "${cert_dir}/server.key"

    cat > "${ext_file}" <<EOF
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
EOF

    openssl x509 -req -in "${cert_dir}/server.csr" \
        -CA "${cert_dir}/rootCA.pem" \
        -CAkey "${cert_dir}/rootCA.key" \
        -CAcreateserial \
        -out "${cert_dir}/server.pem" \
        -days 365 \
        -sha256 \
        -extfile "${ext_file}"

    rm -f "${cert_dir}/server.csr" "${ext_file}" "${cert_dir}/rootCA.srl"
}

trap cleanup_on_exit EXIT INT TERM

while test $# -gt 0
do
    case "$1" in
        --bootstrap)
            if [ -z "${2:-}" ] || [[ "${2}" == --* ]]; then
                echo "Error: --bootstrap requires a path."
                show_usage
                exit 1
            fi
            BOOTSTRAP_PATH="$2"; shift
            ;;
        --load-certs)
            LOAD_CERTS=1
            ;;
        --help)
            show_usage
            exit 0 
            ;;
        *)
            echo "Invalid option provided."
            show_usage
            exit 1
            ;;
    esac
    shift
done

if [ -z "${BOOTSTRAP_PATH}" ]; then
    echo "--bootstrap is mandatory"
    exit 1
fi

if [ ! -f "${BOOTSTRAP_PATH}" ]; then
    echo "${BOOTSTRAP_PATH} not a valid file"
    exit 1
fi

BOOTSTRAP_PATH=$(make_absolute_path "${BOOTSTRAP_PATH}")

if [ ! -r "${TRUSTEDGE_ZIP}" ]; then
    echo "${TRUSTEDGE_ZIP} not a valid file"
    exit 1
fi

pushd "${MSS_DIR}" >/dev/null

rm -rf flash 2>/dev/null || true
rm -f flash.bin 2>/dev/null || true
rm -rf etc/ 2>/dev/null || true

${SCRIPT_DIR}/build/zephyr/zephyr.exe &
PROVISION_PID=$!

echo "provision flash drive.."
sleep 2

if [ ! -d flash/lfs1 ]; then
    echo "flash/lfs1 was not created by device_provision"
    exit 1
fi

unzip -q "${TRUSTEDGE_ZIP}"

if [ ! -d etc ]; then
    echo "${TRUSTEDGE_ZIP} did not extract an etc/ directory"
    exit 1
fi

cp -r etc/ flash/lfs1/
rm -rf etc/

cp "${BOOTSTRAP_PATH}" flash/lfs1/bootstrap.zip

if [ ${LOAD_CERTS} -eq 1 ]; then

    prepare_server_certs
    cp "${MSS_DIR}/pki_certs/server.pem" flash/lfs1/etc/digicert/keystore/certs/te-api-server.pem
    cp "${MSS_DIR}/pki_certs/server.key" flash/lfs1/etc/digicert/keystore/keys/te-api-server.pem
    cp "${MSS_DIR}"/pki_certs/DigiCertGlobalRoot* flash/lfs1/etc/digicert/keystore/ca/

fi

rm -rf etc/ 2>/dev/null || true

popd >/dev/null

echo "returning to foreground"
wait "${PROVISION_PID}"
