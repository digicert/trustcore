#!/usr/bin/env bash

set -m

show_usage()
{
  echo "OPTIONS:"
  echo "   --bootstrap <path>  - path to bootstrap ZIP."
  echo "   --help              - Build options information."
}

SCRIPT_DIR=$( cd $(dirname $0) ; pwd -P )
MSS_DIR=${SCRIPT_DIR}/../../../..
BOOTSTRAP_PATH=""
LOAD_CERTS=0

while test $# -gt 0
do
    case "$1" in
        --bootstrap)
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

pushd "${MSS_DIR}" || true

rm -rf flash 2>/dev/null || true
rm -f flash.bin 2>/dev/null || true

${SCRIPT_DIR}/build/zephyr/zephyr.exe &
bg %1

echo "provision flash drive.."
sleep 2

unzip ./projects/trustedge/trustedge_2.0.2.arm.zip

cp -r etc/ flash/lfs1/
rm -rf etc/

cp -r "${BOOTSTRAP_PATH}" flash/lfs1/bootstrap.zip

if [ ${LOAD_CERTS} -eq 1 ]; then

    rm -rf pki_certs 2>/dev/null || true
    wget -P ./pki_certs https://cacerts.digicert.com/DigiCertGlobalRootG2.crt
    wget -P ./pki_certs https://cacerts.digicert.com/DigiCertGlobalRootCA.crt
    cp ./pki_certs/server.pem flash/lfs1/etc/digicert/keystore/certs/te-api-server.pem
    cp ./pki_certs/server.key flash/lfs1/etc/digicert/keystore/keys/te-api-server.pem
    cp ./pki_certs/DigiCertGlobalRoot* flash/lfs1/etc/digicert/keystore/ca/

fi

rm -rf etc/ 2>/dev/null || true

popd || true

echo "returning to foreground"
fg %1
