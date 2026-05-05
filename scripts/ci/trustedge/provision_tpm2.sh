#!/bin/bash

set -e

TP_USER=trustedge
TP_GROUP=trustedge
ADD_ARGS=

# Set script directory
SCRIPT_DIR=$( cd $(dirname $0) ; pwd -P )

cd ${SCRIPT_DIR}

SEC_CONF_DIR=/etc/digicert
if [ ! -d "${SEC_CONF_DIR}" ]; then
    SEC_CONF_DIR=${SCRIPT_DIR}
fi

while test $# -gt 0
do
    case "$1" in
        --user)
            if [ ! -z "$2" ]; then
                TP_USER=$2
                shift
            fi
            ;;
        --group)
            if [ ! -z "$2" ]; then
                TP_GROUP=$2
                shift
            fi
            ;;
        *)
            ADD_ARGS+=" $1"
            ;;
    esac
    shift
done

export TRUSTEDGE_ENV=1
./scripts/tap/tpm2/tpm2_provision_linux.sh \
    --user $TP_USER \
    --group $TP_GROUP \
    --conf-file ./conf/tap/tpm2/tpm2_prov.conf \
    --keep \
    --bin-path ${SCRIPT_DIR}/bin \
    --conf-dir ${SEC_CONF_DIR} \
    ${ADD_ARGS}