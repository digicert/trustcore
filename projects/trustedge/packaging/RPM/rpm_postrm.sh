#!/bin/bash

# $1 == 0 : Uninstall
# $1 >= 1 : Upgrade

set -e

BACKUP_DIR="/tmp/trustedge_bkup"
INSTALL_DIR="/etc/digicert"
IS_PURGE=0
IS_UPGRADE=0

if [ "$1" -eq "0" ]; then
  IS_PURGE=0
  IS_UPGRADE=0
elif [ "$1" -ge "1" ]; then
  IS_UPGRADE=1
fi

dbg_msg ()
{
    [ "$TE_DEBUG" = "1" ] && echo "DEBUG: $1" || true
}

cleanup_on_quit()
{
    [ -d "$BACKUP_DIR" ] && rm -rf "$BACKUP_DIR" || true
}
trap "cleanup_on_quit" SIGHUP SIGINT SIGTERM EXIT

restore_state ()
{
    if [ ${IS_UPGRADE} -eq 0 ]; then
        if [ -d ${BACKUP_DIR} ] && [ "$(ls -A ${BACKUP_DIR})" ]; then
            dbg_msg "restoring state"
            if [ -d "${BACKUP_DIR}/conf" ]; then
                cp -RT "${BACKUP_DIR}/conf" "${INSTALL_DIR}/conf"
            fi
            if [ -d "${BACKUP_DIR}/keystore" ]; then
                cp -RT "${BACKUP_DIR}/keystore" "${INSTALL_DIR}/keystore"
            fi
            if [ -f "${BACKUP_DIR}/trustedge.json" ]; then
                cp "${BACKUP_DIR}/trustedge.json" "${INSTALL_DIR}/trustedge.json"
            fi
        fi
    elif [ ${IS_UPGRADE} -eq 1 ]; then
        if [ -d ${BACKUP_DIR} ] && [ "$(ls -A ${BACKUP_DIR})" ]; then
            if [ -d "${BACKUP_DIR}/conf" ]; then
                dbg_msg "restoring conf/"
                [ -f "${BACKUP_DIR}/conf/eula.txt" ] && rm "${BACKUP_DIR}/conf/eula.txt" || true
                [ -f "${BACKUP_DIR}/conf/version.txt" ] && rm "${BACKUP_DIR}/conf/version.txt" || true

                [ ! -d "${INSTALL_DIR}/conf" ] && mkdir -p "${INSTALL_DIR}/conf" || true
                cp -RT "${BACKUP_DIR}/conf" "${INSTALL_DIR}/conf"
            fi
            if [ -d "${BACKUP_DIR}/keystore" ]; then
                dbg_msg "restoring keystore/"
                [ ! -d "${INSTALL_DIR}/keystore" ] && mkdir -p "${INSTALL_DIR}/keystore" || true
                cp -RT "${BACKUP_DIR}/keystore" "${INSTALL_DIR}/keystore"
            fi
            if [ -f "${BACKUP_DIR}/trustedge.json" ]; then
                dbg_msg "restoring trustedge.json"
                cp "${BACKUP_DIR}/trustedge.json" "${INSTALL_DIR}/trustedge.json"
            fi
        fi
    fi
}

restore_state

exit 0