#!/bin/bash

set -e

BACKUP_DIR="/tmp/trustedge_bkup"
INSTALL_PATH="/etc/digicert"
CONF_DIR="${INSTALL_PATH}/conf"
KEYSTORE_DIR="${INSTALL_PATH}/keystore"
TRUSTEDGE_CONFIG="${INSTALL_PATH}/trustedge.json"
TRUSTEDGE_SYS_CONFIG="${INSTALL_PATH}/system.json"
SVC="trustedge.service"
SVC_FILE="/etc/systemd/system/$SVC"

RSYSLOG_CONF_FILE="/etc/rsyslog.d/trustedge.conf"
LOGROTATE_CONF_FILE="/etc/logrotate.d/trustedge"

dbg_msg ()
{
    [ "$TE_DEBUG" = "1" ] && echo "DEBUG: $1" || true
}

take_backup ()
{
    # Don't throw away a backup if we already have one
    if [ -d ${BACKUP_DIR} ] && [ "$(ls -A ${BACKUP_DIR})" ]; then
        if [ -d "${BACKUP_DIR}_1" ]; then
            rm -rf "${BACKUP_DIR}_1"
        fi
        dbg_msg "Found an old backup \"${BACKUP_DIR}\", moving to \"${BACKUP_DIR}_1\""
        mv "${BACKUP_DIR}" "${BACKUP_DIR}_1"
    fi
    mkdir -p ${BACKUP_DIR}

    if [ -d "${CONF_DIR}" ]; then
        dbg_msg "Backing up \"${CONF_DIR}\" to \"${BACKUP_DIR}\" "
        cp -r "${CONF_DIR}" ${BACKUP_DIR}
    fi

    if [ -d "${KEYSTORE_DIR}" ]; then
        dbg_msg "Backing up \"${KEYSTORE_DIR}\" to \"${BACKUP_DIR}\" "
        cp -r "${KEYSTORE_DIR}" ${BACKUP_DIR}
    fi

    if [ -f "${TRUSTEDGE_SYS_CONFIG}" ]; then
        dbg_msg "Backing up \"${TRUSTEDGE_SYS_CONFIG}\" to \"${BACKUP_DIR}\" "
        cp -r "${TRUSTEDGE_SYS_CONFIG}" ${BACKUP_DIR}
    fi

    if [ -f "${TRUSTEDGE_CONFIG}" ]; then
        dbg_msg "Backing up \"${TRUSTEDGE_CONFIG}\" to \"${BACKUP_DIR}\" "
        cp -r "${TRUSTEDGE_CONFIG}" ${BACKUP_DIR}
    fi
}

# remove service
remove_service ()
{
    if [ -f "$SVC_FILE" ]; then
        dbg_msg "$SVC_FILE file exist"
        if command -v systemctl > /dev/null 2>&1 ; then
	    dbg_msg "Stopping $SVC service"
            systemctl stop $SVC || true # might not be running
            dbg_msg "Disabling $SVC service"
            systemctl disable $SVC || true
        fi

        find /etc -type f -name $SVC -exec rm -f {} \;
        find /usr -type f -name $SVC -exec rm -f {} \;
        if command -v systemctl > /dev/null 2>&1 ; then
            systemctl daemon-reload
            # systemctl reset-failed $SVC >/dev/null 2>&1
        fi

        dbg_msg "Removing $SVC_FILE file"
        rm -f "$SVC_FILE" 2>/dev/null || true

        dbg_msg "Removing $RSYSLOG_CONF_FILE file"
        rm -f "$RSYSLOG_CONF_FILE" 2>/dev/null || true

        dbg_msg "Removing $LOGROTATE_CONF_FILE file"
        rm -f "$LOGROTATE_CONF_FILE" 2>/dev/null || true

        if command -v dpkg > /dev/null 2>&1 ; then
            if dpkg -l | grep -q "^ii  rsyslog"; then
                systemctl restart rsyslog
            fi
        fi
    fi
}

take_backup

remove_service

exit 0
