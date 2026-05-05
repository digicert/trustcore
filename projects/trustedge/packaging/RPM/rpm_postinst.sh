#!/bin/bash

# $1 == 1 : Fresh Install
# $1 >= 2 : Upgrade

set -e

USERNAME="trustedge"
INSTALL_DIR="/etc/digicert"
KEYSTORE_DIR="${INSTALL_DIR}/keystore"
CONF_DIR="${INSTALL_DIR}/conf"
SCRIPTS_DIR="${INSTALL_DIR}/scripts"

SVC="trustedge.service"
SVC_FILE="${SCRIPTS_DIR}/${SVC}"
CONFIGURE_SCRIPT="${SCRIPTS_DIR}/configure_trustedge.sh"

dbg_msg ()
{
    [ "$TE_DEBUG" = "1" ] && echo "DEBUG: $1" || true
}

create_group ()
{
    if command -v groupadd &> /dev/null ; then
        getent group trustedge || groupadd --system trustedge
    else
        echo "Cannot create the 'trustedge' group"
        exit 1
    fi
}

create_user ()
{
    if command -v useradd &> /dev/null ; then
        id -u "${USERNAME}" > /dev/null 2>&1 || useradd --system -s /bin/false -g trustedge -d ${INSTALL_DIR} "${USERNAME}"
    else
        echo "Cannot create the 'trustedge' user"
        exit 1
    fi
}

set_access_permission ()
{
    dbg_msg "setting permissions"
    chown -R ${USERNAME}:trustedge ${KEYSTORE_DIR} ${CONF_DIR} ${INSTALL_DIR}
    chmod g+w ${INSTALL_DIR}
    chmod -R u=rwx,g=rwx,o=rx ${KEYSTORE_DIR}
    chmod -R u=rwx,g=rwx,o=rx ${CONF_DIR}
    chmod -R u=rwx,go=rx ${SCRIPTS_DIR}

    chown root:root "/usr/bin/trustedge"
    chmod 755 "/usr/bin/trustedge"

    if [ -f "${CONFIGURE_SCRIPT}" ]; then
        chmod +x "${CONFIGURE_SCRIPT}"
    fi
}

update_journal_to_syslog()
{
    local file_path="$1"

    if [ ! -f "${file_path}" ]; then
        echo "could not find service file"
        exit 1
    fi

    sed -i "/StandardOutput=/c\\StandardOutput=syslog" "${file_path}"
    sed -i "/StandardError=/c\\StandardError=syslog" "${file_path}"
}

update_pid_filepath()
{
    local file_path="$1"

    if [ ! -f "${file_path}" ]; then
        echo "could not find service file"
        exit 1
    fi

    sed -i "/PIDFile=/c\\PIDFile=/var/run/trustedge.pid" "${file_path}"
}

install_service ()
{
  if [ -f "${SVC_FILE}" ]; then
    dbg_msg "${SVC_FILE} found"
    if command -v systemctl &> /dev/null ; then

        version=$(systemctl --version | head -n1 | awk '{print $2}')
        if (( version < 38 )); then
            update_journal_to_syslog "${SVC_FILE}"
        fi

        if [ ! -d "/run" ]; then
            update_pid_filepath "${SVC_FILE}"
        fi

        chmod 644 "${SVC_FILE}"

        if [ -f "/etc/systemd/system/$SVC" ]; then
            dbg_msg "/etc/systemd/system/$SVC already exists. deleting"
            rm -f "/etc/systemd/system/$SVC"
        fi

        dbg_msg "copy ${SVC_FILE} to /etc/systemd/system/"
        cp -p "${SVC_FILE}" /etc/systemd/system/

        dbg_msg "reload systemctl daemon"
        systemctl daemon-reload

        dbg_msg "enable $SVC"
        systemctl enable $SVC

    else
        echo "systemctl not found. Cannot install trustedge service."
    fi
  else
    dbg_msg "${SVC_FILE} not found"
  fi
}

create_group

create_user

set_access_permission

install_service

exit 0