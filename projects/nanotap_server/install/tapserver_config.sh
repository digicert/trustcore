#!/bin/bash

#######################################################################
# Description: This script installs NanoTAP server
#######################################################################

# Global params (could be overridden from local env)
SECURE_CONF_DIR=${SECURE_DIR:-/etc/mocana}
TAP_SERVER_PORT=${TAP_REMOTE_PORT:-8277}
#RUN_AS_SERVICE=${TAP_REMOTE_INSTALL_AS_SERVICE:-0}
TPCONF_PATH="${SECURE_CONF_DIR}/tpconf.json"

function parse_json()
{
    [[ -z "$JSON" ]] && quit "JSON data is not loaded"
    JSON_CONTENT=$(echo $JSON | sed "s/,[ \t]*\"/,\\n\"/g" | sed 's/[{}]//g' | sed 's/^[ \t]*//g' | sed 's/[ \t]*$//g' | sed '/^$/d' | sed 's/^,$//g' | sed '/^$/d')
    while IFS=':' read -r col1 col2
    do
        attr=$(echo $col1 | sed 's/\"//g')
        if [[ "$1" = "$attr" ]]; then
            value=$(echo $col2 | sed 's/\"//g' | sed 's/,*$//g' | sed 's/,/, /g')
            echo "$value"
        fi
    done <<< "$JSON_CONTENT"
}

# File paths
TRUSTPOINT_PATH=/opt/trustpoint
if [ -f "$TPCONF_PATH" ]; then
    JSON=$(cat $TPCONF_PATH)
    TRUSTPOINT_PATH=$(parse_json "root_dir")
fi

TAP_SERVER_DIR="${TRUSTPOINT_PATH}/scripts/tap_server"
TAP_SERVER_CONF=${SECURE_CONF_DIR}/taps.conf
TAP_CLIENT_CONF=${SECURE_CONF_DIR}/tapc.conf

function info_msg {
    echo "[INFO] $1"
}

function quit {
    [[ -z $1 ]] || echo "[ERROR] $1"
    exit 1
}

if [ "Darwin" == "$(uname -s)" ]; then
    quit "macOS is not supported by this script"
fi

if [[ $EUID -ne 0 ]]; then
   quit "This script must be run as root"
fi

if [ ! -d "${TAP_SERVER_DIR}" ]; then
    quit "Missing TAP server directory: ${TAP_SERVER_DIR}"
fi

if [ ! -d "${SECURE_CONF_DIR}" ]; then
    mkdir -p "${SECURE_CONF_DIR}"
    chown trustpoint:trustpoint "${SECURE_CONF_DIR}"
    chmod g+rwx "${SECURE_CONF_DIR}"
fi

#######################################################################
### Check TAP server config
#######################################################################
if [ ! -f "${TAP_SERVER_CONF}" ]; then
    info_msg "Attempting to create ${TAP_SERVER_CONF}"
    echo "serverport=${TAP_SERVER_PORT}
enableunsecurecomms=1
bindaddress=127.0.0.1
" >> ${TAP_SERVER_CONF}
    chown trustpoint:trustpoint ${TAP_SERVER_CONF}
fi

if [ ! -f "${TAP_SERVER_CONF}" ]; then
    quit "Missing TAP Server config: ${TAP_SERVER_CONF}"
fi

#######################################################################
### Check TAP client config
#######################################################################
if [ ! -f "${TAP_CLIENT_CONF}" ]; then
    info_msg "Attempting to create ${TAP_CLIENT_CONF}"
    echo "serverport=${TAP_SERVER_PORT}
enableunsecurecomms=1
" >> ${TAP_CLIENT_CONF}
    chown trustpoint:trustpoint ${TAP_CLIENT_CONF}
fi

if [ ! -f "${TAP_CLIENT_CONF}" ]; then
    quit "Missing TAP Client config: ${TAP_CLIENT_CONF}"
fi

#######################################################################
### Start TAP Server
#######################################################################
#if [ "${RUN_AS_SERVICE}" = "1" ]; then
#    if [ -f "${SCRIPT_DIR}/install_tapserver_service.sh" ]; then
#        info_msg "Starting TAP Server as a system service..."
#        cd ${SCRIPT_DIR} && ./install_tapserver_service.sh
#    fi
#else
#    if [ -f "${SCRIPT_DIR}/start_tapserver.sh" ]; then
#        info_msg "Starting TAP Server..."
#        cd ${SCRIPT_DIR} && ./start_tapserver.sh &
#    fi
#fi
