#!/usr/bin/env bash

##################################################################################################
# Copyright © 2022, Digicert Inc. All Rights Reserved.
# The information in this document is proprietary and confidential.
# Liability Disclaimer Notice:
# You MUST NOT edit the following script.
# Any customization may only be performed using the supported command line arguments.
##################################################################################################
## install_tapserver_service script:
##################################################################################################
##
## This script is to be used to remove TAP server service.
##
## ==[ install_tapserver_service parameters. ]========================================
##
## Usage info for install_tapserver_service script:
##       Usage: sudo ./install_tapserver_service.sh
##
################################################################

SVC=tapserver.service
TPCONF_PATH="/etc/mocana/tpconf.json"

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

TP_ROOT_DIR=/opt/trustpoint
if [ -f "$TPCONF_PATH" ]; then
    JSON=$(cat $TPCONF_PATH)
    TP_ROOT_DIR=$(parse_json "root_dir")
fi

SVC_FILE="${TP_ROOT_DIR}/scripts/tap_server/${SVC}"

if [[ $EUID -ne 0 ]]; then
   echo "[ERROR] This script must be run as root"
   exit 1
fi

if [ -f "$SVC_FILE" ]; then
    cp $SVC_FILE /etc/systemd/system/
    systemctl daemon-reload
    systemctl start $SVC
    systemctl enable $SVC
else
    echo "[ERROR] Missing service file $SVC_FILE"
    exit 1
fi

