#!/usr/bin/env bash

##################################################################################################
# Copyright © 2022, Digicert Inc. All Rights Reserved.
# The information in this document is proprietary and confidential.
# Liability Disclaimer Notice:
# You MUST NOT edit the following script.
# Any customization may only be performed using the supported command line arguments.
##################################################################################################
## start_tapserver script:
##################################################################################################
##
## This script is to be used to start the nanotap_server_bin (NanoTAP Server) binary in the tap_server directory.
##
## ==[ start_tapserver parameters. ]========================================
##
## Usage info for the nanotap_server_bin:
##       Usage: ./start_tapserver [-h|--help] [--p <port>] [--conf <conf_file>]
##       where
##
##
##           -h|--help
##                   Display Help menu
##
##       TAP server uses /etc/mocana/taps.conf to pick up values. Use following
##       command line options to override taps.conf values:
##
##           --conf <conf_file>
##                   Path to TAP server configuration file.
##
##           --p <port>
##                   Port at which the TAP server is listening.
##
################################################################

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

TRUSTPOINT_PATH=/opt/trustpoint
if [ -f "$TPCONF_PATH" ]; then
    JSON=$(cat $TPCONF_PATH)
    TRUSTPOINT_PATH=$(parse_json "root_dir")
fi

TAP_SERVER_LIBS="${TRUSTPOINT_PATH}/lib"
TAP_ENV_FILE="${TRUSTPOINT_PATH}/conf/tap/env.sh"
TAPS_BIN="${TRUSTPOINT_PATH}/bin"

function usage()
{
    ret_code=0
    [[ -z $1 ]] || { echo "ERROR: $1"; ret_code=1; }

    echo "Usage: $0 [-h|--help] [--p <port>] [--conf <conf_file>]"
    echo "  --conf <file>: (optional) Path to the TAP server configuration file. The default is /etc/mocana/taps.conf"
    echo "  --p <port>: (optional) Port the TAP server is listening on. By default, the port in the TAP server configuration file is used"
    echo "  -h|--help: Show this help menu"

    exit ${ret_code}
}

if [ -z "${LD_LIBRARY_PATH}" ]; then
    export LD_LIBRARY_PATH=${TAP_SERVER_LIBS}
else
    export LD_LIBRARY_PATH=${TAP_SERVER_LIBS}:${LD_LIBRARY_PATH}
fi

[ "Darwin" == "$(uname -s)" ] && export DYLD_LIBRARY_PATH=${LD_LIBRARY_PATH}

RUN_OPTS=
while test $# -gt 0
do
    case "$1" in
        --conf)
            [[ -z "$2" || "$2" = -* ]] && usage "Missing value for --conf argument"
            RUN_OPTS+=" $1=$2"
            shift
            ;;
        --p)
            [[ -z "$2" || "$2" = -* ]] && usage "Missing value for --p argument"
            RUN_OPTS+=" $1=$2"
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            usage "Invalid option: $1";
            ;;
    esac
    shift
done

if [[ ! -d ${TAPS_BIN} ]] || [[ ! -f ${TAPS_BIN}/nanotap_server_bin ]]; then
    echo "Error: NanoTAP server ${TAPS_BIN}/nanotap_server_bin executable not found..."
    exit 1
fi

if [ -f ${TAP_ENV_FILE} ]; then
    echo "Setting up TAP environment"
    source ${TAP_ENV_FILE}
fi

echo ""
echo "Calling ${TAPS_BIN}/nanotap_server_bin ${RUN_OPTS} &"
echo ""
${TAPS_BIN}/nanotap_server_bin ${RUN_OPTS} &
echo "Successfully executed."
exit 0
