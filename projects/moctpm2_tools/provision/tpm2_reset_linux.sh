#!/usr/bin/env bash

set -e
###############################################################################
# Script Name:   tpm2_reset_linux.sh                                          #
# Version:       1.0.0                                                        #
# Date:          September 29, 2022                                           #
# Disclaimer:    This script MUST NOT be modified and is reserved for edits   #
#                by Digicert only.                                  #
# Description:   Bash script for provisioning TPM2 on Linux-based systems.    #
# Prerequisites:                                                              #
#                - Linux-based system (Ubuntu, CentOS, Raspbian)              #
#                - TPM2 hardware (Infineon, STM)                              #
#                - TrustEdge Foundation Clients with TAP Tools installed      #
###############################################################################
# VERBOSE: Set to 1 to see verbose/debug output, or 0 to show less output
VERBOSE=0
# DRY_RUN: Set to 1 to just show commands to be executed, but do not execute
DRY_RUN=0
TP_ROOT_DIR=/opt/trustpoint
TP_BIN_DIR=${TP_ROOT_DIR}/bin
TP_LIB_DIR=${TP_ROOT_DIR}/lib
SEC_CONF_DIR=${SECURE_DIR:-/etc/digicert}
TPM2_CONF_FILE=${SEC_CONF_DIR}/tpm2.conf
DEVICE=
CRED_FILE=
FORCE=0
CMD_RET=
TPCONF_PATH="/etc/digicert/tpconf.json"
TP_USER=trustpoint
TP_GROUP=trustpoint

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

if [[ -z "${TRUSTEDGE_ENV}" ]]; then
    if [ -f "$TPCONF_PATH" ]; then
        JSON=$(cat $TPCONF_PATH)
        TP_ROOT_DIR=$(parse_json "root_dir")
        TP_BIN_DIR=${TP_ROOT_DIR}/bin
        TP_LIB_DIR=${TP_ROOT_DIR}/lib
    fi
fi

### DO NOT MODIFY BELOW THIS LINE ###
function usage()
{
    ret_code=0
    [[ -z $1 ]] || { echo "ERROR: $1"; ret_code=1; }

    echo "Usage: sudo $0 [--device <device>] [--cred-file <file>]"
    echo "  --device <device>: (optional) TPM2 device to reset. If not specified, the device is selected from ${TPM2_CONF_FILE}"
    echo "  --cred-file <file>: (optional) TPM2 credential file. If not specified, credential file is selected from ${TPM2_CONF_FILE}"
    echo "  --force: If the TPM2 reset fails with the credential file, or the credential file is not provided or found, attempt to force reset the TPM2 device"
    echo "  --dryrun: Show commands to execute"
    echo "  --verbose: Show verbose output"
    echo "  --user <user>: (optional) User to run the script as. Default is 'trustpoint'"
    echo "  --group <group>: (optional) Group to run the script as. Default is 'trustpoint'"
    echo "  -h|--help: Show this help menu"

    exit ${ret_code}
}

function quit()
{
    [ -z "$1" ] || echo "[ERROR] $1"
    exit 1
}

function info_msg()
{
    echo "[INFO] $1"
}

function dbg_msg()
{
    [ "${VERBOSE}" == "0" ] || echo "[DEBUG] $1"
}

function execute_cmd()
{
    local cmd=$1
    if [ -n "${cmd}" ]; then
        dbg_msg "Executing command: ${cmd}"
        if [ "${DRY_RUN}" -eq 0 ]; then
            eval ${cmd}
        fi
    fi
}

function execute_cmd_out()
{
    local cmd=$1
    local _cmd_out=""
    local _result=$2
    if [ -n "${cmd}" ]; then
        dbg_msg "Executing command: ${cmd}"
        _cmd_out=$(eval ${cmd})
        dbg_msg "${_cmd_out}"
        eval $_result="'$_cmd_out'"
    fi
}

function is_user_root()
{
    [ "$(id -u)" -eq 0 ];
}

while test $# -gt 0
do
    case "$1" in
        --device)
            [[ -z "$2" || "$2" = -* ]] && usage "Missing value for --device argument"
            DEVICE=$2
            dbg_msg "Setting device to $2"
            shift
            ;;
        --cred-file)
            [[ -z "$2" || "$2" = -* ]] && usage "Missing value for --cred-file argument"
            CRED_FILE=$2
            dbg_msg "Setting credential file to $2"
            shift
            ;;
        --force)
            FORCE=1
            dbg_msg "Enabling force reset"
            ;;
        --dryrun)
            DRY_RUN=1
            dbg_msg "Enabling dry-run mode"
            ;;
        --verbose)
            VERBOSE=1
            dbg_msg "Enabling verbose output"
            ;;
        --user)
            [[ -z "$2" || "$2" = -* ]] && usage "Missing value for --user argument"
            TP_USER=$2
            dbg_msg "Setting user to $2"
            shift
            ;;
        --group)
            [[ -z "$2" || "$2" = -* ]] && usage "Missing value for --group argument"
            TP_GROUP=$2
            dbg_msg "Setting group to $2"
            shift
            ;;
        --bin-path)
            [[ -z "$2" || "$2" = -* ]] && usage "Missing value for --bin-path argument"
            TP_BIN_DIR=$2
            dbg_msg "Setting bin path to $2"
            shift
            ;;
        --conf-dir)
            [[ -z "$2" || "$2" = -* ]] && usage "Missing value for --conf-dir argument"
            SEC_CONF_DIR=$2
            dbg_msg "Setting conf path to $2"
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

is_user_root || quit "Root user required to run this script"

TPM2_CONF_FILE=${SEC_CONF_DIR}/tpm2.conf
if [ -z "${CRED_FILE}" ]; then
    if [ -f "${TPM2_CONF_FILE}" ]; then
        info_msg "No credential file provided, finding credential file from ${TPM2_CONF_FILE}..."
        cmd="sed -n -e '/^credfile=/p' ${TPM2_CONF_FILE} | head -n 1 | cut -d \"=\" -f2"
        execute_cmd_out "${cmd}" CRED_FILE_TMP
        [[ -z "${CRED_FILE_TMP}" ]] && quit "Unable to find credential file"

        CRED_FILE=${SEC_CONF_DIR}/${CRED_FILE_TMP}
    elif [ "${FORCE}" -eq 0 ]; then
        quit "Must at least provide --cred-file or --force option"
    else
        info_msg "No credential file provided or found, attempting force reset"
    fi
fi

if [ -z "${DEVICE}" ]; then
    if [ -f "${TPM2_CONF_FILE}" ]; then
        info_msg "No device provided, finding device from ${TPM2_CONF_FILE}..."
        cmd="sed -n -e '/^modulename=/p' ${TPM2_CONF_FILE} | head -n 1 | cut -d \"=\" -f2"
        execute_cmd_out "${cmd}" DEVICE
        [[ -z "${DEVICE}" ]] && quit "Unable to find device"
    else
        quit "No device provided or found, provide --device option"
    fi
fi

if [[ -z "${TRUSTEDGE_ENV}" ]]; then
    info_msg "Checking TrustEdge Clients installation"
    [ -d ${TP_ROOT_DIR} ] || quit "TrustEdge Clients not found in ${TP_ROOT_DIR}"
fi

dbg_msg "Verifying that '$TP_USER' user exist"
if ! id "$TP_USER" >/dev/null 2>&1; then
    quit "User '$TP_USER' does not exist"
fi

dbg_msg "Verifying that '$TP_GROUP' group exist"
if [ -f /usr/bin/getent ]; then
    /usr/bin/getent group $TP_GROUP || quit "Group '$TP_GROUP' does not exist"
fi

if [[ -z "${TRUSTEDGE_ENV}" ]]; then
    if [ -d "${TP_LIB_DIR}" ]; then
        # Ensure TP_LIB_DIR is not already in LD_LIBRARY_PATH to avoid duplication
        [[ "${LD_LIBRARY_PATH}" == *"${TP_LIB_DIR}"* ]] || {
            dbg_msg "Adding ${TP_LIB_DIR} to LD_LIBRARY_PATH"
            export LD_LIBRARY_PATH=${TP_LIB_DIR}:${LD_LIBRARY_PATH}
        }
    fi
else
    if [ ! -d "${SEC_CONF_DIR}" ]; then
        quit "Configuration directory ${SEC_CONF_DIR} does not exist"
    fi
fi

dbg_msg "Verifying that TPM2 device is available"
[ -c "${DEVICE}" ] || quit "Device ${DEVICE} does not exist"

if [ ! -z "${CRED_FILE}" ]; then
    dbg_msg "Verifying credential file exists"
    [ -f "${CRED_FILE}" ] || quit "Credential file ${CRED_FILE} does not exist"

    info_msg "Clearing TPM2"
    cmd="${TP_BIN_DIR}/digicert_tpm2_takeownership --sm=${DEVICE} --c --credfile=${CRED_FILE}"
    CMD_RET=0
    execute_cmd "${cmd}" || CMD_RET=$?
    # If clearing TPM2 worked then unset force option
    if [ "${CMD_RET}" == "0" ]; then
        FORCE=0
    fi
fi

if [ "${FORCE}" -eq 1 ]; then
    info_msg "Force clearing TPM2"
    cmd="${TP_BIN_DIR}/digicert_tpm2_takeownership --sm=${DEVICE} --c --force"
    execute_cmd "${cmd}"
fi

info_msg "DONE"
