#!/usr/bin/env bash

set -e
###############################################################################
# Script Name:   pkcs11_provision_linux.sh                                    #
# Version:       1.0.0                                                        #
# Date:          August 3, 2021                                               #
# Disclaimer:    This script MUST NOT be modified and is reserved for edits   #
#                by Digicert Inc only.                                  #
# Description:   Bash script for provisioning PKCS11 on Linux-based systems.  #
#                Supported for SoftHSMv2 and Digicert SSM.                    #
# Prerequisites:                                                              #
#                - Linux-based system (Ubuntu, CentOS, Raspbian)              #
#                - PKCS11 SoftHSMv2 library or Digicert SSM PKCS11 library    #
#                - TrustEdge Foundation Clients with TAP Tools installed      #
###############################################################################
# Default credential file with auth value of 0000 for all entities. Used
# as a template for constructing the creds file. Based on the input
# provided in the configuration file, the template is updated accordingly before
# being written out as the creds file.
DEFAULT_CREDS="IyBlbnRpdHktZGVzYwplbnRpdHkgOgogCXBhcmVudC10eXBlIHVuZGVmaW5lZAogCXBhcmVudC1pZCAwCiAJZW50aXR5LXR5cGUgbW9kdWxlCiAJZW50aXR5LWlkIDAKIAogCSAJY3JlZGVudGlhbCB7dHlwZSBwYXNzd2QKIAkgCWZvcm1hdCBwbGFpbnRleHQKIAkgCWNvbnRleHQgb3duZXIKIAkgCWF1dGggWyAwMDAwIF0gCgkgCX0KIyBlbnRpdHktZGVzYyAtIDYgVG9rZW5zOyAxIG1haW4gc2xvdCAmIDUgdmlydHVhbCBzbG90cy4KIyBNYWluIHRva2VuCmVudGl0eSA6CiAJcGFyZW50LXR5cGUgbW9kdWxlCiAJcGFyZW50LWlkIDAKIAllbnRpdHktdHlwZSB0b2tlbgogCWVudGl0eS1pZCAwCiAKIAkgCWNyZWRlbnRpYWwge3R5cGUgcGFzc3dkCiAJIAlmb3JtYXQgcGxhaW50ZXh0CiAJIAljb250ZXh0IHVzZXIKIAkgCWF1dGggWyAwMDAwIF0gCgkgCX0KZW50aXR5IDoKIAlwYXJlbnQtdHlwZSBtb2R1bGUKIAlwYXJlbnQtaWQgMAogCWVudGl0eS10eXBlIHRva2VuCiAJZW50aXR5LWlkIDEKIAogCSAJY3JlZGVudGlhbCB7dHlwZSBwYXNzd2QKIAkgCWZvcm1hdCBwbGFpbnRleHQKIAkgCWNvbnRleHQgdXNlcgogCSAJYXV0aCBbIDAwMDAgXSAKCSAJfQplbnRpdHkgOgogCXBhcmVudC10eXBlIG1vZHVsZQogCXBhcmVudC1pZCAwCiAJZW50aXR5LXR5cGUgdG9rZW4KIAllbnRpdHktaWQgMgogCiAJIAljcmVkZW50aWFsIHt0eXBlIHBhc3N3ZAogCSAJZm9ybWF0IHBsYWludGV4dAogCSAJY29udGV4dCB1c2VyCiAJIAlhdXRoIFsgMDAwMCBdIAoJIAl9CmVudGl0eSA6CiAJcGFyZW50LXR5cGUgbW9kdWxlCiAJcGFyZW50LWlkIDAKIAllbnRpdHktdHlwZSB0b2tlbgogCWVudGl0eS1pZCAzCiAKIAkgCWNyZWRlbnRpYWwge3R5cGUgcGFzc3dkCiAJIAlmb3JtYXQgcGxhaW50ZXh0CiAJIAljb250ZXh0IHVzZXIKIAkgCWF1dGggWyAwMDAwIF0gCgkgCX0KZW50aXR5IDoKIAlwYXJlbnQtdHlwZSBtb2R1bGUKIAlwYXJlbnQtaWQgMAogCWVudGl0eS10eXBlIHRva2VuCiAJZW50aXR5LWlkIDQKIAogCSAJY3JlZGVudGlhbCB7dHlwZSBwYXNzd2QKIAkgCWZvcm1hdCBwbGFpbnRleHQKIAkgCWNvbnRleHQgdXNlcgogCSAJYXV0aCBbIDAwMDAgXSAKCSAJfQplbnRpdHkgOgogCXBhcmVudC10eXBlIG1vZHVsZQogCXBhcmVudC1pZCAwCiAJZW50aXR5LXR5cGUgdG9rZW4KIAllbnRpdHktaWQgNQogCiAJIAljcmVkZW50aWFsIHt0eXBlIHBhc3N3ZAogCSAJZm9ybWF0IHBsYWludGV4dAogCSAJY29udGV4dCB1c2VyCiAJIAlhdXRoIFsgMDAwMCBdIAoJIAl9"
SLOT=0
# VERBOSE: Set to 1 to see verbose/debug output, or 0 to show less output
VERBOSE=0
# DRY_RUN: Set to 1 to just show commands to be executed, but do not execute
DRY_RUN=0
TMP_DIR=/tmp
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
TP_BIN_DIR=${TP_ROOT_DIR}/bin
TP_LIB_DIR=${TP_ROOT_DIR}/lib
TAP_ENV_FILE=${TP_ROOT_DIR}/conf/tap/env.sh
SEC_CONF_DIR=${SECURE_DIR:-/etc/mocana}
PKCS11_PROV_CONF_SAMPLE=${TP_ROOT_DIR}/conf/tap/pkcs11/pkcs11_prov.conf
PKCS11_PROV_CONF=
PKCS11_SMP_CONF_FILE=pkcs11_smp.conf
PKCS11_ENV_FILE=
TAP_SERVER_CONF=taps.conf
NEXT_MODULE_NUM=
MODULE_LIB_PATH=
CRED_FILE=creds.pkcs11
KEEP=0

### DO NOT MODIFY BELOW THIS LINE ###
function usage()
{
    ret_code=0
    [[ -z $1 ]] || { echo "ERROR: $1"; ret_code=1; }

    echo "Usage: sudo $0 [--lib-path <file>] [--conf-file <file>] [--cred-file <file>] [--env <file>]"
    echo "  --lib-path <file>   - (required) Path to PKCS11 library"
    echo "  --conf-file <file>  - (optional) PKCS11 configuration file. Sample provided in ${PKCS11_PROV_CONF_SAMPLE}, default values used if not provided."
    echo "  --cred-file <file>  - (optional) Name of credential file that is generated. Default is ${CRED_FILE}"
    echo "  --env <file>        - (optional) File containing environment variables used by the provider"
    echo "  --keep              - Keep provisioning configuration file"
    echo "  --dryrun            - Show commands to be executed"
    echo "  --verbose           - Show verbose output"
    echo "  -h|--help           - Show this help menu"

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
        if [ "${DRY_RUN}" -eq 0 ]; then
            _cmd_out=$(eval ${cmd})
            dbg_msg "${_cmd_out}"
            eval $_result="'$_cmd_out'"
        fi
    fi
}

function is_user_root()
{
    [ "$(id -u)" -eq 0 ];
}

function find_next_module_num()
{
    local conf_file=$1
    local _result=$2
    declare -a module_arr
    if [ ! -f "${conf_file}" ]; then
        quit "File does not exist ${conf_file}"
    fi
    while IFS= read -r line
    do
        if [[ $line == modulenum=* ]]; then
            module_arr+=(${line#*=})
        fi
    done < "${conf_file}"
    sorted_str=$(echo "${module_arr[@]}" | tr ' ' '\n' | sort | tr '\n' ' ')
    sorted_module_arr=($sorted_str)
    next_num=$((${#sorted_module_arr[@]} + 1))
    for i in "${!sorted_module_arr[@]}"; do
        if [[ "$(($i + 1))" != "${sorted_module_arr[$i]}" ]]; then
            next_num="$(($i + 1))"
            break
        fi
    done
    eval $_result="'$next_num'"
}

function add_line_if_not_exist()
{
    local conf_file=$1
    local line_to_add=$2
    if [ ! -f "${conf_file}" ]; then
        quit "File does not exist ${conf_file}"
    fi
    add_line=1
    while IFS= read -r line
    do
        if [[ $line == $line_to_add ]]; then
            add_line=0
            break
        fi
    done < "${conf_file}"
    if [ "${add_line}" -eq 1 ]; then
        [[ $(tail -c1 ${conf_file}) && -f ${conf_file} ]] && echo '' >> ${conf_file}
        cmd="echo \"${line_to_add}\" >> ${conf_file}"
        execute_cmd "${cmd}"
    fi
}

function add_to_tap_env()
{
    local env_file=$1
    if [ ! -f "${env_file}" ]; then
        quit "File does not exist ${env_file}"
    fi
    if [ ! -f "${TAP_ENV_FILE}" ]; then
        info_msg "Creating ${TAP_ENV_FILE}"
        cmd="> ${TAP_ENV_FILE}"
        execute_cmd "${cmd}"
        cmd="chown trustpoint:trustpoint ${TAP_ENV_FILE}"
        execute_cmd "${cmd}"
    fi
    cmd="echo \"# PKCS11 Module ${NEXT_MODULE_NUM} Env\" >> ${TAP_ENV_FILE}"
    execute_cmd "${cmd}"
    cmd="cat ${env_file} >> ${TAP_ENV_FILE}"
    execute_cmd "${cmd}"
}

while test $# -gt 0
do
    case "$1" in
        --conf-file)
            [[ -z "$2" || "$2" = -* ]] && usage "Missing value for --conf-file argument"
            PKCS11_PROV_CONF=$2
            dbg_msg "Setting conf file to $2"
            shift
            ;;
        --env)
            [[ -z "$2" || "$2" = -* ]] && usage "Missing value for --env argument"
            PKCS11_ENV_FILE=$2
            dbg_msg "Setting env file to $2"
            shift
            ;;
        --lib-path)
            [[ -z "$2" || "$2" = -* ]] && usage "Missing value for --lib-path argument"
            MODULE_LIB_PATH=$2
            dbg_msg "Setting PKCS11 module path to $2"
            shift
            ;;
        --cred-file)
            [[ -z "$2" || "$2" = -* ]] && usage "Missing value for --cred-file argument"
            CRED_FILE=$2
            dbg_msg "Setting credential file to $2"
            shift
            ;;
        --keep)
            KEEP=1
            dbg_msg "Keeping configuration file post provisioning"
            ;;
        --dryrun)
            DRY_RUN=1
            dbg_msg "Enabling dry-run mode"
            ;;
        --verbose)
            VERBOSE=1
            dbg_msg "Enabling verbose output"
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

# Must provide path to PKCS11 library
[[ -z "${MODULE_LIB_PATH}" ]] && quit "PKCS11 module not specified. Provide --lib-path argument."

if [ ! -z "${PKCS11_PROV_CONF}" ]; then
    dbg_msg "Reading config from ${PKCS11_PROV_CONF}"
    [ -e "${PKCS11_PROV_CONF}" ] || quit "Missing config file [${PKCS11_PROV_CONF}]"
    source ${PKCS11_PROV_CONF} || quit "Unable to read configuration from ${PKCS11_PROV_CONF}"
fi

# Must provide credential file
[[ -z "${CRED_FILE}" ]] && quit "Credentials file is not specified. Provide --cred-file argument."

# Ensure script is not overriding and existing credential file
if [ -f "${SEC_CONF_DIR}/${CRED_FILE}" ]; then
    quit "Credential file ${CRED_FILE} already exists in ${SEC_CONF_DIR} directory."
fi

# Load environment variables from environment file
if [ ! -z "${PKCS11_ENV_FILE}" ]; then
    source ${PKCS11_ENV_FILE} || quit "Unable to process configuration from ${PKCS11_ENV_FILE}"
fi

info_msg "Checking TrustEdge Clients installation"
[ -d ${TP_ROOT_DIR} ] || quit "TrustEdge Clients not found in ${TP_ROOT_DIR}"

dbg_msg "Verifying that 'trustpoint' user and group exist"
if ! id "trustpoint" >/dev/null 2>&1; then
    quit 'User "trustpoint" does not exist'
fi
if [ -f /usr/bin/getent ]; then
    /usr/bin/getent group trustpoint || quit 'Group "trustpoint" does not exist'
fi

dbg_msg "Creating and setting permissions on ${SEC_CONF_DIR}"
if [ ! -d "${SEC_CONF_DIR}" ]; then
    cmd="mkdir -p ${SEC_CONF_DIR}"
    execute_cmd "${cmd}"
fi

cmd="chown -R trustpoint:trustpoint ${SEC_CONF_DIR}"
execute_cmd "${cmd}"

if [ -d "${TP_LIB_DIR}" ]; then
    # Ensure TP_LIB_DIR is not already in LD_LIBRARY_PATH to avoid duplication
    [[ "${LD_LIBRARY_PATH}" == *"${TP_LIB_DIR}"* ]] || {
        dbg_msg "Adding ${TP_LIB_DIR} to LD_LIBRARY_PATH"
        export LD_LIBRARY_PATH=${TP_LIB_DIR}:${LD_LIBRARY_PATH}
    }
fi

# Copy PKCS11 library to the lib directory
if [ ! -z "${MODULE_LIB_PATH}" ]; then
    if [ ! -f "${MODULE_LIB_PATH}" ]; then
        quit "Unable to PKCS11 library ${MODULE_LIB_PATH}"
    fi
    cmd="cp ${MODULE_LIB_PATH} ${TP_LIB_DIR}"
    execute_cmd "${cmd}"
    MODULE_LIB_PATH=${TP_LIB_DIR}/${MODULE_LIB_PATH##*/}
    cmd="chown -R trustpoint:trustpoint ${MODULE_LIB_PATH}"
    execute_cmd "${cmd}"
fi

info_msg "Retrieving slot description"
if [ ! -z "${MODULE_LIB_PATH}" ]; then
    cmd="cd ${TMP_DIR} && ${TP_BIN_DIR}/smp_pkcs11_getslotdesc_bin -modulelibpath ${MODULE_LIB_PATH} | sed -n '/^Slot\[${SLOT}] description: / {p;q}' | sed 's/Slot\[${SLOT}] description: //'"
else
    cmd="cd ${TMP_DIR} && ${TP_BIN_DIR}/smp_pkcs11_getslotdesc_bin | sed -n '/^Slot\[${SLOT}] description: / {p;q}' | sed 's/Slot\[${SLOT}] description: //'"
fi
execute_cmd_out "${cmd}" SLOT_DESC
if [ "${DRY_RUN}" -eq 0 ]; then
    [[ -z "${SLOT_DESC}" ]] && quit "Unable to find slot description"
fi

info_msg "Retrieving module ID string"
if [ ! -z "${MODULE_LIB_PATH}" ]; then
    cmd="cd ${TMP_DIR} && ${TP_BIN_DIR}/smp_pkcs11_getmoduleidstr_bin -modulelibpath ${MODULE_LIB_PATH} | sed -n '/^Slot\[${SLOT}] Module Id String: / {p;q}' | sed 's/Slot\[${SLOT}] Module Id String: //'"
else
    cmd="cd ${TMP_DIR} && ${TP_BIN_DIR}/smp_pkcs11_getmoduleidstr_bin | sed -n '/^Slot\[${SLOT}] Module Id String: / {p;q}' | sed 's/Slot\[${SLOT}] Module Id String: //'"
fi
execute_cmd_out "${cmd}" MOD_ID_STR
if [ "${DRY_RUN}" -eq 0 ]; then
    [[ -z "${MOD_ID_STR}" ]] && quit "Unable to find module ID string"
fi

if [ -z "${AUTH}" ]; then
    info_msg "Generating default credential file"
    cmd="cd ${TMP_DIR} && echo -n ${DEFAULT_CREDS} &> ${CRED_FILE}"
    execute_cmd "${cmd}"
else
    info_msg "Generating credential file"
    cmd="cd ${TMP_DIR} && echo ${DEFAULT_CREDS} | base64 -d | sed 's/0000/${AUTH}/' | base64 -w 0 &> ${CRED_FILE}"
    execute_cmd "${cmd}"
fi

dbg_msg "Updating config files in ${SEC_CONF_DIR}"
if [ -f "${TMP_DIR}/${CRED_FILE}" ] || [ "${DRY_RUN}" -eq 1 ]; then
    cmd="mv ${TMP_DIR}/${CRED_FILE} ${SEC_CONF_DIR}"
    execute_cmd "${cmd}"
else
    quit "Unable to find ${TMP_DIR}/${CRED_FILE}"
fi

if [ ! -f "${SEC_CONF_DIR}/${PKCS11_SMP_CONF_FILE}" ]; then
    info_msg "Creating ${PKCS11_SMP_CONF_FILE}"

    NEXT_MODULE_NUM=1
    info_msg "Using module ID number: ${NEXT_MODULE_NUM}"

    cmd="> ${SEC_CONF_DIR}/${PKCS11_SMP_CONF_FILE}"
    execute_cmd "${cmd}"
    cmd="echo \"providerType=13\" >> ${SEC_CONF_DIR}/${PKCS11_SMP_CONF_FILE}"
    execute_cmd "${cmd}"
    cmd="echo \"[module]\" >> ${SEC_CONF_DIR}/${PKCS11_SMP_CONF_FILE}"
    execute_cmd "${cmd}"
    cmd="echo \"modulename=${SLOT_DESC}\" >> ${SEC_CONF_DIR}/${PKCS11_SMP_CONF_FILE}"
    execute_cmd "${cmd}"
    cmd="echo \"moduleidstr=${MOD_ID_STR}\" >> ${SEC_CONF_DIR}/${PKCS11_SMP_CONF_FILE}"
    execute_cmd "${cmd}"
    if [ ! -z "${MODULE_LIB_PATH}" ]; then
        cmd="echo \"modulelibpath=${MODULE_LIB_PATH}\" >> ${SEC_CONF_DIR}/${PKCS11_SMP_CONF_FILE}"
        execute_cmd "${cmd}"
    fi
    cmd="echo \"modulenum=${NEXT_MODULE_NUM}\" >> ${SEC_CONF_DIR}/${PKCS11_SMP_CONF_FILE}"
    execute_cmd "${cmd}"
    cmd="echo \"credfile=${CRED_FILE}\" >> ${SEC_CONF_DIR}/${PKCS11_SMP_CONF_FILE}"
    execute_cmd "${cmd}"
    cmd="echo \"\" >> ${SEC_CONF_DIR}/${PKCS11_SMP_CONF_FILE}"
    execute_cmd "${cmd}"
else
    info_msg "Appending to ${PKCS11_SMP_CONF_FILE}"

    # Find next available module ID number
    find_next_module_num "${SEC_CONF_DIR}/${PKCS11_SMP_CONF_FILE}" NEXT_MODULE_NUM
    info_msg "Found next module ID number: ${NEXT_MODULE_NUM}"

    cmd="echo \"[module]\" >> ${SEC_CONF_DIR}/${PKCS11_SMP_CONF_FILE}"
    execute_cmd "${cmd}"
    cmd="echo \"modulename=${SLOT_DESC}\" >> ${SEC_CONF_DIR}/${PKCS11_SMP_CONF_FILE}"
    execute_cmd "${cmd}"
    cmd="echo \"moduleidstr=${MOD_ID_STR}\" >> ${SEC_CONF_DIR}/${PKCS11_SMP_CONF_FILE}"
    execute_cmd "${cmd}"
    if [ ! -z "${MODULE_LIB_PATH}" ]; then
        cmd="echo \"modulelibpath=${MODULE_LIB_PATH}\" >> ${SEC_CONF_DIR}/${PKCS11_SMP_CONF_FILE}"
        execute_cmd "${cmd}"
    fi
    cmd="echo \"modulenum=${NEXT_MODULE_NUM}\" >> ${SEC_CONF_DIR}/${PKCS11_SMP_CONF_FILE}"
    execute_cmd "${cmd}"
    cmd="echo \"credfile=${CRED_FILE}\" >> ${SEC_CONF_DIR}/${PKCS11_SMP_CONF_FILE}"
    execute_cmd "${cmd}"
    cmd="echo \"\" >> ${SEC_CONF_DIR}/${PKCS11_SMP_CONF_FILE}"
    execute_cmd "${cmd}"
fi

cmd="chown trustpoint:trustpoint ${SEC_CONF_DIR}/${CRED_FILE} ${SEC_CONF_DIR}/${PKCS11_SMP_CONF_FILE}"
execute_cmd "${cmd}"
cmd="chmod g+rw ${SEC_CONF_DIR}/${CRED_FILE} ${SEC_CONF_DIR}/${PKCS11_SMP_CONF_FILE}"
execute_cmd "${cmd}"

# Store environment variables
if [ ! -z "${PKCS11_ENV_FILE}" ]; then
    add_to_tap_env "${PKCS11_ENV_FILE}"
fi

# Update TAP server configuration as needed
if [ -f "${SEC_CONF_DIR}/${TAP_SERVER_CONF}" ]; then
    add_line_if_not_exist "${SEC_CONF_DIR}/${TAP_SERVER_CONF}" "module=${PKCS11_SMP_CONF_FILE}"
fi

if [ "${KEEP}" -eq 0 ] && [ ! -z "${PKCS11_PROV_CONF}" ]; then
    dbg_msg "Removing ${PKCS11_PROV_CONF} configuration file"
    cmd="rm -f ${PKCS11_PROV_CONF}"
    execute_cmd "${cmd}"
fi

info_msg "DONE"
