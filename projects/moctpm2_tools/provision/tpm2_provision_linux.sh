#!/usr/bin/env bash

set -e
###############################################################################
# Script Name:   tpm2_provision_linux.sh                                      #
# Version:       1.0.0                                                        #
# Date:          June 28, 2021                                                #
# Disclaimer:    This script MUST NOT be modified and is reserved for edits   #
#                by Digicert only.                                  #
# Description:   Bash script for provisioning TPM2 on Linux-based systems.    #
# Prerequisites:                                                              #
#                - Linux-based system (Ubuntu, CentOS, Raspbian)              #
#                - TPM2 hardware (Infineon, STM)                              #
#                - TrustEdge Foundation Clients with TAP Tools installed      #
#                - ./tpm2_prov.conf configuration file                        #
###############################################################################
# VERBOSE: Set to 1 to see verbose/debug output, or 0 to show less output
VERBOSE=0
# DRY_RUN: Set to 1 to just show commands to be executed, but do not execute
DRY_RUN=0
TMP_DIR=/tmp
TP_ROOT_DIR=/opt/trustpoint
TP_BIN_DIR=${TP_ROOT_DIR}/bin
TP_LIB_DIR=${TP_ROOT_DIR}/lib
SEC_CONF_DIR=${SECURE_DIR:-/etc/digicert}
TPM2_PROV_CONF_DEFAULT=${TP_ROOT_DIR}/conf/tap/tpm2/tpm2_prov.conf
TPM2_PROV_CONF=${TPM2_PROV_CONF_DEFAULT}
TPM2_CONF_FILE=tpm2.conf
TAP_SERVER_CONF=taps.conf
KEEP=0
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
        TPM2_PROV_CONF_DEFAULT=${TP_ROOT_DIR}/conf/tap/tpm2/tpm2_prov.conf
        TPM2_PROV_CONF=${TPM2_PROV_CONF_DEFAULT}
    fi
fi

### DO NOT MODIFY BELOW THIS LINE ###
function usage()
{
    ret_code=0
    [[ -z $1 ]] || { echo "ERROR: $1"; ret_code=1; }

    echo "Usage: sudo $0 [--conf-file <file>]"
    echo "  --conf-file <file>: (optional) TPM2 configuration file. If not provided, default is ${TPM2_PROV_CONF_DEFAULT}"
    echo "  --keep: Retain the provisioning configuration file after provisioning is completed. The default action is to delete the provisioning configuration file"
    echo "  --dryrun: Show commands that are executed"
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

function is_user_root()
{
    [ "$(id -u)" -eq 0 ];
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

while test $# -gt 0
do
    case "$1" in
        --conf-file)
            [[ -z "$2" || "$2" = -* ]] && usage "Missing value for --conf-file argument"
            TPM2_PROV_CONF=$2
            dbg_msg "Setting conf file to $2"
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

dbg_msg "Reading config from ${TPM2_PROV_CONF}"
[ -e "${TPM2_PROV_CONF}" ] || quit "Missing config file [${TPM2_PROV_CONF}]"
source ${TPM2_PROV_CONF} || quit "Unable to read configuration from ${TPM2_PROV_CONF}"

# Validate configuration
[[ -z "${DEVICE}" ]] && quit "TPM device is not specified. Set DEVICE in config file."
[[ -z "${CRED_FILE}" ]] && quit "Credentials file is not specified. Set CRED_FILE in config file."
[[ -z "${EK_ALGO}" ]] && quit "EK algorithm is not specified. Set EK_ALGO in config file."
[[ 'rsa' != "${EK_ALGO}" && 'ecc' != "${EK_ALGO}" ]] && quit "Invalid value for SRK_ALGO. Valid values: rsa, ecc"
[[ -z "${SRK_ALGO}" ]] && quit "SRK algorithm is not specified. Set SRK_ALGO in config file."
[[ 'rsa' != "${SRK_ALGO}" && 'ecc' != "${SRK_ALGO}" ]] && quit "Invalid value for SRK_ALGO. Valid values: rsa, ecc"
[[ -z "${AUTH_FAIL}" ]] && quit "AUTH_FAIL is not specified. Set AUTH_FAIL in config file."
[[ -z "${RCY_TIME}" ]] && quit "RCY_TIME timeout is not specified. Set RCY_TIME in config file."
[[ -z "${LORCY}" ]] && quit "LORCY timeout is not specified. Set LORCY in config file."

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
    dbg_msg "Creating and setting permissions on ${SEC_CONF_DIR}"
    if [ ! -d "${SEC_CONF_DIR}" ]; then
        cmd="mkdir -p ${SEC_CONF_DIR}"
        execute_cmd "${cmd}"
    fi

    cmd="chown -R $TP_USER:$TP_GROUP ${SEC_CONF_DIR}"
    execute_cmd "${cmd}"

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

dbg_msg "Setting '$TP_USER/$TP_GROUP' user/group device ownership for ${DEVICE}"
cmd="chown $TP_USER:$TP_GROUP ${DEVICE}"
execute_cmd "${cmd}"

dbg_msg "Setting +rw group permissions for ${DEVICE}"
cmd="chmod g+rw ${DEVICE}"
execute_cmd "${cmd}"

if [ -d /etc/udev/rules.d ]; then
    dbg_msg "Updating /etc/udev/rules.d/71-tpm.rules"
    echo "KERNEL==\"tpm0\", SUBSYSTEM==\"tpm\", MODE=\"0660\", OWNER=\"$TP_USER\", GROUP=\"$TP_GROUP\"" > /etc/udev/rules.d/71-tpm.rules

    dbg_msg "Reloading udev rules to apply the permission changes to ${DEVICE}"
    cmd='udevadm control --reload-rules && udevadm trigger'
    execute_cmd "${cmd}"
fi

info_msg "Taking TPM2 ownership"
cmd="cd ${TMP_DIR} && ${TP_BIN_DIR}/digicert_tpm2_takeownership --sm=${DEVICE} --lhpwd=${LH_PWD} --ehpwd=${EH_PWD} --shpwd=${SH_PWD} --credfile=${CRED_FILE} --authfail=${AUTH_FAIL} --rcytime=${RCY_TIME} --lorcy=${LORCY}"
execute_cmd "${cmd}"

info_msg "Provisioning primary keys"
cmd="cd ${TMP_DIR} && ${TP_BIN_DIR}/digicert_tpm2_provision --sm=${DEVICE} --ekpwd=${EK_PWD} --ekalg=${EK_ALGO} --srkpwd=${SRK_PWD} --srkalg=${SRK_ALGO} --credfile=${CRED_FILE}"
execute_cmd "${cmd}"

dbg_msg "Updating config files in ${SEC_CONF_DIR}"
if [ -f "${TMP_DIR}/${CRED_FILE}" ] || [ "${DRY_RUN}" -eq 1 ]; then
    cmd="mv ${TMP_DIR}/${CRED_FILE} ${SEC_CONF_DIR}"
    execute_cmd "${cmd}"
else
    quit "Unable to find ${TMP_DIR}/${CRED_FILE}"
fi

if [ -f ${SEC_CONF_DIR}/${CRED_FILE} ] || [ "${DRY_RUN}" -eq 1 ]; then
    dbg_msg "Creating ${SEC_CONF_DIR}/${TPM2_CONF_FILE} file"
    cmd="> ${SEC_CONF_DIR}/tpm2.conf"
    execute_cmd "${cmd}"
    cmd="echo \"providerType=3\" >> ${SEC_CONF_DIR}/tpm2.conf"
    execute_cmd "${cmd}"
    cmd="echo \"[module]\" >> ${SEC_CONF_DIR}/tpm2.conf"
    execute_cmd "${cmd}"
    cmd="echo \"modulename=${DEVICE}\" >> ${SEC_CONF_DIR}/tpm2.conf"
    execute_cmd "${cmd}"
    cmd="echo \"moduleidstr=0000000000000000000000000000000000000000000000000000000000000000\" >> ${SEC_CONF_DIR}/tpm2.conf"
    execute_cmd "${cmd}"
    cmd="echo \"modulenum=1\" >> ${SEC_CONF_DIR}/tpm2.conf"
    execute_cmd "${cmd}"
    cmd="echo \"credfile=${CRED_FILE}\" >> ${SEC_CONF_DIR}/tpm2.conf"
    execute_cmd "${cmd}"
    cmd="echo \"\" >> ${SEC_CONF_DIR}/tpm2.conf"
    execute_cmd "${cmd}"
else
    quit "Unable to find ${SEC_CONF_DIR}/${CRED_FILE}"
fi

cmd="chown $TP_USER:$TP_GROUP ${SEC_CONF_DIR}/${CRED_FILE} ${SEC_CONF_DIR}/tpm2.conf"
execute_cmd "${cmd}"
cmd="chmod g+rw ${SEC_CONF_DIR}/${CRED_FILE} ${SEC_CONF_DIR}/tpm2.conf"
execute_cmd "${cmd}"

# Update TAP server configuration as needed
if [ -f "${SEC_CONF_DIR}/${TAP_SERVER_CONF}" ]; then
    add_line_if_not_exist "${SEC_CONF_DIR}/${TAP_SERVER_CONF}" "module=${TPM2_CONF_FILE}"
fi

dbg_msg "Updating module params in ${SEC_CONF_DIR}/tpm2.conf"
cmd="cd ${TMP_DIR} && ${TP_BIN_DIR}/smp_tpm2_getidstr_bin --c ${SEC_CONF_DIR}/tpm2.conf --w"
execute_cmd "${cmd}"

if [ "${KEEP}" -eq 0 ]; then
    dbg_msg "Removing ${TPM2_PROV_CONF} configuration file"
    cmd="rm -f ${TPM2_PROV_CONF}"
    execute_cmd "${cmd}"
fi

info_msg "DONE"
