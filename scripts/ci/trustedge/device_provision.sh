#!/bin/bash
###########################################################################################################
# Script for provisioning TPM2 and device with bootstrap configuration.
###########################################################################################################
###########################################################################################################
# Copyright (c) 2025 DigiCert Corporation. All Rights Reserved.
# This software is copyrighted work of DigiCert and is confidential and proprietary.
# Copying or reproduction of this software is expressly prohibited.
###########################################################################################################
# System dependencies: sed
###########################################################################################################

# Exit on error
set -e

# Set script directory
SCRIPT_DIR=$( cd $(dirname $0) ; pwd -P )

SCRIPT_USER=$USER
SCRIPT_GROUP=`id -gn`
PROV_USER=$SCRIPT_USER
PROV_GROUP=$SCRIPT_GROUP

PROVISION_TPM2=0
SETUP_TRUSTEDGE=0
PROVISION_DEVICE=0
PROXY_URL=

TPM2_TOOLS_DIR=${SCRIPT_DIR}/tpm2_tools
TRUSTEDGE_DIR=${SCRIPT_DIR}/trustedge

BOOTSTRAP_PATH=${SCRIPT_DIR}/config/bootstrap.zip

ROOT_CMD="sudo"
if ! command -v sudo 2>&1 >/dev/null
then
    ROOT_CMD=""
fi

#######################################
# Print new line
#######################################
function printNewLine() {
  echo ""
}

#######################################
# Print text in RED bold color
#######################################
function printErrorMessage() {
  local datetime=$(date +"$DATETIME_FORMAT")
  local red="\e[31m"
  local stop="\e[0m"
  printf "${red}"
  printNewLine
  echo "ERROR: ${datetime} $1"
  printf "${stop}"
}

#######################################
# Prints informational text
#######################################
function printInfoMessage() {
  local datetime=$(date +"$DATETIME_FORMAT")
  local yellow="\e[33m"
  local stop="\e[0m"
  printf "${yellow}"
  echo "INFO: ${datetime} $1"
  printf "${stop}"
}

#######################################
# Print debug message if DEBUG flag is true
#######################################
function printDebugMessage() {
  if [ "$DEBUG" = true ]; then
    local datetime=$(date +"$DATETIME_FORMAT")
    local grey="\e[90m"
    local stop="\e[0m"
    printf "${grey}"
    echo "DEBUG: ${datetime} $1"
    printf "${stop}"
  fi
}

#######################################
# Show usage help
#######################################
function displayHelp() {
    echo "Usage : $0 [-u <user>] [-g <group>] -t -c -p [-x <url>] [-h]"
    echo "-u, --user <user> : Optional user, default user is $SCRIPT_USER"
    echo "-g, --group <group> : Optional group, default group is $SCRIPT_GROUP"
    echo "-t, --provision-tpm2 : Provision TPM2"
    echo "-c, --configure-trustedge : Configure TrustEdge"
    echo "-p, --provision-device : Provision device"
    echo "-x, --proxy <url> : Proxy URL"
    echo "-h, --help : Display help message"
    echo ""
    if [ -n "$1" ]; then
        echo "$1"
        echo ""
        exit 1
    else
        exit 0
    fi
    exit 0
}

while test $# -gt 0
    do
        case $1 in
            -h | --help)
                displayHelp
                ;;
            -u | --user)
                if [ ! -z "$2" ]; then
                    PROV_USER=$2
                    printInfoMessage "User set to [$PROV_USER]"
                    shift
                else
                    printErrorMessage "User value is missing."
                    displayHelp
                fi
                ;;
            -g | --group)
                if [ ! -z "$2" ]; then
                    PROV_GROUP=$2
                    printInfoMessage "User set to [$PROV_GROUP]"
                    shift
                else
                    displayHelp
                    printErrorMessage "User value is missing."
                fi
                ;;
            -t | --provision-tpm2)
                PROVISION_TPM2=1
                ;;
            -c | --configure-trustedge)
                SETUP_TRUSTEDGE=1
                ;;
            -p | --provision-device)
                PROVISION_DEVICE=1
                ;;
            -x | --proxy)
                if [ ! -z "$2" ]; then
                    PROXY_URL=$2
                    printInfoMessage "Proxy set to [$PROXY_URL]"
                    shift
                else
                    displayHelp
                    printErrorMessage "Proxy value is missing."
                fi
                ;;
            *)

                displayHelp "ERROR: Unknown argument $1"
                ;;
    esac
    shift
done

if [ ! -d ${TPM2_TOOLS_DIR} ]; then
    displayHelp "ERROR: TPM2 tools directory ${TPM2_TOOLS_DIR} does not exist"
fi

if [ ! -d ${TRUSTEDGE_DIR} ]; then
    displayHelp "ERROR: TrustEdge directory ${TRUSTEDGE_DIR} does not exist"
fi

echo "Running with user $PROV_USER and group $PROV_GROUP..."

# Provision TPM2
if [ ${PROVISION_TPM2} -eq 1 ]; then
    echo "Provisioning TPM2"
    ${ROOT_CMD} ${TPM2_TOOLS_DIR}/provision_tpm2.sh --user $PROV_USER --group $PROV_GROUP
fi

# Setup TrustEdge
if [ ${SETUP_TRUSTEDGE} -eq 1 ]; then
    echo "Configuring TrustEdge"
    TRUSTEDGE_PATH=$SCRIPT_DIR/trustedge
    sed -i "s#/usr#$TRUSTEDGE_PATH#g" ${TRUSTEDGE_DIR}/trustedge.json
    sed -i "s#/etc/digicert#$TRUSTEDGE_PATH#g" ${TRUSTEDGE_DIR}/trustedge.json
    TRUSTEDGE_CONFIG=${TRUSTEDGE_DIR}/trustedge.json ${TRUSTEDGE_DIR}/bin/trustedge agent \
        --reset
    cp ${SCRIPT_DIR}/config/attributes.json ${TRUSTEDGE_DIR}/conf/
    cp ${SCRIPT_DIR}/config/get_attributes.sh ${TRUSTEDGE_DIR}/conf/
    cp ${TPM2_TOOLS_DIR}/tpm2.conf ${TRUSTEDGE_DIR}
    cp ${TPM2_TOOLS_DIR}/creds.tpm2 ${TRUSTEDGE_DIR}
    echo "Bootstrap path: $BOOTSTRAP_PATH"
    TRUSTEDGE_CONFIG=${TRUSTEDGE_DIR}/trustedge.json ${TRUSTEDGE_DIR}/bin/trustedge agent \
        --configure \
        --bootstrap-zip $BOOTSTRAP_PATH \
        --trustedge-user $PROV_USER \
        --trustedge-group $PROV_GROUP
fi

if [ ! -z ${PROXY_URL} ]; then
    echo "Setting proxy URL"
    sed -i "s|\"url\": .*|\"url\": \"${PROXY_URL}\"|g" ${TRUSTEDGE_DIR}/trustedge.json
fi

# Provision Device
if [ ${PROVISION_DEVICE} -eq 1 ]; then
    echo "Provisioning Device"
    TRUSTEDGE_CONFIG=${TRUSTEDGE_DIR}/trustedge.json ${TRUSTEDGE_DIR}/bin/trustedge agent
fi

echo "Done"
