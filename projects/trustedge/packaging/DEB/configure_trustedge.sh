#!/usr/bin/env bash

##################################################################################################
# Copyright © 2024, Digicert Inc. All Rights Reserved.
# The information in this document is proprietary and confidential.
# Liability Disclaimer Notice:
# You MUST NOT edit the following script.
# Any customization may only be performed using the supported command line arguments.
##################################################################################################
## configure_trustedge script:
##################################################################################################
##
## This script is to be used to configure TrustEdge on the device
##
## ==[ configure_trustedge parameters. ]========================================
##
## Usage info for the configure_trustedge:
##       Usage: ./configure_trustedge.sh --bootstrap-zip <pathname> [--bootstrap-key <file>]
##
##       Option(s):
##         --bootstrap-zip <pathname>     Path to the bootstrap zip file.
##         --bootstrap-key <file>         Path to the bootstrap key file.
##
##       To configure with the bootstrap zip file, the user should provide the
##       path to the zip file using the --bootstrap-zip argument.
##
##         ./configure_trustedge --bootstrap-zip /home/bootstrap.zip
##
################################################################

set -e

BOOTSTRAP_ZIP=""
BOOTSTRAP_KEY=""
CONFIG_ARGS=""

function show_usage
{
    echo ""
    echo "./configure_trustedge.sh --bootstrap-zip <pathname> [--bootstrap-key <file>]"
    echo ""
    echo "   --bootstrap-zip <pathname>     Path to the bootstrap zip file."
    echo "   --bootstrap-key <file>         [Optional] Path to the bootstrap key file."
    echo ""
    if [ -n "$1" ]; then
        echo "$1"
        echo ""
        exit 1
    else
        exit 0
    fi
}

function parse_json()
{
    [[ -z "$JSON" ]] && quit "JSON data is not loaded"
    JSON_CONTENT=$(echo $JSON | sed "s/,[ \t]*\"/,\\n\"/g" | sed 's/[{}]//g' | sed 's/^[ \t]*//g' | sed 's/[ \t]*$//g' | sed '/^$/d' | sed 's/^,$//g' | sed '/^$/d')
    while IFS=':' read -r col1 col2
    do
        attr=$(echo $col1 | sed 's/\"//g')
        if [[ "$1" = "$attr" ]]; then
            value=$(echo $col2 | sed 's/.*"\(.*\)".*/\1/' | sed 's/,*$//g' | sed 's/,/, /g')
            echo "$value"
        fi
    done <<< "$JSON_CONTENT"
}

function find_key()
{
    local dir="$1"
    local line="$2"

    if [ ! -d "$dir" ]; then
        return 1
    fi

    for file in "$dir"/*; do
        if [ -f "$file" ]; then
            first_line=$(head -n 1 "$file")
            if [ "$first_line" == "$line" ]; then
                echo "$file"
                return 0
            fi
        fi
    done

    echo ""
}

function update_bootstrap_with_key()
{
    local file="$1"
    local new_key_alias_value=$(basename "$2")

    echo "Updating key_alias in $file with $new_key_alias_value"

    key_alias_line=$(grep "\"key_alias\"" "$file" || true)
    if [ -z "$key_alias_line" ]; then
        cert_alias_line=$(grep "\"cert_alias\"" "$file")
        if [ -z "$cert_alias_line" ]; then
            echo "ERROR: No key_alias or cert_alias found in $file"
            cleanup_func
            exit -1
        fi

        new_key_alias_line=$(sed "s/cert_alias/key_alias/" <<< "$cert_alias_line" | awk -v new_value="$new_key_alias_value" -F'"' -v OFS='"' '{$4=new_value; print}')
        [[ "${new_key_alias_line: -1}" != "," ]] && new_key_alias_line+=","
        sudo -u trustedge sed -i "s/$cert_alias_line/$new_key_alias_line\n$cert_alias_line/" $1
    else
        new_key_alias_line=$(echo "$key_alias_line" | awk -v new_value="$new_key_alias_value" -F'"' -v OFS='"' '{$4=new_value; print}')
        sudo -u trustedge sed -i "s/$key_alias_line/$new_key_alias_line/" $1
    fi
}

function cleanup_func()
{
    sudo rm -rf /tmp/trustedge_bootstrap
    sudo rm -f /tmp/bootstrap.zip
}

trap 'cleanup_func' ERR

while test $# -gt 0
do
     case "$1" in
        --bootstrap-zip)
            if [ -z "$2" ]; then
                show_usage "ERROR: Missing path argument for bootstrap zip file..."
            fi
            BOOTSTRAP_ZIP="$2"
            shift
            ;;
        --bootstrap-key)
            if [ -z "$2" ]; then
                show_usage "ERROR: Missing path argument for bootstrap key file..."
            fi
            BOOTSTRAP_KEY="$2"
            shift
            ;;
        --help)
            show_usage
            ;;
        *)
            show_usage "ERROR: Invalid argument: $1"
            ;;
    esac
    shift
done

if [[ -z "${BOOTSTRAP_ZIP}" ]]; then
    show_usage "ERROR: bootstrap zip file not provided..."
fi

if [[ ! -f ${BOOTSTRAP_ZIP} ]]; then
    show_usage "ERROR: bootstrap zip file not found..."
fi

cleanup_func
sudo -u trustedge mkdir -p /tmp/trustedge_bootstrap
cp "${BOOTSTRAP_ZIP}" /tmp/bootstrap.zip
sudo chown trustedge:trustedge /tmp/bootstrap.zip
sudo -u trustedge unzip /tmp/bootstrap.zip -d /tmp/trustedge_bootstrap
if [[ -f /tmp/trustedge_bootstrap/bootstrap/bootstrap_config.json ]]; then

    if [[ ! -z "${BOOTSTRAP_KEY}" ]]; then
        update_bootstrap_with_key "/tmp/trustedge_bootstrap/bootstrap/bootstrap_config.json" "${BOOTSTRAP_KEY}"
    fi

    CONFIG_ARGS+=" --bootstrap-configuration /tmp/trustedge_bootstrap/bootstrap/bootstrap_config.json"

    if [[ ! -z "${BOOTSTRAP_KEY}" ]]; then
        CONFIG_ARGS+=" --creds-key ${BOOTSTRAP_KEY}"
    elif [[ -f /tmp/trustedge_bootstrap/bootstrap/bootstrap_key.pem ]]; then
        CONFIG_ARGS+=" --creds-key /tmp/trustedge_bootstrap/bootstrap/bootstrap_key.pem"
    fi
    if [[ -f /tmp/trustedge_bootstrap/bootstrap/bootstrap_cert.pem ]]; then
        CONFIG_ARGS+=" --creds-cert /tmp/trustedge_bootstrap/bootstrap/bootstrap_cert.pem"
    fi
else
    # if we did not find bootstrap_config.json, use the find first JSON file we find
    echo ""
    PATTERN="/tmp/trustedge_bootstrap/*.json"
    FILE=( $PATTERN )
    if [ ! -f "${FILE[0]}" ]; then
        echo "bootstrap file not found"
        cleanup_func
        exit 1
    fi

    if [[ ! -z "${BOOTSTRAP_KEY}" ]]; then
        update_bootstrap_with_key "${FILE[0]}" "${BOOTSTRAP_KEY}"
    fi

    CONFIG_ARGS+=" --bootstrap-configuration ${FILE[0]}"

    JSON=$(cat "${FILE[0]}")
    KEY_ALIAS=$(parse_json "key_alias")
    CERT_ALIAS=$(parse_json "cert_alias")

    if [[ ! -z "${BOOTSTRAP_KEY}" ]]; then
        CONFIG_ARGS+=" --creds-key ${BOOTSTRAP_KEY}"
    elif [[ -z "${KEY_ALIAS}" ]]; then
        KEY_FILE=$(find_key "/tmp/trustedge_bootstrap" "-----BEGIN PRIVATE KEY-----")
        if [[ -f "${KEY_FILE}" ]]; then
            CONFIG_ARGS+=" --creds-key ${KEY_FILE}"
        fi
    elif [[ -f /tmp/trustedge_bootstrap/${KEY_ALIAS} ]]; then
        CONFIG_ARGS+=" --creds-key /tmp/trustedge_bootstrap/${KEY_ALIAS}"
    else
        echo "key file not found"
        cleanup_func
        exit 1
    fi
    if [[ -n "${CERT_ALIAS}" ]] && [[ -f /tmp/trustedge_bootstrap/${CERT_ALIAS} ]]; then
        CONFIG_ARGS+=" --creds-cert /tmp/trustedge_bootstrap/${CERT_ALIAS}"
    fi
fi

if [[ -d /tmp/trustedge_bootstrap/ca/ ]]; then
    sudo -u trustedge cp /tmp/trustedge_bootstrap/ca/* /etc/digicert/keystore/ca/
fi
echo "Calling sudo -u trustedge trustedge agent --configure $CONFIG_ARGS"
echo ""
sudo -u trustedge trustedge agent --configure $CONFIG_ARGS
cleanup_func
echo "Done"
exit 0
